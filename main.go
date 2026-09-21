package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"dengan.dev/camera-streamer/internal/handlers"
	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/models"
	"dengan.dev/camera-streamer/internal/onvif"
	"dengan.dev/camera-streamer/internal/provider"
	"dengan.dev/camera-streamer/internal/stream"
	"dengan.dev/camera-streamer/internal/tuyaengine"
	"dengan.dev/camera-streamer/internal/tuyaqr"
)

//go:embed static
var staticFiles embed.FS

// listenAddress reports the address the HTTP server binds.
func listenAddress() string {
	if address := os.Getenv("ONVIF_VIEWER_LISTEN_ADDR"); address != "" {
		return address
	}
	return ":7878"
}

// providerStarter is the stream.Manager as tuyaengine sees it, with the provider
// tag applied at the point where the stream is actually created.
//
// The tag MUST be applied here rather than to the returned *models.StreamInfo:
// the manager returns a copy of the process state, so mutating that copy would
// leave the manager's own record (and therefore /api/stream/list) reporting
// ONVIF. It would also make a Tuya stream be restored as ONVIF after a restart.
type providerStarter struct {
	manager  *stream.Manager
	provider models.ProviderKind
}

// StartStream is the shared StreamStarter signature (profileToken, rtspURL),
// which every provider uses and which ONVIF must keep exactly.
//
// The Tuya resolution is NOT carried here, because this signature has nowhere to
// put it and changing it would touch the ONVIF path. The Tuya provider instead
// PERSISTS the resolved choice before asking the bridge to start the stream, so
// the manager reads it back from the store at this point. That keeps one source
// of truth (the stream_configs row) for both a fresh start and a restart.
func (s providerStarter) StartStream(profileToken, rtspURL string) (*models.StreamInfo, error) {
	if s.provider == models.ProviderTuya {
		return s.manager.StartStreamWithResolution(profileToken, rtspURL, s.provider, "")
	}
	return s.manager.StartStreamForProvider(profileToken, rtspURL, s.provider)
}

// tuyaSessionCheckInterval is how often the Tuya session is probed while the
// process is idle. It is deliberately far longer than the provider's own
// validation cache: the point is to notice a session that dies while nothing is
// being started, not to poll the cloud.
const tuyaSessionCheckInterval = 3 * time.Minute

// tuyaSessionWatchdog probes the Tuya session periodically so a session that
// dies while the user is not touching anything is noticed, and the Tuya streams
// are stood down, instead of being left for the HLS watchdog to restart against
// a dead source.
//
// It is read-mostly and cheap: the provider caches the verdict for its own
// validateTTL, and the check itself is one authenticated call.
func tuyaSessionWatchdog(t *provider.Tuya, log *logger.Logger) {
	ticker := time.NewTicker(tuyaSessionCheckInterval)
	defer ticker.Stop()
	for range ticker.C {
		if !t.Configured() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		status, err := t.Session(ctx)
		cancel()
		if err != nil {
			log.LogWarn("tuya", "tuya", "periodic Tuya session check failed: "+err.Error())
			continue
		}
		if status == nil || status.Valid {
			continue
		}
		// Session(), not this loop, is what stands the streams down; log only
		// the transition-worthy fact, never cookie material.
		log.LogWarn("tuya", "tuya", fmt.Sprintf(
			"periodic Tuya session check: session invalid (filePresent=%t cloudVerified=%t); streams stood down until a new QR scan",
			status.FilePresent, status.CloudVerified))
	}
}

// tuyaStoreReason explains, in one operator-facing sentence, where the Tuya
// session is kept and what the legacy file is for now.
//
// It is a function rather than an inline format because the sentence has two
// shapes: an install that still points at a legacy file (which is read once and
// then left alone) and a fully migrated install that does not (so there is no
// file to name, and saying "the legacy file at " with an empty path would be
// nonsense). The reason is surfaced verbatim by GET /api/tuya/session.
func tuyaStoreReason(dbPath, legacyFile string) string {
	base := fmt.Sprintf("the session is kept in the project database %s, alongside the stream configs and logs", dbPath)
	if strings.TrimSpace(legacyFile) == "" {
		return base + "; no legacy session file is configured, so nothing is read from the filesystem"
	}
	return base + fmt.Sprintf("; the legacy file at %s is imported once at start-up and never written", legacyFile)
}

// tuyaBootSessionMessage states, at start-up and in ONE operator-facing
// sentence, whether a Tuya session is stored right now, and what to do when one
// is not.
//
// It exists because of a MEASURED defect: the bridge used to be built once,
// behind a "is Tuya configured?" flag evaluated at boot, and an install whose
// session had not landed yet (the row arrived later, via an import or the cloud
// refresh) came up with a nil bridge FOR THE LIFETIME OF THE PROCESS. The only
// symptom was an opaque "provider: tuya streaming is not configured in this
// process" when a stream was started, with no warning at boot at all, and the
// way out was to restart the viewer. This sentence is the warning that was
// missing, and it deliberately does NOT say "restart is needed": the bridge is
// built regardless of this answer (see tuyaengine.NewBridgeForSession), so a
// session that appears later is picked up by the running process.
//
// The message never contains credential material: account labels, a count, a
// store kind and a path only.
func tuyaBootSessionMessage(store tuyaqr.SessionStore, legacySessionFile string) (available bool, message string) {
	accts, err := store.Accounts()
	switch {
	case err != nil:
		return false, fmt.Sprintf(
			"WARNING: the Tuya session store could not be listed at start-up (%v), so no Tuya camera can stream until it is readable. Tuya is NOT disabled: the streaming bridge is up, and a session that becomes readable is picked up WITHOUT restarting the viewer",
			err)
	case len(accts) > 0:
		return true, fmt.Sprintf(
			"Tuya session available at start-up: %d stored account(s) in the %s store at %s; stored Tuya cameras will be re-registered with the engine and restored",
			len(accts), store.Kind(), store.Location())
	case strings.TrimSpace(legacySessionFile) != "":
		return true, fmt.Sprintf(
			"Tuya session file configured at start-up (%s) but not yet imported into the %s store at %s; it is imported below and then used",
			legacySessionFile, store.Kind(), store.Location())
	default:
		return false, fmt.Sprintf(
			"WARNING: NO Tuya session is stored at start-up - the %s store at %s holds no account and no legacy session file is configured - so no Tuya camera can stream yet. What is missing: the credential itself (the fast-sid/s-sid cookie pair a QR scan produces). Tuya is NOT disabled and NO restart is needed: the streaming bridge is already up, so the moment a QR scan or an import provides a session, camera discovery and one-click start work in this same process; only a camera whose stream row was stored by an earlier run stays unrestored until a session exists",
			store.Kind(), store.Location())
	}
}

// tuyaRestoreRegistrar is the slice of the Tuya provider the start-up
// re-registration needs: registering a persisted camera with the engine, and
// NOTHING else. See provider.TuyaStreamRegistrar for why the seam is that
// narrow.
type tuyaRestoreRegistrar interface {
	RegisterStoredDeviceForProfile(profileToken string) provider.TuyaRegistrationOutcome
}

// reRegisterStoredTuyaStreams re-registers every PERSISTED Tuya camera with the
// engine, so that stream.Manager.RestoreStreams (which runs after this) has a
// live loopback URL to resolve for each of them.
//
// THIS IS THE FIX FOR THE DEFECT THAT MADE A RESTART LOSE THE CAMERA. A Tuya
// stream's RTSP URL is a loopback address on our own in-process engine, on a
// port that is allocated fresh on every start; the stored row therefore carries
// an EMPTY url, and restore asks the engine for the live one. Nothing used to
// put the device back into the engine at boot, so restore asked about a device
// the engine had never heard of, correctly reported not-found, and skipped the
// camera: MEASURED live, 1 stream before a restart and 0 after.
//
// Ordering is the whole point: this runs BEFORE RestoreStreams, synchronously,
// so every registration has completed by the time restore asks the engine.
//
// It can never fail startup. A listing that is not usable, a camera that is
// offline, a session that is missing and an engine that refuses are each
// reported through `report` and then skipped; the loop always runs to the end.
// It returns how many cameras it registered and how many it skipped.
func reRegisterStoredTuyaStreams(configs []logger.StreamConfig, registrar tuyaRestoreRegistrar, report func(provider.TuyaRegistrationOutcome)) (registered, skipped int) {
	for _, config := range configs {
		if models.ProviderKind(config.Provider).OrDefault() != models.ProviderTuya {
			continue
		}
		if registrar == nil {
			// Only reachable if the Tuya provider could not be built at all.
			// Say so rather than leaving the camera silently unrestorable.
			report(provider.TuyaRegistrationOutcome{
				ProfileToken:  config.ProfileToken,
				SkippedReason: "the Tuya provider is not wired in this process, so this camera cannot be registered with the engine and will not be restored",
			})
			skipped++
			continue
		}
		outcome := registrar.RegisterStoredDeviceForProfile(config.ProfileToken)
		report(outcome)
		if outcome.Registered {
			registered++
			continue
		}
		skipped++
	}
	return registered, skipped
}

// reportTuyaRegistration writes one registration outcome to the console AND to
// the project database's log, so an operator sees it whether they read the
// service journal or the Logs panel. A skip is a WARNING: it means a camera the
// user configured is not coming back.
func reportTuyaRegistration(dbLog *logger.Logger) func(provider.TuyaRegistrationOutcome) {
	return func(outcome provider.TuyaRegistrationOutcome) {
		label := outcome.ProfileToken
		if label == "" {
			label = outcome.DeviceID
		}
		if outcome.Registered {
			msg := fmt.Sprintf(
				"Tuya camera %s re-registered with the engine at start-up (resolution=%s, engine url %s); restoring it next",
				label, outcome.Resolution, outcome.RTSPURL)
			log.Printf("%s", msg)
			dbLog.LogInfo("tuya", "startup", msg)
			return
		}
		msg := fmt.Sprintf("Tuya camera %s was NOT re-registered with the engine: %s", label, outcome.SkippedReason)
		log.Printf("WARNING: %s", msg)
		dbLog.LogWarn("tuya", "startup", msg)
	}
}

// streamRestorer is the one thing the start-up sequence needs from the stream
// manager: restore the persisted rows. It is an interface so the ORDER below can
// be asserted without spawning an encoder. *stream.Manager satisfies it.
type streamRestorer interface {
	RestoreStreams()
}

// restoreStoredStreamsAtStartup is the whole start-up sequence for persisted
// streams, in the ONE order that works:
//
//  1. re-register every stored Tuya camera with the engine, synchronously, so
//     each has a live loopback URL in THIS process;
//  2. only then ask the stream manager to restore the stored rows.
//
// Doing (2) before (1) is the defect this milestone fixes: restore resolves a
// Tuya URL by asking the engine, the engine has never heard of the device, the
// resolver reports not-found, and the camera is silently skipped (MEASURED live:
// 1 stream before a restart, 0 after). Extracting the sequence into one function
// is what makes that order assertable in a test instead of being a comment.
//
// It returns how many cameras were registered and how many were skipped.
func restoreStoredStreamsAtStartup(manager streamRestorer, configs []logger.StreamConfig, registrar tuyaRestoreRegistrar, report func(provider.TuyaRegistrationOutcome)) (registered, skipped int) {
	registered, skipped = reRegisterStoredTuyaStreams(configs, registrar, report)
	manager.RestoreStreams()
	return registered, skipped
}

func main() {
	// Create a temporary directory for HLS files
	hlsBaseDir, err := os.MkdirTemp("", "onvif-hls")
	if err != nil {
		log.Fatalf("Failed to create temp directory: %v", err)
	}
	log.Printf("HLS files will be stored in: %s", hlsBaseDir)
	defer os.RemoveAll(hlsBaseDir)

	// Initialize logger
	dbLogger, err := logger.NewLogger("onvif_logs.db")
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer dbLogger.Close()

	// M8: the Tuya session lives in the same database as the stream configs and
	// logs, through the SAME connection the logger opened, so the process has
	// one writer and one place where the database's 0600 permissions are
	// enforced. This is what makes the credential a first-class part of the
	// project's own store instead of a side-car JSON file.
	//
	// The selection is still made by tuyaqr.ResolveSessionStore, so
	// TUYA_SESSION_STORE=file genuinely escapes back to the legacy file store
	// (and TUYA_SESSION_DB retargets the database). The database handle opened
	// above is handed in, so the resolved store shares this process's one writer
	// rather than opening a second pool at the same file.
	//
	// The legacy file path is taken from TUYA_ENGINE_SESSION_FILE - the variable
	// this project has always used for it, and the one the UI and the CLI tools
	// set - rather than from tuyaqr's own TUYA_SESSION_FILE. They name the same
	// thing, but only one of them is what an existing install actually exports,
	// and reading the wrong one silently skipped the migration import.
	legacySessionFile := strings.TrimSpace(os.Getenv(tuyaengine.EnvSessionFile))
	sessionCfg := tuyaqr.StoreConfigFromEnv()
	if strings.TrimSpace(sessionCfg.FilePath) == "" {
		sessionCfg.FilePath = legacySessionFile
	}
	sessionCfg.OpenDB = func(path string) (*tuyaqr.SQLiteSessionStore, error) {
		if path == dbLogger.Path() {
			return tuyaqr.NewSQLiteSessionStoreFromDB(dbLogger.DB(), dbLogger.Path())
		}
		return tuyaqr.NewSQLiteSessionStore(path)
	}
	resolved, err := tuyaqr.ResolveSessionStore(sessionCfg)
	if err != nil {
		log.Fatalf("Failed to initialize the Tuya session store: %v", err)
	}
	sessionStore := resolved.Store
	log.Printf("Tuya session store: %s (%s) - %s", resolved.Kind, resolved.Location, resolved.Reason)
	if resolved.Kind == tuyaqr.StoreKindSQLite {
		log.Printf("Tuya session database and its -wal/-shm are held at 0600 (mode reported by GET /api/tuya/session)")
	}
	if resolved.FallbackFrom != "" {
		log.Printf("WARNING: the Tuya session store fell back from %q, so the session is NOT in the database", resolved.FallbackFrom)
	}

	// The legacy session file is now an IMPORT SOURCE and a read-only fallback,
	// never a write target: importing copies it and leaves it exactly as it was.
	// It is only meaningful when the destination is the database; a file store
	// already IS that file.
	if resolved.Kind == tuyaqr.StoreKindSQLite {
		if importSource := resolved.ImportSource; importSource != "" {
			result, importErr := tuyaqr.ImportSessionFile(sessionStore, importSource)
			switch {
			case importErr != nil:
				log.Printf("Legacy Tuya session import skipped: %v", importErr)
			case result.Imported:
				log.Printf("Imported the legacy Tuya session for %s into %s (%d cookie(s)); the source file was read only",
					result.Region+"/"+result.Email, result.DestLocation, result.CookieCount)
			case result.AlreadyStored:
				log.Printf("The Tuya session store already holds %s; the legacy file was left untouched", result.Region+"/"+result.Email)
			default:
				log.Printf("Legacy Tuya session import: %s", result.Detail)
			}
		}
	}

	// tuyaConfigured used to live here: a boot-time "is Tuya part of this install
	// at all?" answer that gated whether the bridge was built. It is GONE, and
	// that is the Bug 3 fix. It collapsed two different questions - "does this
	// install want Tuya?" and "is a session stored RIGHT NOW?" - and answered the
	// second once, at boot. An install whose session arrived later (an import, or
	// the cloud refresh) therefore came up with a nil bridge for the whole life
	// of the process. The provider now exists whenever a session STORE exists
	// (see the provider seam below), and the bridge is built unconditionally, so
	// a session that appears after start-up is used without a restart.

	// Initialize ONVIF client
	onvifClient := onvif.NewClient()

	// Initialize Stream Manager
	streamManager := stream.NewManager(hlsBaseDir, dbLogger)
	go streamManager.CleanupInactiveClients()

	// Tuya bridge: the Tuya source runs IN THIS PROCESS through the vendored
	// go2rtc code in internal/go2rtc, exposed as a loopback RTSP endpoint that
	// the existing ffmpeg pipeline consumes. No child process and no external
	// engine binary are involved.
	//
	// The bridge is built UNCONDITIONALLY, and that is Bug 3's fix. It used to
	// be gated on a boot-time "is a session configured?" answer, so an install
	// whose session landed later (an import, or the cloud refresh) kept a nil
	// bridge for the whole life of the process and failed a stream start with an
	// opaque "tuya streaming is not configured in this process". Building it
	// costs nothing until a stream is started: no port is bound and no child is
	// spawned until the first registration.
	tuyaBridge, err := tuyaengine.NewBridgeForSession(providerStarter{manager: streamManager, provider: models.ProviderTuya}, dbLogger)
	if err != nil {
		log.Printf("Tuya bridge disabled: %v", err)
	}
	if tuyaBridge != nil {
		defer tuyaBridge.Stop()
		// A Tuya stream's RTSP URL is a loopback address on this in-process
		// engine, and the engine binds an ephemeral port that changes every
		// start. Give the manager a way to ask for the CURRENT address, so a
		// restored Tuya stream reconnects to the live port instead of replaying
		// a frozen one that no longer exists.
		//
		// This MUST be installed before RestoreStreams below: the resolver is
		// how restore turns an empty stored URL into the live one.
		streamManager.SetTuyaURLResolver(tuyaBridge.ResolveProfileToken)
	}

	// Provider seam. The ONVIF provider is always present and is registered
	// first, so an install with no Tuya configuration keeps its old behaviour
	// byte for byte: an empty provider on a request means ONVIF.
	onvifProvider := provider.NewONVIF(onvifClient)
	providerSet := provider.NewSet(onvifProvider)

	// Tuya is added only when a session STORE exists. Everything it does is
	// read-only against the store until a QR scan deliberately replaces it. The
	// legacy session FILE is now an import source and a fallback, so an install
	// that has already migrated keeps working with the file gone.
	//
	// Note what this condition is NOT: it is not "is a session stored right
	// now?". A store with no account is a store that will hold one after the
	// next QR scan, and the provider must exist by then without a restart.
	var tuyaProvider *provider.Tuya
	var loginManager *provider.LoginManager
	if legacySessionFile != "" || sessionStore != nil {
		var streaming provider.TuyaStreaming
		var registrar provider.TuyaStreamRegistrar
		if tuyaBridge != nil {
			streaming = tuyaBridge
			registrar = tuyaBridge
		}
		tuyaProvider = provider.NewTuya("",
			provider.WithTuyaResolvedStore(&tuyaqr.ResolvedStore{
				Store:    sessionStore,
				Kind:     sessionStore.Kind(),
				Location: sessionStore.Location(),
				Reason:   tuyaStoreReason(sessionStore.Location(), legacySessionFile),
			}),
			provider.WithTuyaBridge(streaming),
			provider.WithTuyaStreamRegistrar(registrar),
			provider.WithTuyaStreamStopper(streamManager),
			provider.WithTuyaHost(tuyaengine.DefaultTuyaHost),
			provider.WithTuyaLogger(dbLogger),
			// The per-camera sd|hd choice lives in the same stream_configs rows the
			// provider tags with its provider kind, so it is restored by the normal
			// RestoreStreams path without a second store.
			provider.WithTuyaResolutionStore(dbLogger),
		)
		providerSet = provider.NewSet(onvifProvider, tuyaProvider)
		loginManager = provider.NewLoginManager(
			provider.WithLoginStore(sessionStore),
			provider.WithLoginHost(tuyaengine.DefaultTuyaHost),
		)
		log.Printf("Tuya provider enabled (session store=%s, legacy file=%t, streaming=%t)", sessionStore.Kind(), legacySessionFile != "", tuyaBridge != nil)
	}

	// The session state at boot, said LOUDLY. An install with no stored session
	// is a normal state (the user has not scanned a QR yet) but it is exactly
	// the state that used to be reported by silence, so it is stated here rather
	// than discovered later from an opaque start-time error.
	if tuyaProvider != nil {
		available, message := tuyaBootSessionMessage(sessionStore, legacySessionFile)
		log.Printf("%s", message)
		if !available {
			dbLogger.LogWarn("tuya", "startup", message)
		}
	}

	// ---------------------------------------------------------------------------
	// ORDER IS CRITICAL: re-register the stored Tuya cameras with the engine
	// BEFORE RestoreStreams runs, and synchronously.
	//
	// A Tuya RTSP URL is a loopback address on OUR OWN in-process engine, on a
	// port allocated fresh every start, so the stored row carries an EMPTY url
	// and restore asks the engine for the live address. Without this step the
	// engine has never heard of the device, restore correctly skips it, and the
	// camera is silently gone after a restart (MEASURED live: 1 stream before,
	// 0 after). Registration only puts the device in the engine: it starts no
	// ffmpeg and writes no row, because restore is what starts the single stream
	// and the row already exists.
	//
	// Nothing in here can abort start-up: an offline camera, a missing session
	// and an engine refusal are each logged and skipped.
	// ---------------------------------------------------------------------------
	if tuyaProvider != nil {
		storedConfigs, listErr := dbLogger.ListStreamConfigs()
		if listErr != nil {
			log.Printf("WARNING: the stored stream configs could not be read (%v), so no Tuya camera can be re-registered with the engine; ONVIF streams are unaffected", listErr)
			dbLogger.LogWarn("tuya", "startup", fmt.Sprintf("stored stream configs unreadable at start-up: %v", listErr))
			// Restore is still attempted: an ONVIF row is unaffected by this
			// failure and must not be dropped because of it.
			streamManager.RestoreStreams()
		} else {
			registered, skipped := restoreStoredStreamsAtStartup(streamManager, storedConfigs, tuyaProvider, reportTuyaRegistration(dbLogger))
			if registered > 0 || skipped > 0 {
				log.Printf("Tuya start-up re-registration: %d camera(s) registered with the engine, %d skipped", registered, skipped)
			}
		}
	} else {
		// No Tuya provider at all: ONVIF-only install, or a store that could not
		// be resolved. Restore as before.
		streamManager.RestoreStreams()
	}

	// Initialize HTTP handlers
	apiHandler := handlers.New(streamManager, onvifClient, dbLogger)
	apiHandler.SetProviders(providerSet, loginManager, tuyaProvider, func() {
		// A new session was captured by a QR scan. The discovery provider caches
		// its authenticated client, so it must drop it here to pick the new
		// session up without a restart. The streaming bridge needs no such
		// action: it re-reads the session file on every connect.
		if tuyaProvider != nil {
			tuyaProvider.Invalidate()
		}
	})

	// Serve the embedded static files
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("Failed to get static files sub-filesystem: %v", err)
	}

	// Define HTTP handlers
	http.Handle("/", http.FileServer(http.FS(staticFS)))
	http.Handle("/hls/", http.StripPrefix("/hls/", http.FileServer(http.Dir(hlsBaseDir))))

	// API routes
	http.HandleFunc("/api/functest", apiHandler.FuncTest)
	http.HandleFunc("/api/stream/start", apiHandler.StartStream)
	http.HandleFunc("/api/stream/stop", apiHandler.StopStream)
	http.HandleFunc("/api/stream/list", apiHandler.ListStreams)
	http.HandleFunc("/api/stream/diagnose", apiHandler.DiagnoseStream)
	http.HandleFunc("/api/stream/reconnect", apiHandler.ReconnectStream)
	http.HandleFunc("/api/stream/synchronize", apiHandler.SynchronizeStream)
	http.HandleFunc("/api/stream/snapshot", apiHandler.Snapshot)
	http.HandleFunc("/api/stream/uri", apiHandler.GetStreamUri)
	http.HandleFunc("/api/stream/logevents", apiHandler.LogEvents)
	http.HandleFunc("/api/logs", apiHandler.GetLogs)
	http.HandleFunc("/api/datetime", apiHandler.GetSystemDateAndTime)

	// Multi-provider routes. /api/stream/start above is unchanged for ONVIF and
	// additionally accepts {"provider":"tuya","deviceId":...,"resolution":"sd|hd"}.
	http.HandleFunc("/api/providers/cameras", apiHandler.ProviderCameras)
	http.HandleFunc("/api/tuya/resolution", apiHandler.SetTuyaResolution)
	http.HandleFunc("/api/tuya/login/begin", apiHandler.TuyaLoginBegin)
	http.HandleFunc("/api/tuya/login/poll", apiHandler.TuyaLoginPoll)
	http.HandleFunc("/api/tuya/session", apiHandler.TuyaSession)
	http.HandleFunc("/api/tuya/logout", apiHandler.TuyaLogout)
	http.HandleFunc("/api/tuya/resume", apiHandler.TuyaResume)

	// M6: a periodic session watchdog. Without it, a session that dies while
	// nothing is being started would only be noticed the next time the user
	// opened the Tuya panel, and the running streams would keep their ffmpeg
	// pointed at a dead source until the HLS watchdog began restarting it.
	if tuyaProvider != nil {
		go tuyaSessionWatchdog(tuyaProvider, dbLogger)
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutting down gracefully...")
		streamManager.Shutdown()
		os.Exit(0)
	}()

	address := listenAddress()
	log.Printf("Server started on %s", address)
	if err := http.ListenAndServe(address, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
