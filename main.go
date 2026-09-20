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

func (s providerStarter) StartStream(profileToken, rtspURL string) (*models.StreamInfo, error) {
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

	// tuyaConfigured answers "is Tuya part of this install at all?" BEFORE the
	// bridge is built, and it is deliberately independent of HOW the session is
	// stored: a migrated install may have TUYA_ENGINE_SESSION_FILE unset while
	// its credential sits in the database, and gating on the env var alone would
	// silently disable Tuya streaming on a working install.
	tuyaConfigured := legacySessionFile != ""
	if !tuyaConfigured {
		if accts, listErr := sessionStore.Accounts(); listErr == nil && len(accts) > 0 {
			tuyaConfigured = true
		}
	}
	// A FILE store with a configured path is configured by definition, even if
	// the file cannot be read yet (the user has not scanned a QR).
	if !tuyaConfigured && resolved.Kind == tuyaqr.StoreKindFile && resolved.Location != "" {
		tuyaConfigured = true
	}

	// Initialize ONVIF client
	onvifClient := onvif.NewClient()

	// Initialize Stream Manager
	streamManager := stream.NewManager(hlsBaseDir, dbLogger)
	streamManager.RestoreStreams()
	go streamManager.CleanupInactiveClients()

	// Tuya bridge: the Tuya source runs IN THIS PROCESS through the vendored
	// go2rtc code in internal/go2rtc, exposed as a loopback RTSP endpoint that
	// the existing ffmpeg pipeline consumes. No child process and no external
	// engine binary are involved, and it stays off entirely until
	// TUYA_ENGINE_SESSION_FILE is configured, so an ONVIF-only install is
	// unchanged.
	tuyaBridge, err := tuyaengine.NewBridgeForSession(providerStarter{manager: streamManager, provider: models.ProviderTuya}, dbLogger, tuyaConfigured)
	if err != nil {
		log.Printf("Tuya bridge disabled: %v", err)
	}
	if tuyaBridge != nil {
		defer tuyaBridge.Stop()
	}

	// Provider seam. The ONVIF provider is always present and is registered
	// first, so an install with no Tuya configuration keeps its old behaviour
	// byte for byte: an empty provider on a request means ONVIF.
	onvifProvider := provider.NewONVIF(onvifClient)
	providerSet := provider.NewSet(onvifProvider)

	// Tuya is added only when a session is configured. Everything it does is
	// read-only against the store until a QR scan deliberately replaces it. The
	// legacy session FILE is now an import source and a fallback, so an install
	// that has already migrated keeps working with the file gone.
	var tuyaProvider *provider.Tuya
	var loginManager *provider.LoginManager
	if legacySessionFile != "" || sessionStore != nil {
		var streaming provider.TuyaStreaming
		if tuyaBridge != nil {
			streaming = tuyaBridge
		}
		tuyaProvider = provider.NewTuya("",
			provider.WithTuyaResolvedStore(&tuyaqr.ResolvedStore{
				Store:    sessionStore,
				Kind:     sessionStore.Kind(),
				Location: sessionStore.Location(),
				Reason:   tuyaStoreReason(sessionStore.Location(), legacySessionFile),
			}),
			provider.WithTuyaBridge(streaming),
			provider.WithTuyaStreamStopper(streamManager),
			provider.WithTuyaHost(tuyaengine.DefaultTuyaHost),
			provider.WithTuyaLogger(dbLogger),
		)
		providerSet = provider.NewSet(onvifProvider, tuyaProvider)
		loginManager = provider.NewLoginManager(
			provider.WithLoginStore(sessionStore),
			provider.WithLoginHost(tuyaengine.DefaultTuyaHost),
		)
		log.Printf("Tuya provider enabled (session store=sqlite, legacy file=%t, streaming=%t)", legacySessionFile != "", tuyaBridge != nil)
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
	// additionally accepts {"provider":"tuya","deviceId":...}.
	http.HandleFunc("/api/providers/cameras", apiHandler.ProviderCameras)
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
