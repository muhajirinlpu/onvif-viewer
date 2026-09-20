package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"dengan.dev/camera-streamer/internal/handlers"
	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/models"
	"dengan.dev/camera-streamer/internal/onvif"
	"dengan.dev/camera-streamer/internal/provider"
	"dengan.dev/camera-streamer/internal/stream"
	"dengan.dev/camera-streamer/internal/tuyaengine"
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
	tuyaBridge, err := tuyaengine.NewBridgeFromEnv(providerStarter{manager: streamManager, provider: models.ProviderTuya}, dbLogger)
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

	// Tuya is added only when a session file is configured. Everything it does
	// is read-only against that file until a QR scan deliberately replaces it.
	var tuyaProvider *provider.Tuya
	var loginManager *provider.LoginManager
	if sessionFile := strings.TrimSpace(os.Getenv(tuyaengine.EnvSessionFile)); sessionFile != "" {
		var streaming provider.TuyaStreaming
		if tuyaBridge != nil {
			streaming = tuyaBridge
		}
		tuyaProvider = provider.NewTuya(sessionFile,
			provider.WithTuyaBridge(streaming),
			provider.WithTuyaHost(tuyaengine.DefaultTuyaHost),
			provider.WithTuyaLogger(dbLogger),
		)
		providerSet = provider.NewSet(onvifProvider, tuyaProvider)
		loginManager = provider.NewLoginManager(
			provider.WithLoginSessionFile(sessionFile),
			provider.WithLoginHost(tuyaengine.DefaultTuyaHost),
		)
		log.Printf("Tuya provider enabled (session file configured, streaming=%t)", tuyaBridge != nil)
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
