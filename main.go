package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"dengan.dev/onvif/internal/handlers"
	"dengan.dev/onvif/internal/logger"
	"dengan.dev/onvif/internal/onvif"
	"dengan.dev/onvif/internal/stream"
)

//go:embed static
var staticFiles embed.FS

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
	go streamManager.CleanupInactiveClients()

	// Initialize HTTP handlers
	apiHandler := handlers.New(streamManager, onvifClient, dbLogger)

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
	http.HandleFunc("/api/stream/uri", apiHandler.GetStreamUri)
	http.HandleFunc("/api/stream/logevents", apiHandler.LogEvents)
	http.HandleFunc("/api/logs", apiHandler.GetLogs)
	http.HandleFunc("/api/datetime", apiHandler.GetSystemDateAndTime)

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutting down gracefully...")
		streamManager.Shutdown()
		os.Exit(0)
	}()

	log.Println("Server started on :7878")
	if err := http.ListenAndServe(":7878", nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
