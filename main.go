package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed static
var staticFiles embed.FS

const streamStopTimeout = 5 * time.Second

// Use OS temp directory for HLS files
var hlsBaseDir string

type CameraRequest struct {
	CameraIp   string `json:"cameraIp"`
	CameraPort string `json:"cameraPort"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}

type GetStreamUriRequest struct {
	CameraRequest
	ProfileToken string `json:"profileToken"`
}

type CameraFunction string

const (
	GetCapabilities       CameraFunction = "GetCapabilities"
	GetDeviceInformation  CameraFunction = "GetDeviceInformation"
	GetProfiles           CameraFunction = "GetProfiles"
	GetStreamUri          CameraFunction = "GetStreamUri"
	GetSnapshotUri        CameraFunction = "GetSnapshotUri"
	GetVideoEncoderConfig CameraFunction = "GetVideoEncoderConfig"
)

func ToCameraFunction(s string) CameraFunction {
	switch s {
	case string(GetCapabilities):
		return GetCapabilities
	case string(GetDeviceInformation):
		return GetDeviceInformation
	case string(GetProfiles):
		return GetProfiles
	case string(GetStreamUri):
		return GetStreamUri
	case string(GetSnapshotUri):
		return GetSnapshotUri
	case string(GetVideoEncoderConfig):
		return GetVideoEncoderConfig
	default:
		return ""
	}
}

func (f CameraFunction) uri() string {
	switch f {
	case GetCapabilities:
		return "onvif/device_service"
	case GetDeviceInformation:
		return "onvif/device_service"
	case GetProfiles:
		return "onvif/media_service"
	case GetStreamUri:
		return "onvif/media_service"
	case GetSnapshotUri:
		return "onvif/media_service"
	case GetVideoEncoderConfig:
		return "onvif/media_service"
	default:
		return ""
	}
}

func (f CameraFunction) envelope(cam CameraRequest) string {
	securityHeader := generateSecurityHeader(cam)
	switch f {
	case GetCapabilities:
		return `
			<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
				xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
				xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
				xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
				` + securityHeader + `
				<SOAP-ENV:Body>
					<tds:GetCapabilities/>
				</SOAP-ENV:Body>
			</SOAP-ENV:Envelope>`
	case GetDeviceInformation:
		return `
			<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
				xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
				xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
				xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
				` + securityHeader + `
				<SOAP-ENV:Body>
					<tds:GetDeviceInformation/>
				</SOAP-ENV:Body>
			</SOAP-ENV:Envelope>`
	case GetProfiles:
		return `
			<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
				xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
				xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
				xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
				` + securityHeader + `
				<SOAP-ENV:Body>
					<trt:GetProfiles/>
				</SOAP-ENV:Body>
			</SOAP-ENV:Envelope>`
	case GetStreamUri:
		return `

			<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
				xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
				xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
				xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
				` + securityHeader + `
				<SOAP-ENV:Body>
					<trt:GetStreamUri>
						<StreamSetup>
							<Stream xmlns="http://www.onvif.org/ver10/schema">RTP-Unicast</Stream>
							<Transport xmlns="http://www.onvif.org/ver10/schema">
								<Protocol>RTSP</Protocol>
							</Transport>
						</StreamSetup>
						<ProfileToken>%s</ProfileToken>
					</trt:GetStreamUri>
				</SOAP-ENV:Body>
			</SOAP-ENV:Envelope>`
	case GetSnapshotUri:
		return `
			<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
				xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
				xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
				xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
				` + securityHeader + `
				<SOAP-ENV:Body>
					<trt:GetSnapshotUri>
						<ProfileToken>%s</ProfileToken>
					</trt:GetSnapshotUri>
				</SOAP-ENV:Body>
			</SOAP-ENV:Envelope>`
	case GetVideoEncoderConfig:
		return `
			<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
				xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
				xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
				xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
				` + securityHeader + `
				<SOAP-ENV:Body>
					<trt:GetVideoEncoderConfiguration>
						<ProfileToken>%s</ProfileToken>
					</trt:GetVideoEncoderConfiguration>
				</SOAP-ENV:Body>
			</SOAP-ENV:Envelope>`
	default:
		return ""
	}
}

type StreamInfo struct {
	ID           string    `json:"id"`
	ProfileToken string    `json:"profileToken"`
	RtspURL      string    `json:"rtspUrl"`
	HlsURL       string    `json:"hlsUrl"`
	StartedAt    time.Time `json:"startedAt"`
	Status       string    `json:"status"`
}

type ClientConnection struct {
	Channel   chan LogEntry
	LastActive time.Time
}

type StreamManager struct {
	streams       map[string]*StreamProcess
	mutex         sync.RWMutex
	sseClients    map[string]*ClientConnection
	clientTimeout time.Duration // Timeout for inactive clients
	stopCleanup   chan struct{} // Channel to signal cleanup goroutine to stop
}

type StreamProcess struct {
	Info       StreamInfo
	Command    *exec.Cmd
	Done       chan bool
	Logs       []string
	LogsMutex  sync.RWMutex
	LogMaxSize int       // Maximum number of log entries to keep in memory
	closed     sync.Once
}

var (
	streamManager = &StreamManager{
		streams:       make(map[string]*StreamProcess),
		sseClients:    make(map[string]*ClientConnection),
		clientTimeout: 3 * time.Minute, // Clean up clients after 3 minutes of inactivity
		stopCleanup:   make(chan struct{}),
	}
)

func (sm *StreamManager) StartStream(profileToken, rtspURL string) (*StreamInfo, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Check if stream already exists for this profile
	for _, stream := range sm.streams {
		if stream.Info.ProfileToken == profileToken {
			return &stream.Info, nil
		}
	}

	// Create stream ID and HLS path
	streamID := fmt.Sprintf("stream_%d", time.Now().Unix())
	hlsDir := filepath.Join(hlsBaseDir, streamID)
	os.MkdirAll(hlsDir, 0755)

	// Prepare FFmpeg command
	args := []string{
		"-y",
		"-rtsp_transport", "tcp",
		"-i", rtspURL,
		"-c:v", "copy",
		"-c:a", "aac",
		"-hls_time", "2",
		"-hls_list_size", "3",
		"-hls_flags", "delete_segments",
		"-f", "hls",
		filepath.Join(hlsDir, "stream.m3u8"),
	}

	cmd := exec.Command("ffmpeg", args...)

	// Set process group
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// Capture stdout and stderr for logging
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %v", err)
	}

	streamProcess := &StreamProcess{
		Info: StreamInfo{
			ID:           streamID,
			ProfileToken: profileToken,
			RtspURL:      rtspURL,
			HlsURL:       fmt.Sprintf("/hls/%s/stream.m3u8", streamID),
			StartedAt:    time.Now(),
			Status:       "running",
		},
		Command:    cmd,
		Done:       make(chan bool),
		Logs:       []string{},
		LogMaxSize: 500, // Maximum 500 log entries per stream
		closed:     sync.Once{},
	}

	// For debugging - log the complete FFmpeg command
	log.Printf("Starting FFmpeg with command: ffmpeg %s", strings.Join(cmd.Args[1:], " "))

	// Start FFmpeg process
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start FFmpeg: %v", err)
	}

	// Monitor process
	go func() {
		// Read and log stdout
		go func() {
			scanner := bufio.NewScanner(stdoutPipe)
			for scanner.Scan() {
				line := scanner.Text()
				log.Println("FFmpeg stdout:", line)
				streamProcess.AddLog("stdout: " + line)
				sm.broadcastLog(LogEntry{
					StreamID: streamID,
					Message:  "stdout: " + line,
					Time:     time.Now().Format(time.RFC3339),
				})
			}
		}()

		// Read and log stderr
		go func() {
			scanner := bufio.NewScanner(stderrPipe)
			for scanner.Scan() {
				line := scanner.Text()
				log.Println("FFmpeg stderr:", line)
				streamProcess.AddLog("stderr: " + line)
				sm.broadcastLog(LogEntry{
					StreamID: streamID,
					Message:  "stderr: " + line,
					Time:     time.Now().Format(time.RFC3339),
				})
			}
		}()

		cmd.Wait()
		sm.mutex.Lock()
		delete(sm.streams, streamID)
		sm.mutex.Unlock()
		streamProcess.closed.Do(func() {
			close(streamProcess.Done)
		})
	}()

	sm.streams[streamID] = streamProcess
	return &streamProcess.Info, nil
}

func (sm *StreamManager) StopStream(streamID string) error {
	sm.mutex.Lock()
	stream, exists := sm.streams[streamID]
	if !exists {
		sm.mutex.Unlock()
		return fmt.Errorf("stream not found")
	}

	// Create a timeout context
	ctx, cancel := context.WithTimeout(context.Background(), streamStopTimeout)
	defer cancel()

	// Kill the entire process group
	if stream.Command.Process != nil {
		pgid, err := syscall.Getpgid(stream.Command.Process.Pid)
		if err == nil {
			// First try SIGTERM
			_ = syscall.Kill(-pgid, syscall.SIGTERM)

			// Wait for graceful shutdown
			select {
			case <-ctx.Done():
				// If timeout, force kill
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			case <-time.After(time.Second):
				// Give it a second to terminate gracefully
			}
		} else {
			// Fallback to regular process kill
			_ = stream.Command.Process.Kill()
		}
	}

	// Cleanup resources
	delete(sm.streams, streamID)
	stream.closed.Do(func() {
		close(stream.Done)
	})
	sm.mutex.Unlock()

	// Cleanup files in background
	go func() {
		hlsDir := filepath.Join(hlsBaseDir, streamID)
		// Wait a bit before removing files
		time.Sleep(time.Second)
		if err := os.RemoveAll(hlsDir); err != nil {
			log.Printf("Error removing HLS directory: %v", err)
		}
	}()

	return nil
}

func (sm *StreamManager) ListStreams() []StreamInfo {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	streams := make([]StreamInfo, 0, len(sm.streams))
	for _, stream := range sm.streams {
		streams = append(streams, stream.Info)
	}
	return streams
}

func (sm *StreamManager) broadcastLog(entry LogEntry) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	for _, clientConn := range sm.sseClients {
		select {
		case clientConn.Channel <- entry:
			// Log sent to client
		default:
			// Channel full, skip this client
		}
	}
}

func handleStartStream(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProfileToken string `json:"profileToken"`
		RtspURL      string `json:"rtspUrl"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	streamInfo, err := streamManager.StartStream(req.ProfileToken, req.RtspURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(streamInfo)
}

func handleStopStream(w http.ResponseWriter, r *http.Request) {
	streamID := r.URL.Query().Get("id")
	if err := streamManager.StopStream(streamID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func handleListStreams(w http.ResponseWriter, r *http.Request) {
	streams := streamManager.ListStreams()
	json.NewEncoder(w).Encode(streams)
}

// LogEntry represents a single log entry
type LogEntry struct {
	StreamID string `json:"streamId"`
	Message  string `json:"message"`
	Time     string `json:"time"`
}

// LogEventHandler handles SSE connections for streaming logs
func handleLogEvents(w http.ResponseWriter, r *http.Request) {
	// Set headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	
	// Create a client channel
	clientChan := make(chan LogEntry, 10)
	clientID := fmt.Sprintf("client-%d", time.Now().UnixNano())
	
	// Create mutex for clients map if not exists
	streamManager.mutex.Lock()
	
	// Add this client to the active SSE clients
	streamManager.sseClients[clientID] = &ClientConnection{
		Channel:    clientChan,
		LastActive: time.Now(),
	}
	streamManager.mutex.Unlock()
	
	// Remove client when connection closes
	defer func() {
		streamManager.mutex.Lock()
		delete(streamManager.sseClients, clientID)
		streamManager.mutex.Unlock()
		close(clientChan)
	}()
	
	// Flush the response writer to send the headers
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	} else {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}
	
	// Send initial logs - but limit to prevent memory overload
	streamManager.mutex.RLock()
	for streamID, stream := range streamManager.streams {
		stream.LogsMutex.RLock()
		// Only send the most recent logs to prevent overwhelming the client
		startIdx := 0
		if len(stream.Logs) > 100 {
			startIdx = len(stream.Logs) - 100
		}
		for _, logMsg := range stream.Logs[startIdx:] {
			entry := LogEntry{
				StreamID: streamID,
				Message:  logMsg,
				Time:     time.Now().Format(time.RFC3339),
			}
			data, _ := json.Marshal(entry)
			fmt.Fprintf(w, "data: %s\n\n", data)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
		stream.LogsMutex.RUnlock()
	}
	streamManager.mutex.RUnlock()
	
	// Create a heartbeat ticker to keep connection alive and update last active time
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()
	
	// Keep connection open and stream logs
	for {
		select {
		case entry := <-clientChan:
			// Update last active time for this client
			streamManager.mutex.Lock()
			if client, exists := streamManager.sseClients[clientID]; exists {
				client.LastActive = time.Now()
			}
			streamManager.mutex.Unlock()
			
			// Marshal the log entry
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			
			// Write the SSE data
			fmt.Fprintf(w, "data: %s\n\n", data)
			
			// Flush to send the data immediately
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			
		case <-heartbeat.C:
			// Send heartbeat and update last active time
			streamManager.mutex.Lock()
			if client, exists := streamManager.sseClients[clientID]; exists {
				client.LastActive = time.Now()
			}
			streamManager.mutex.Unlock()
			
			// Send a comment as heartbeat
			fmt.Fprintf(w, ": heartbeat %s\n\n", time.Now().Format(time.RFC3339))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			
		case <-r.Context().Done():
			// Client disconnected
			return
		}
	}
}

func extractProfileToken(soapResponse string) (string, error) {
	// Simple XML parsing to extract the first Profile token
	if token := strings.Split(soapResponse, `<trt:Profiles token="`); len(token) > 1 {
		if end := strings.Index(token[1], `"`); end != -1 {
			return token[1][:end], nil
		}
	}
	return "", fmt.Errorf("no profile token found")
}

// Replace doHTTPRequest with a simpler version without proxy
func doHTTPRequest(method, targetUrl, contentType string, body io.Reader) (*http.Response, error) {
	client := &http.Client{}

	httpReq, err := http.NewRequest(method, targetUrl, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	if contentType != "" {
		httpReq.Header.Set("Content-Type", contentType)
	}

	return client.Do(httpReq)
}

// Update handleGetStreamUri
func handleGetStreamUri(w http.ResponseWriter, r *http.Request) {
	var req GetStreamUriRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// First get profiles if no token provided
	if (req.ProfileToken == "") {
		profilesEnvelope := GetProfiles.envelope(req.CameraRequest)
		url := fmt.Sprintf("http://%s:%s/%s", req.CameraIp, req.CameraPort, GetProfiles.uri())

		resp, err := doHTTPRequest("POST", url, "application/soap+xml; charset=utf-8",
			strings.NewReader(profilesEnvelope))
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get profiles: %v", err), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		profilesResponse, _ := io.ReadAll(resp.Body)
		token, err := extractProfileToken(string(profilesResponse))
		if err != nil {
			http.Error(w, "No profile token found", http.StatusInternalServerError)
			return
		}
		req.ProfileToken = token
	}

	// Get stream URI with profile token
	streamUriEnvelope := fmt.Sprintf(GetStreamUri.envelope(req.CameraRequest), req.ProfileToken)
	url := fmt.Sprintf("http://%s:%s/%s", req.CameraIp, req.CameraPort, GetStreamUri.uri())

	resp, err := doHTTPRequest("POST", url, "application/soap+xml; charset=utf-8",
		strings.NewReader(streamUriEnvelope))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get stream URI: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	streamUriResponse, _ := io.ReadAll(resp.Body)
	response := map[string]interface{}{
		"url":         url,
		"envelope":    streamUriEnvelope,
		"rawResponse": string(streamUriResponse),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Update handleFuncTest
func handleFuncTest(w http.ResponseWriter, r *http.Request) {
	var req map[string]interface{}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	err = json.Unmarshal(body, &req)
	if err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	var camReq CameraRequest
	if err := json.Unmarshal(body, &camReq); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if camReq.CameraPort == "" {
		camReq.CameraPort = "8000"
	}

	funcName, ok := req["func"].(string)
	if !ok {
		http.Error(w, "Missing or invalid 'func' field", http.StatusBadRequest)
		return
	}

	cameraFunction := ToCameraFunction(funcName)
	uri := cameraFunction.uri()
	url := fmt.Sprintf("http://%s:%s/%s", camReq.CameraIp, camReq.CameraPort, uri)
	envelope := cameraFunction.envelope(camReq)

	resp, err := doHTTPRequest("POST", url, "application/soap+xml; charset=utf-8",
		strings.NewReader(envelope))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to send SOAP request: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	soapResponse, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read SOAP response", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"url":         url,
		"envelope":    envelope,
		"rawResponse": string(soapResponse),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	// Create a temporary directory for HLS files
	var err error
	hlsBaseDir, err = os.MkdirTemp("", "onvif-hls")
	if err != nil {
		log.Fatalf("Failed to create temp directory: %v", err)
	}
	log.Printf("HLS files will be stored in: %s", hlsBaseDir)

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutting down gracefully...")

		// Stop all streams
		streamManager.mutex.Lock()
		for id := range streamManager.streams {
			if err := streamManager.StopStream(id); err != nil {
				log.Printf("Error stopping stream %s: %v", id, err)
			}
		}
		streamManager.mutex.Unlock()

			// Stop cleanup routine
		close(streamManager.stopCleanup)

		// Remove HLS directory
		os.RemoveAll(hlsBaseDir)
		os.Exit(0)
	}()

	// Start client cleanup routine
	go cleanupInactiveClients()

	// Serve the embedded static files
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("Failed to get static files sub-filesystem: %v", err)
	}
	
	// Define HTTP handlers
	http.Handle("/", http.FileServer(http.FS(staticFS)))
	
	// Serve HLS files from temp directory
	http.Handle("/hls/", http.StripPrefix("/hls/", http.FileServer(http.Dir(hlsBaseDir))))

	http.HandleFunc("/api/functest", handleFuncTest)
	http.HandleFunc("/api/stream/start", handleStartStream)
	http.HandleFunc("/api/stream/stop", handleStopStream)
	http.HandleFunc("/api/stream/list", handleListStreams)
	http.HandleFunc("/api/stream/uri", handleGetStreamUri)
	http.HandleFunc("/api/stream/logevents", handleLogEvents)

	log.Println("Server started on :7878")
	log.Fatal(http.ListenAndServe(":7878", nil))
}

func generateNonce() string {
	b := make([]byte, 20)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func calculatePasswordDigest(nonceBase64, created, password string) string {
	nonce, _ := base64.StdEncoding.DecodeString(nonceBase64)

	createdBytes := []byte(created)
	passwordBytes := []byte(password)

	h := sha1.New()
	h.Write(nonce)
	h.Write(createdBytes)
	h.Write(passwordBytes)
	sha := h.Sum(nil)

	digest := base64.StdEncoding.EncodeToString(sha)

	return digest
}

func generateSecurityHeader(cam CameraRequest) string {
	created := time.Now().UTC().Format(time.RFC3339)

	nonce := generateNonce()
	passwordDigest := calculatePasswordDigest(nonce, created, cam.Password)

	return fmt.Sprintf(`
	<SOAP-ENV:Header>
		<wsse:Security SOAP-ENV:mustUnderstand="1">
			<wsse:UsernameToken>
				<wsse:Username>%s</wsse:Username>
				<wsse:Password
					Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">
					%s</wsse:Password>
				<wsse:Nonce
					EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">
					%s</wsse:Nonce>
				<wsu:Created>%s</wsu:Created>
			</wsse:UsernameToken>
		</wsse:Security>
	</SOAP-ENV:Header>`, cam.Username, passwordDigest, nonce, created)
}

func (sp *StreamProcess) AddLog(message string) {
	sp.LogsMutex.Lock()
	defer sp.LogsMutex.Unlock()

	// Add the log
	sp.Logs = append(sp.Logs, message)

	// Check if we need to trim the logs to prevent memory leaks
	if len(sp.Logs) > sp.LogMaxSize {
		// Keep only the most recent logs (last sp.LogMaxSize entries)
		sp.Logs = sp.Logs[len(sp.Logs)-sp.LogMaxSize:]
	}
}

func cleanupInactiveClients() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			streamManager.mutex.Lock()
			
			// Log current client count for monitoring
			clientCount := len(streamManager.sseClients)
			if clientCount > 0 {
				log.Printf("Cleaning up inactive clients. Current count: %d", clientCount)
			}
			
			// Check each client's last activity time
			for clientID, clientConn := range streamManager.sseClients {
				if now.Sub(clientConn.LastActive) > streamManager.clientTimeout {
					log.Printf("Cleaning up inactive client: %s (inactive for %v)", 
						clientID, now.Sub(clientConn.LastActive))
					close(clientConn.Channel)
					delete(streamManager.sseClients, clientID)
				}
			}
			
			streamManager.mutex.Unlock()
			
		case <-streamManager.stopCleanup:
			return
		}
	}
}
