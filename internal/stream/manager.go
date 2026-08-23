package stream

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/models"
)

const (
	streamStopTimeout    = 5 * time.Second
	maxLogEntries        = 500
	maxReconnectAttempts = 30
	reconnectDelay       = 5 * time.Second
	maxReconnectDelay    = 60 * time.Second
	stableRunThreshold   = 30 * time.Second
	maxBufferedLogLine   = 64 * 1024
)

// Process represents a single FFmpeg stream process
type Process struct {
	Info            models.StreamInfo
	Command         *exec.Cmd
	Done            chan bool
	Exited          chan struct{}
	closed          sync.Once
	logger          *logger.Logger
	reconnectCount  int
	shouldReconnect bool
	mutex           sync.RWMutex
}

// Manager manages multiple video streams
type Manager struct {
	streams       map[string]*Process
	mutex         sync.RWMutex
	sseClients    map[string]*models.ClientConnection
	clientTimeout time.Duration
	stopCleanup   chan struct{}
	hlsBaseDir    string
	logger        *logger.Logger
}

// NewManager creates a new stream manager
func NewManager(hlsBaseDir string, logger *logger.Logger) *Manager {
	return &Manager{
		streams:       make(map[string]*Process),
		sseClients:    make(map[string]*models.ClientConnection),
		clientTimeout: 3 * time.Minute,
		stopCleanup:   make(chan struct{}),
		hlsBaseDir:    hlsBaseDir,
		logger:        logger,
	}
}

// StartStream starts a new FFmpeg stream process
func (sm *Manager) StartStream(profileToken, rtspURL string) (*models.StreamInfo, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Check if stream already exists for this profile
	for _, stream := range sm.streams {
		stream.mutex.RLock()
		if stream.Info.ProfileToken == profileToken {
			info := stream.Info
			stream.mutex.RUnlock()
			sm.logger.LogInfo(info.ID, "system", "Stream already exists for profile token")
			return &info, nil
		}
		stream.mutex.RUnlock()
	}

	// Create stream ID and HLS path
	streamID := fmt.Sprintf("stream_%d", time.Now().Unix())
	hlsDir := filepath.Join(sm.hlsBaseDir, streamID)

	if err := os.MkdirAll(hlsDir, 0755); err != nil {
		sm.logger.LogError(streamID, "system", fmt.Sprintf("Failed to create HLS directory: %v", err))
		return nil, fmt.Errorf("failed to create HLS directory: %v", err)
	}

	streamProcess := &Process{
		Info: models.StreamInfo{
			ID:           streamID,
			ProfileToken: profileToken,
			RtspURL:      rtspURL,
			HlsURL:       fmt.Sprintf("/hls/%s/stream.m3u8", streamID),
			StartedAt:    time.Now(),
			Status:       "starting",
		},
		Command:         nil,
		Done:            make(chan bool),
		Exited:          make(chan struct{}),
		logger:          sm.logger,
		shouldReconnect: true,
		reconnectCount:  0,
	}

	sm.logger.LogInfo(streamID, "system", "Initializing stream monitoring and connection")
	log.Printf("Initializing stream %s", streamID)

	info := streamProcess.Info
	sm.streams[streamID] = streamProcess

	// Monitor process only after the initial response snapshot is complete.
	go sm.monitorStreamWithReconnect(streamProcess, hlsDir)
	return &info, nil
}

// reconnectBackoff returns capped exponential delay after consecutive failures.
func reconnectBackoff(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	delay := reconnectDelay
	for i := 1; i < failures && delay < maxReconnectDelay; i++ {
		delay *= 2
		if delay > maxReconnectDelay {
			delay = maxReconnectDelay
		}
	}
	return delay
}

func nextReconnectFailureCount(current int, runDuration time.Duration) int {
	if runDuration >= stableRunThreshold {
		return 1
	}
	return current + 1
}

func redactSensitiveText(text string) string {
	lower := strings.ToLower(text)
	searchFrom := 0
	for {
		rel := strings.Index(lower[searchFrom:], "rtsp://")
		if rel < 0 {
			return text
		}
		start := searchFrom + rel
		authStart := start + len("rtsp://")
		atRel := strings.Index(text[authStart:], "@")
		if atRel < 0 {
			return text
		}
		at := authStart + atRel
		endRel := strings.IndexAny(text[authStart:at], " /\t\r\n")
		if endRel >= 0 {
			searchFrom = authStart
			continue
		}
		text = text[:authStart] + "REDACTED" + text[at:]
		lower = strings.ToLower(text)
		searchFrom = authStart + len("REDACTED@")
	}
}

func sanitizeFFmpegArgs(args []string) []string {
	sanitized := append([]string(nil), args...)
	for i := range sanitized {
		sanitized[i] = redactSensitiveText(sanitized[i])
	}
	return sanitized
}

// createFFmpegCommand creates a new FFmpeg command for the given stream
func (sm *Manager) createFFmpegCommand(rtspURL string, hlsDir string) *exec.Cmd {
	// Prepare FFmpeg command with improved settings for stability
	args := []string{
		"-y",                 // Overwrite output files
		"-fflags", "+genpts", // Generate presentation timestamps
		"-rtsp_transport", "tcp", // Use TCP for RTSP (more reliable)
		"-rtsp_flags", "prefer_tcp", // Prefer TCP
		"-timeout", "5000000", // 5 seconds socket timeout
		"-i", rtspURL,
		"-c:v", "copy", // Copy video codec (no transcoding)
		"-c:a", "aac", // Audio codec
		"-avoid_negative_ts", "make_zero", // Handle negative timestamps
		"-hls_time", "2", // 2 second segments
		"-hls_list_size", "5", // Keep 5 segments in playlist
		"-hls_flags", "delete_segments+independent_segments", // Delete old segments
		"-hls_segment_type", "mpegts", // Use MPEG-TS segments
		"-f", "hls", // Output format
		filepath.Join(hlsDir, "stream.m3u8"),
	}

	cmd := exec.Command("ffmpeg", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	return cmd
}

// monitorStreamWithReconnect monitors a stream and handles reconnection
func (sm *Manager) monitorStreamWithReconnect(process *Process, hlsDir string) {
	defer close(process.Exited)
	defer process.closed.Do(func() { close(process.Done) })

	for {
		startedAt := time.Now()
		cmd, err := sm.startFFmpegProcess(process, hlsDir)
		if err == nil {
			err = cmd.Wait()
			if writer, ok := cmd.Stdout.(*filteredLogWriter); ok {
				writer.Flush()
			}
			if writer, ok := cmd.Stderr.(*filteredLogWriter); ok {
				writer.Flush()
			}
			runDuration := time.Since(startedAt)
			if err != nil {
				sm.logger.LogError(process.Info.ID, "system", fmt.Sprintf("FFmpeg exited after %s: %v", runDuration.Round(time.Second), err))
				log.Printf("Stream %s: FFmpeg exited after %s: %v", process.Info.ID, runDuration.Round(time.Second), err)
			} else {
				sm.logger.LogWarn(process.Info.ID, "system", fmt.Sprintf("FFmpeg exited normally after %s; reconnecting", runDuration.Round(time.Second)))
			}
			process.mutex.Lock()
			process.Command = nil
			process.reconnectCount = nextReconnectFailureCount(process.reconnectCount, runDuration)
			process.mutex.Unlock()
		} else {
			process.mutex.Lock()
			stopping := !process.shouldReconnect
			if !stopping {
				process.reconnectCount++
			}
			process.mutex.Unlock()
			if stopping {
				return
			}
			sm.logger.LogError(process.Info.ID, "system", fmt.Sprintf("Failed to start FFmpeg: %v", err))
		}

		process.mutex.Lock()
		if !process.shouldReconnect {
			process.mutex.Unlock()
			return
		}
		failures := process.reconnectCount
		if failures >= maxReconnectAttempts {
			process.shouldReconnect = false
			process.Info.Status = "failed"
			process.mutex.Unlock()
			sm.logger.LogError(process.Info.ID, "system", "Maximum reconnection attempts reached; stream stopped")
			return
		}
		delay := reconnectBackoff(failures)
		process.Info.Status = "reconnecting"
		process.mutex.Unlock()

		sm.logger.LogWarn(process.Info.ID, "system", fmt.Sprintf("Reconnection attempt %d/%d in %s", failures, maxReconnectAttempts, delay))
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-process.Done:
			timer.Stop()
			return
		}
	}
}

type filteredLogWriter struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	handle func(string)
}

func (w *filteredLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	originalLen := len(p)
	for _, b := range p {
		if b == '\n' || b == '\r' {
			w.emitLocked()
			continue
		}
		if w.buffer.Len() >= maxBufferedLogLine {
			w.emitLocked()
		}
		_ = w.buffer.WriteByte(b)
	}
	return originalLen, nil
}

func (w *filteredLogWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.emitLocked()
}

func (w *filteredLogWriter) emitLocked() {
	line := strings.TrimSpace(w.buffer.String())
	w.buffer.Reset()
	if line != "" {
		w.handle(line)
	}
}

// startFFmpegProcess creates and starts FFmpeg while holding the process lock,
// preventing StopStream from missing a concurrently starting process.
func (sm *Manager) startFFmpegProcess(process *Process, hlsDir string) (*exec.Cmd, error) {
	process.mutex.Lock()
	defer process.mutex.Unlock()
	if !process.shouldReconnect {
		return nil, fmt.Errorf("stream is stopping")
	}

	cmd := sm.createFFmpegCommand(process.Info.RtspURL, hlsDir)
	args := sanitizeFFmpegArgs(cmd.Args[1:])
	cmdStr := fmt.Sprintf("ffmpeg %s", strings.Join(args, " "))
	sm.logger.LogInfo(process.Info.ID, "system", fmt.Sprintf("Starting FFmpeg: %s", cmdStr))
	log.Printf("Starting stream %s with command: %s", process.Info.ID, cmdStr)

	cmd.Stdout = &filteredLogWriter{handle: func(line string) { sm.handleFFmpegLine(process, "ffmpeg_stdout", line) }}
	cmd.Stderr = &filteredLogWriter{handle: func(line string) { sm.handleFFmpegLine(process, "ffmpeg", line) }}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start FFmpeg: %v", err)
	}
	process.Command = cmd
	process.Info.Status = "running"
	sm.logger.LogInfo(process.Info.ID, "system", "FFmpeg process started successfully")
	return cmd, nil
}

func (sm *Manager) handleFFmpegLine(process *Process, source, line string) {
	line = redactSensitiveText(line)
	if line == "" || !shouldLogFFmpegLine(line) {
		return
	}
	level := determineLogLevel(line)
	switch level {
	case logger.ERROR:
		sm.logger.LogError(process.Info.ID, source, line)
	case logger.WARN:
		sm.logger.LogWarn(process.Info.ID, source, line)
	default:
		sm.logger.LogInfo(process.Info.ID, source, line)
	}
	sm.broadcastLog(models.LogEntry{StreamID: process.Info.ID, Message: fmt.Sprintf("ffmpeg: %s", line), Time: time.Now().Format(time.RFC3339)})
}

// determineLogLevel determines the log level based on FFmpeg output content
func determineLogLevel(line string) logger.LogLevel {
	lowerLine := strings.ToLower(line)

	// FFmpeg error indicators
	if strings.Contains(lowerLine, "error") ||
		strings.Contains(lowerLine, "failed") ||
		strings.Contains(lowerLine, "cannot") ||
		strings.Contains(lowerLine, "unable") ||
		strings.Contains(lowerLine, "timed out") ||
		strings.Contains(lowerLine, "connection refused") {
		return logger.ERROR
	}

	// FFmpeg warning indicators
	if strings.Contains(lowerLine, "warning") ||
		strings.Contains(lowerLine, "deprecated") ||
		strings.Contains(lowerLine, "no such file") ||
		strings.Contains(lowerLine, "overriding") {
		return logger.WARN
	}

	// Progress indicators are usually info level
	if strings.Contains(lowerLine, "frame=") ||
		strings.Contains(lowerLine, "opening") ||
		strings.Contains(lowerLine, "fps=") {
		return logger.INFO
	}

	return logger.INFO
}

// shouldLogFFmpegLine determines if an FFmpeg output line should be logged
func shouldLogFFmpegLine(line string) bool {
	lowerLine := strings.ToLower(line)

	// Always log errors and warnings
	if strings.Contains(lowerLine, "error") ||
		strings.Contains(lowerLine, "failed") ||
		strings.Contains(lowerLine, "warning") ||
		strings.Contains(lowerLine, "deprecated") ||
		strings.Contains(lowerLine, "timed out") ||
		strings.Contains(lowerLine, "connection refused") {
		return true
	}

	// Log important operational messages
	if strings.Contains(lowerLine, "opening") ||
		strings.Contains(lowerLine, "input #") ||
		strings.Contains(lowerLine, "output #") ||
		strings.Contains(lowerLine, "stream mapping") ||
		strings.Contains(lowerLine, "codec") {
		return true
	}

	// Drop banners, library versions, progress, and other routine chatter.
	return false
}

// StopStream stops a stream by its ID
func (sm *Manager) StopStream(streamID string) error {
	sm.mutex.Lock()
	stream, exists := sm.streams[streamID]
	if !exists {
		sm.mutex.Unlock()
		return fmt.Errorf("stream not found")
	}
	// Remove it from the public active set immediately, but keep the local
	// reference until FFmpeg and its output writers have fully exited.
	delete(sm.streams, streamID)
	sm.mutex.Unlock()

	sm.logger.LogInfo(streamID, "system", "Stopping stream")

	// Disable reconnection and snapshot the current command atomically with start.
	stream.mutex.Lock()
	stream.shouldReconnect = false
	stream.Info.Status = "stopping"
	cmd := stream.Command
	stream.closed.Do(func() { close(stream.Done) })
	stream.mutex.Unlock()

	// Terminate the process group, then wait for the monitor to confirm exit.
	if cmd != nil && cmd.Process != nil {
		pgid, err := syscall.Getpgid(cmd.Process.Pid)
		if err == nil {
			sm.logger.LogInfo(streamID, "system", "Sending SIGTERM to process group")
			_ = syscall.Kill(-pgid, syscall.SIGTERM)
		} else {
			sm.logger.LogWarn(streamID, "system", "Failed to get process group, using regular kill")
			_ = cmd.Process.Signal(syscall.SIGTERM)
		}
	}

	grace := time.NewTimer(streamStopTimeout)
	select {
	case <-stream.Exited:
		grace.Stop()
	case <-grace.C:
		if cmd != nil && cmd.Process != nil {
			sm.logger.LogWarn(streamID, "system", "Graceful shutdown timed out, force killing")
			if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			} else {
				_ = cmd.Process.Kill()
			}
		}
		forceWait := time.NewTimer(streamStopTimeout)
		select {
		case <-stream.Exited:
			forceWait.Stop()
		case <-forceWait.C:
			return fmt.Errorf("stream process did not exit after SIGKILL")
		}
	}

	// Cleanup files in background
	go func() {
		hlsDir := filepath.Join(sm.hlsBaseDir, streamID)
		// Wait a bit before removing files
		time.Sleep(2 * time.Second)
		if err := os.RemoveAll(hlsDir); err != nil {
			sm.logger.LogError(streamID, "system", fmt.Sprintf("Error removing HLS directory: %v", err))
			log.Printf("Error removing HLS directory for stream %s: %v", streamID, err)
		} else {
			sm.logger.LogInfo(streamID, "system", "HLS directory cleaned up")
		}
	}()

	return nil
}

// ListStreams returns information about all active streams
func (sm *Manager) ListStreams() []models.StreamInfo {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	streams := make([]models.StreamInfo, 0, len(sm.streams))
	for _, stream := range sm.streams {
		stream.mutex.RLock()
		streams = append(streams, stream.Info)
		stream.mutex.RUnlock()
	}
	return streams
}

// AddSSEClient adds a new SSE client
func (sm *Manager) AddSSEClient(clientID string, client *models.ClientConnection) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.sseClients[clientID] = client
}

// RemoveSSEClient removes an SSE client
func (sm *Manager) RemoveSSEClient(clientID string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	if client, exists := sm.sseClients[clientID]; exists {
		close(client.Channel)
		delete(sm.sseClients, clientID)
	}
}

// broadcastLog broadcasts a log entry to all SSE clients
func (sm *Manager) broadcastLog(entry models.LogEntry) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	for _, clientConn := range sm.sseClients {
		select {
		case clientConn.Channel <- entry:
			// Log sent successfully
		default:
			// Channel full, silently skip to aggressively prevent console bloat
		}
	}
}

// CleanupInactiveClients starts a background routine to clean up inactive SSE clients
func (sm *Manager) CleanupInactiveClients() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			sm.mutex.Lock()

			clientCount := len(sm.sseClients)
			if clientCount > 0 {
				log.Printf("Cleaning up inactive clients. Current count: %d", clientCount)
			}

			// Check each client's last activity time
			for clientID, clientConn := range sm.sseClients {
				if now.Sub(clientConn.LastActive) > sm.clientTimeout {
					log.Printf("Cleaning up inactive client: %s (inactive for %v)",
						clientID, now.Sub(clientConn.LastActive))
					close(clientConn.Channel)
					delete(sm.sseClients, clientID)
				}
			}

			sm.mutex.Unlock()

		case <-sm.stopCleanup:
			return
		}
	}
}

// UpdateClientActivity updates the last active time for a client
func (sm *Manager) UpdateClientActivity(clientID string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if client, exists := sm.sseClients[clientID]; exists {
		client.LastActive = time.Now()
	}
}

// GetSSEClients returns a copy of current SSE clients
func (sm *Manager) GetSSEClients() map[string]*models.ClientConnection {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	clients := make(map[string]*models.ClientConnection)
	for id, client := range sm.sseClients {
		clients[id] = client
	}
	return clients
}

// Shutdown gracefully shuts down the stream manager
func (sm *Manager) Shutdown() {
	log.Println("Shutting down stream manager...")

	// Stop all active streams
	sm.mutex.Lock()
	streamIDs := make([]string, 0, len(sm.streams))
	for id, stream := range sm.streams {
		streamIDs = append(streamIDs, id)
		// Disable reconnection for all streams
		stream.mutex.Lock()
		stream.shouldReconnect = false
		stream.mutex.Unlock()
	}
	sm.mutex.Unlock()

	for _, id := range streamIDs {
		if err := sm.StopStream(id); err != nil {
			log.Printf("Error stopping stream %s: %v", id, err)
		}
	}

	// Stop cleanup routine
	close(sm.stopCleanup)

	// Close all SSE clients
	sm.mutex.Lock()
	for clientID, client := range sm.sseClients {
		close(client.Channel)
		delete(sm.sseClients, clientID)
	}
	sm.mutex.Unlock()

	log.Println("Stream manager shutdown complete")
}
