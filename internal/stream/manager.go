package stream

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"dengan.dev/onvif/internal/logger"
	"dengan.dev/onvif/internal/models"
)

const (
	streamStopTimeout    = 5 * time.Second
	maxLogEntries        = 500
	maxReconnectAttempts = 5
	reconnectDelay       = 2 * time.Second
	maxReconnectDelay    = 30 * time.Second
)

// Process represents a single FFmpeg stream process
type Process struct {
	Info            models.StreamInfo
	Command         *exec.Cmd
	Done            chan bool
	closed          sync.Once
	logger          *logger.Logger
	reconnectCount  int
	shouldReconnect bool
	lastReconnect   time.Time
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
		if stream.Info.ProfileToken == profileToken {
			sm.logger.LogInfo(stream.Info.ID, "system", "Stream already exists for profile token")
			return &stream.Info, nil
		}
	}

	// Create stream ID and HLS path
	streamID := fmt.Sprintf("stream_%d", time.Now().Unix())
	hlsDir := filepath.Join(sm.hlsBaseDir, streamID)

	if err := os.MkdirAll(hlsDir, 0755); err != nil {
		sm.logger.LogError(streamID, "system", fmt.Sprintf("Failed to create HLS directory: %v", err))
		return nil, fmt.Errorf("failed to create HLS directory: %v", err)
	}

	// Prepare FFmpeg command with improved settings for stability
	args := []string{
		"-y",                 // Overwrite output files
		"-fflags", "+genpts", // Generate presentation timestamps
		"-rtsp_transport", "tcp", // Use TCP for RTSP (more reliable)
		"-rtsp_flags", "prefer_tcp", // Prefer TCP
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

	// Set process group for better process management
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
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
		Command:         cmd,
		Done:            make(chan bool),
		logger:          sm.logger,
		shouldReconnect: true,
		reconnectCount:  0,
	}

	// Log the FFmpeg command
	cmdStr := fmt.Sprintf("ffmpeg %s", strings.Join(args, " "))
	sm.logger.LogInfo(streamID, "system", fmt.Sprintf("Starting FFmpeg: %s", cmdStr))
	log.Printf("Starting stream %s with command: %s", streamID, cmdStr)

	// Start FFmpeg process
	if err := cmd.Start(); err != nil {
		sm.logger.LogError(streamID, "system", fmt.Sprintf("Failed to start FFmpeg: %v", err))
		return nil, fmt.Errorf("failed to start FFmpeg: %v", err)
	}

	streamProcess.Info.Status = "running"
	sm.logger.LogInfo(streamID, "system", "FFmpeg process started successfully")

	// Monitor process in separate goroutines
	go sm.monitorStreamWithReconnect(streamProcess, hlsDir)

	sm.streams[streamID] = streamProcess
	return &streamProcess.Info, nil
}

// createFFmpegCommand creates a new FFmpeg command for the given stream
func (sm *Manager) createFFmpegCommand(rtspURL string, hlsDir string) *exec.Cmd {
	// Prepare FFmpeg command with improved settings for stability
	args := []string{
		"-y",                 // Overwrite output files
		"-fflags", "+genpts", // Generate presentation timestamps
		"-rtsp_transport", "tcp", // Use TCP for RTSP (more reliable)
		"-rtsp_flags", "prefer_tcp", // Prefer TCP
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
	for {
		process.mutex.Lock()
		if !process.shouldReconnect {
			process.mutex.Unlock()
			break
		}
		process.mutex.Unlock()

		// Start or restart the FFmpeg process
		err := sm.startFFmpegProcess(process, hlsDir)
		if err != nil {
			sm.logger.LogError(process.Info.ID, "system", fmt.Sprintf("Failed to start FFmpeg: %v", err))

			process.mutex.Lock()
			if process.reconnectCount >= maxReconnectAttempts {
				sm.logger.LogError(process.Info.ID, "system", "Max reconnection attempts reached, giving up")
				process.shouldReconnect = false
				process.Info.Status = "failed"
				process.mutex.Unlock()
				break
			}

			process.reconnectCount++
			delay := time.Duration(process.reconnectCount) * reconnectDelay
			if delay > maxReconnectDelay {
				delay = maxReconnectDelay
			}
			process.lastReconnect = time.Now()
			process.mutex.Unlock()

			sm.logger.LogWarn(process.Info.ID, "system", fmt.Sprintf("Reconnection attempt %d/%d in %v", process.reconnectCount, maxReconnectAttempts, delay))
			time.Sleep(delay)
			continue
		}

		// Monitor the process
		sm.monitorSingleProcess(process)

		// Check if we should reconnect
		process.mutex.Lock()
		shouldContinue := process.shouldReconnect && process.reconnectCount < maxReconnectAttempts
		process.mutex.Unlock()

		if !shouldContinue {
			break
		}

		// Brief delay before reconnecting
		time.Sleep(reconnectDelay)
	}

	// Cleanup when done
	process.closed.Do(func() {
		close(process.Done)
	})
}

// startFFmpegProcess starts a new FFmpeg process for the given stream
func (sm *Manager) startFFmpegProcess(process *Process, hlsDir string) error {
	process.Command = sm.createFFmpegCommand(process.Info.RtspURL, hlsDir)

	// Create pipes for monitoring before starting the process
	stdoutPipe, err := process.Command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	stderrPipe, err := process.Command.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %v", err)
	}

	// Log the FFmpeg command
	args := process.Command.Args[1:] // Skip the "ffmpeg" part
	cmdStr := fmt.Sprintf("ffmpeg %s", strings.Join(args, " "))
	sm.logger.LogInfo(process.Info.ID, "system", fmt.Sprintf("Starting FFmpeg: %s", cmdStr))
	log.Printf("Starting stream %s with command: %s", process.Info.ID, cmdStr)

	// Start FFmpeg process
	if err := process.Command.Start(); err != nil {
		return fmt.Errorf("failed to start FFmpeg: %v", err)
	}

	process.Info.Status = "running"
	sm.logger.LogInfo(process.Info.ID, "system", "FFmpeg process started successfully")

	// Start monitoring in goroutines
	go sm.monitorPipes(process, stdoutPipe, stderrPipe)

	return nil
}

// monitorPipes monitors stdout and stderr pipes
func (sm *Manager) monitorPipes(process *Process, stdoutPipe, stderrPipe io.ReadCloser) {
	// Monitor stdout
	go func() {
		defer stdoutPipe.Close()
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			line := scanner.Text()
			if line != "" {
				sm.logger.LogDebug(process.Info.ID, "ffmpeg_stdout", line)
				sm.broadcastLog(models.LogEntry{
					StreamID: process.Info.ID,
					Message:  fmt.Sprintf("stdout: %s", line),
					Time:     time.Now().Format(time.RFC3339),
				})
			}
		}
		if err := scanner.Err(); err != nil {
			sm.logger.LogError(process.Info.ID, "ffmpeg_stdout", fmt.Sprintf("Scanner error: %v", err))
		}
	}()

	// Monitor stderr
	go func() {
		defer stderrPipe.Close()
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			if line != "" {
				// Filter out noisy progress messages (optional)
				if shouldLogFFmpegLine(line) {
					// Determine log level based on content
					logLevel := determineLogLevel(line)
					switch logLevel {
					case logger.ERROR:
						sm.logger.LogError(process.Info.ID, "ffmpeg", line)
					case logger.WARN:
						sm.logger.LogWarn(process.Info.ID, "ffmpeg", line)
					default:
						sm.logger.LogInfo(process.Info.ID, "ffmpeg", line)
					}

					sm.broadcastLog(models.LogEntry{
						StreamID: process.Info.ID,
						Message:  fmt.Sprintf("ffmpeg: %s", line),
						Time:     time.Now().Format(time.RFC3339),
					})
				}
			}
		}
		if err := scanner.Err(); err != nil {
			sm.logger.LogError(process.Info.ID, "ffmpeg_stderr", fmt.Sprintf("Scanner error: %v", err))
		}
	}()
}

// monitorSingleProcess monitors a single FFmpeg process instance
func (sm *Manager) monitorSingleProcess(process *Process) {
	if err := process.Command.Wait(); err != nil {
		sm.logger.LogError(process.Info.ID, "system", fmt.Sprintf("FFmpeg process exited with error: %v", err))
		log.Printf("Stream %s: FFmpeg exited with error: %v", process.Info.ID, err)

		// Reset reconnect count on successful periods
		process.mutex.Lock()
		if time.Since(process.lastReconnect) > 30*time.Second {
			process.reconnectCount = 0 // Reset if stream ran for a while
		}
		process.mutex.Unlock()
	} else {
		sm.logger.LogInfo(process.Info.ID, "system", "FFmpeg process completed normally")
		log.Printf("Stream %s: FFmpeg completed normally", process.Info.ID)

		// Reset reconnect count on normal completion
		process.mutex.Lock()
		process.reconnectCount = 0
		process.mutex.Unlock()
	}
}

// determineLogLevel determines the log level based on FFmpeg output content
func determineLogLevel(line string) logger.LogLevel {
	lowerLine := strings.ToLower(line)

	// FFmpeg error indicators
	if strings.Contains(lowerLine, "error") ||
		strings.Contains(lowerLine, "failed") ||
		strings.Contains(lowerLine, "cannot") ||
		strings.Contains(lowerLine, "unable") {
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
		strings.Contains(lowerLine, "deprecated") {
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

	// Skip noisy frame progress messages (optional - set to true if you want them)
	if strings.Contains(lowerLine, "frame=") && strings.Contains(lowerLine, "fps=") {
		return false // Change to true if you want progress messages
	}

	// Log everything else by default
	return true
}

// StopStream stops a stream by its ID
func (sm *Manager) StopStream(streamID string) error {
	sm.mutex.Lock()
	stream, exists := sm.streams[streamID]
	if !exists {
		sm.mutex.Unlock()
		return fmt.Errorf("stream not found")
	}

	sm.logger.LogInfo(streamID, "system", "Stopping stream")

	// Disable reconnection first
	stream.mutex.Lock()
	stream.shouldReconnect = false
	stream.mutex.Unlock()

	// Create a timeout context
	ctx, cancel := context.WithTimeout(context.Background(), streamStopTimeout)
	defer cancel()

	// Kill the entire process group
	if stream.Command != nil && stream.Command.Process != nil {
		pgid, err := syscall.Getpgid(stream.Command.Process.Pid)
		if err == nil {
			// First try SIGTERM for graceful shutdown
			sm.logger.LogInfo(streamID, "system", "Sending SIGTERM to process group")
			_ = syscall.Kill(-pgid, syscall.SIGTERM)

			// Wait for graceful shutdown
			select {
			case <-ctx.Done():
				// If timeout, force kill
				sm.logger.LogWarn(streamID, "system", "Graceful shutdown timed out, force killing")
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			case <-time.After(time.Second):
				// Give it a second to terminate gracefully
			}
		} else {
			// Fallback to regular process kill
			sm.logger.LogWarn(streamID, "system", "Failed to get process group, using regular kill")
			_ = stream.Command.Process.Kill()
		}
	}

	// Update status and cleanup
	stream.Info.Status = "stopping"
	delete(sm.streams, streamID)
	stream.closed.Do(func() {
		close(stream.Done)
	})
	sm.mutex.Unlock()

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
		streams = append(streams, stream.Info)
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

	for clientID, clientConn := range sm.sseClients {
		select {
		case clientConn.Channel <- entry:
			// Log sent successfully
		default:
			// Channel full, skip this client
			log.Printf("SSE client %s channel full, skipping log broadcast", clientID)
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
