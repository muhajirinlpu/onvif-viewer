package stream

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	// hlsStallTimeout is the watchdog for "connected but no frames". It MUST stay
	// comfortably above this camera's natural playlist advance interval: the
	// camera emits segments with zero duration (EXTINF:0.000000), so with
	// -c:v copy the playlist only advances once per keyframe interval (~30s).
	// A timeout near that cadence turns the watchdog into a guaranteed self-kill,
	// so keep it at 90s until the segment cadence is fixed at the source.
	hlsStallTimeout   = 90 * time.Second
	hlsHealthInterval = 3 * time.Second
	// sessionProbeTimeout bounds the RTSP probe used during reconnection.
	sessionProbeTimeout = 3 * time.Second
	// sessionProbeCollect is how long the probe samples RTP to tell "camera
	// granted but silent" from "camera refused".
	sessionProbeCollect = 2 * time.Second
	// sessionTableBackoff is the pause after the camera reports an exhausted
	// session table. Retrying fast cannot help: the orphaned sessions are only
	// reaped by the camera's own expiry, so the loop must back off and keep
	// probing rather than burning attempts.
	sessionTableBackoff = 2 * time.Minute
	// playlistFirstSegmentGrace is added to hlsStallTimeout before a totally
	// absent playlist/segment set is treated as a stall. This camera's HLS
	// muxer can take ~30-90s to close its first segment with -c:v copy, so
	// without this grace the watchdog kills a healthy start.
	playlistFirstSegmentGrace = 120 * time.Second
)

// StatusNeedsRelogin is the stream status used when a provider's stored session
// was rejected by its cloud. The stream is deliberately stopped (so an HLS
// watchdog cannot hot-loop ffmpeg against a dead source) but its card stays
// visible and asks for a re-login.
const StatusNeedsRelogin = "needs_relogin"

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
	// suspended marks a stream that was deliberately stood down while its
	// registered state is kept, so the card stays visible and a resume can
	// restart it later. Used by the M6 Tuya session-loss degradation.
	suspended       bool
	suspendedReason string
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
	snapshotSem   chan struct{}
	// ffmpegBin is the ffmpeg executable. Empty means "ffmpeg" from PATH, which
	// is what every production call site has always used; it is a field purely so
	// a test can substitute a stub instead of spawning a real encoder.
	ffmpegBin string
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
		snapshotSem:   make(chan struct{}, 1),
	}
}

func newStreamID() string {
	return fmt.Sprintf("stream_%d", time.Now().UnixNano())
}

// StartStream starts a new FFmpeg stream process. The provider defaults to
// ONVIF, which is what every ONVIF call site has always meant.
func (sm *Manager) StartStream(profileToken, rtspURL string) (*models.StreamInfo, error) {
	return sm.startStreamWithProvider(profileToken, rtspURL, models.ProviderONVIF, true)
}

// StartStreamForProvider starts (and persists) a stream tagged with the provider
// that owns it, so a Tuya stream is restored as Tuya across restarts.
func (sm *Manager) StartStreamForProvider(profileToken, rtspURL string, provider models.ProviderKind) (*models.StreamInfo, error) {
	return sm.startStreamWithProvider(profileToken, rtspURL, provider, true)
}

func (sm *Manager) startStream(profileToken, rtspURL string, persist bool) (*models.StreamInfo, error) {
	return sm.startStreamWithProvider(profileToken, rtspURL, models.ProviderONVIF, persist)
}

func (sm *Manager) startStreamWithProvider(profileToken, rtspURL string, provider models.ProviderKind, persist bool) (*models.StreamInfo, error) {
	provider = provider.OrDefault()
	if profileToken == "" || rtspURL == "" {
		return nil, fmt.Errorf("profile token and RTSP URL are required")
	}
	sm.mutex.Lock()

	// Check if stream already exists for this profile
	for _, stream := range sm.streams {
		stream.mutex.RLock()
		if stream.Info.ProfileToken == profileToken {
			suspended := stream.suspended
			id := stream.Info.ID
			info := stream.Info
			stream.mutex.RUnlock()
			if suspended {
				// A suspended stream (Tuya session loss) is resumed in place
				// with the URL the caller just resolved, so the card, the
				// profile token and the persisted config are all reused and no
				// device has to be re-selected.
				//
				// The manager lock MUST be dropped first: publishState
				// broadcasts to SSE clients and re-takes sm.mutex as a reader,
				// and Go's RWMutex is not reentrant.
				sm.mutex.Unlock()
				return sm.ResumeSuspended(id, rtspURL, provider)
			}
			if info.RtspURL != rtspURL {
				return nil, fmt.Errorf("profile %s is already running with a different RTSP URL; stop it before starting the new URL", profileToken)
			}
			sm.logger.LogInfo(info.ID, "system", "Stream already exists for profile token")
			return &info, nil
		}
		stream.mutex.RUnlock()
	}

	// Create stream ID and HLS path
	streamID := newStreamID()
	hlsDir := filepath.Join(sm.hlsBaseDir, streamID)

	if err := os.MkdirAll(hlsDir, 0755); err != nil {
		sm.logger.LogError(streamID, "system", fmt.Sprintf("Failed to create HLS directory: %v", err))
		return nil, fmt.Errorf("failed to create HLS directory: %v", err)
	}
	if persist {
		if err := sm.logger.UpsertStreamConfig(profileToken, rtspURL, string(provider)); err != nil {
			_ = os.RemoveAll(hlsDir)
			return nil, fmt.Errorf("persist stream configuration: %w", err)
		}
	}

	streamProcess := &Process{
		Info: models.StreamInfo{
			ID:           streamID,
			ProfileToken: profileToken,
			Provider:     provider,
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
	sm.mutex.Unlock()

	// Monitor process only after the initial response snapshot is complete.
	// The lock is released first: the monitor publishes state immediately, and
	// publishState re-takes sm.mutex as a reader (Go's RWMutex is not
	// reentrant).
	go sm.monitorStreamWithReconnect(streamProcess, hlsDir)
	return &info, nil
}

// RestoreStreams loads saved streams without delaying HTTP server startup.
func (sm *Manager) RestoreStreams() {
	go func() {
		configs, err := sm.logger.ListStreamConfigs()
		if err != nil {
			sm.logger.LogError("", "restore", fmt.Sprintf("Failed to load saved streams: %v", err))
			return
		}
		for _, config := range configs {
			provider := models.ProviderKind(config.Provider).OrDefault()
			if _, err := sm.startStreamWithProvider(config.ProfileToken, config.RTSPURL, provider, false); err != nil {
				sm.logger.LogError("", "restore", fmt.Sprintf("Failed to restore profile %s: %v", config.ProfileToken, err))
			}
		}
	}()
}

func (sm *Manager) stateEntry(info models.StreamInfo, detail string) models.LogEntry {
	info.RtspURL = ""
	info.Detail = redactSensitiveText(detail)
	return models.LogEntry{Type: "state", StreamID: info.ID, Message: info.Detail, Time: time.Now().Format(time.RFC3339), State: &info}
}

func (sm *Manager) publishState(process *Process, status, detail string) {
	process.mutex.Lock()
	process.Info.Status = status
	process.Info.Detail = redactSensitiveText(detail)
	info := process.Info
	process.mutex.Unlock()
	sm.broadcastLog(sm.stateEntry(info, detail))
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
		return 0
	}
	return current + 1
}

// hlsOutputUnhealthy reports a stalled stream.
//
// IMPORTANT: this camera's HLS muxer does not create stream.m3u8 until the first
// segment is closed, which can take ~30-90s with -c:v copy. A missing playlist
// is therefore NORMAL early in a run. The previous implementation treated a
// missing playlist as unhealthy once the timeout elapsed, so the watchdog killed
// ffmpeg at exactly hlsStallTimeout, the restart removed the playlist again, and
// the loop repeated forever.
//
// A stall is now: no playlist progress AND no segment file growth. A missing
// playlist only counts once the run has far exceeded any plausible
// first-segment time, so a slow-but-working startup is never killed.
//
// Deprecated in favour of hlsRunUnhealthy, which also watches segment files.
func hlsOutputUnhealthy(playlist string, now, startedAt time.Time, timeout time.Duration) bool {
	info, err := os.Stat(playlist)
	if err == nil {
		return now.Sub(info.ModTime()) > timeout
	}
	if !os.IsNotExist(err) {
		return false
	}
	// No playlist yet. Only flag this well beyond the expected first-segment
	// delay, so slow HLS startup is not mistaken for a stall.
	return now.Sub(startedAt) > timeout+playlistFirstSegmentGrace
}

// hlsRunUnhealthy is the primary stall check. Progress means "a new segment
// file appeared", not a file modification time: with -hls_flags delete_segments
// and a camera whose segments are named stream<epoch>.ts, the newest segment's
// NAME advances exactly once per completed segment. Modification times update
// mid-write and produce false stalls.
func hlsRunUnhealthy(hlsDir string, lastProgress *time.Time, lastName *string, now, startedAt time.Time, timeout time.Duration) bool {
	name := newestSegmentName(hlsDir)

	// A brand-new segment name is unambiguous progress.
	if name != "" && name != *lastName {
		*lastName = name
		*lastProgress = now
		return false
	}

	// Fall back to playlist movement for the case where segments are recycled.
	if info, err := os.Stat(filepath.Join(hlsDir, "stream.m3u8")); err == nil {
		if info.ModTime().After(*lastProgress) {
			*lastProgress = now
			return false
		}
	}

	if name == "" {
		// Nothing produced at all yet: allow a generous startup window, since
		// this camera can take over a minute to close its first segment.
		return now.Sub(startedAt) > timeout+playlistFirstSegmentGrace
	}
	if lastProgress.IsZero() {
		*lastProgress = now
		return false
	}
	return now.Sub(*lastProgress) > timeout
}

// hlsOutputStale reports whether an existing playlist has stopped advancing.
// Preserved for tests and callers that only have the playlist path.
func hlsOutputStale(playlist string, now time.Time, timeout time.Duration) bool {
	return hlsOutputUnhealthy(playlist, now, now, timeout)
}

// newestSegmentName returns the lexically greatest .ts name, which for this
// camera's stream<epoch>.ts naming is also the most recent segment.
func newestSegmentName(hlsDir string) string {
	entries, err := os.ReadDir(hlsDir)
	if err != nil {
		return ""
	}
	newest := ""
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".ts") {
			continue
		}
		if e.Name() > newest {
			newest = e.Name()
		}
	}
	return newest
}

// newestSegmentModTime returns the newest modification time among .ts files.
func newestSegmentModTime(hlsDir string) time.Time {
	entries, err := os.ReadDir(hlsDir)
	if err != nil {
		return time.Time{}
	}
	var newest time.Time
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".ts") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if mt := info.ModTime(); mt.After(newest) {
			newest = mt
		}
	}
	return newest
}

func tcpReachable(address string, timeout time.Duration) bool {
	connection, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

func diagnoseReachability(rtspURL, onvifAddress string, timeout time.Duration) string {
	parsed, err := url.Parse(rtspURL)
	if err != nil || parsed.Hostname() == "" {
		return "camera address invalid; unable to run network diagnosis"
	}
	rtspAddress := parsed.Host
	if parsed.Port() == "" {
		rtspAddress = net.JoinHostPort(parsed.Hostname(), "554")
	}
	rtspReachable := tcpReachable(rtspAddress, timeout)
	onvifReachable := onvifAddress != "" && tcpReachable(onvifAddress, timeout)
	hostState := "camera host unreachable"
	if rtspReachable || onvifReachable {
		hostState = "camera host reachable"
	}
	rtspState := "RTSP port unreachable"
	if rtspReachable {
		rtspState = "RTSP port reachable"
	}
	onvifState := "ONVIF port not configured"
	if onvifAddress != "" {
		onvifState = "ONVIF port unreachable"
		if onvifReachable {
			onvifState = "ONVIF port reachable"
		}
	}
	return fmt.Sprintf("%s; %s; %s", hostState, rtspState, onvifState)
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
		"-y", // Overwrite output files
		// +genpts generates missing timestamps; +igndts discards the camera's
		// own DTS. This camera emits duplicate/backwards DTS ("non monotonically
		// increasing dts to muxer"), which corrupts HLS segment timing.
		"-fflags", "+genpts+igndts",
		"-rtsp_transport", "tcp", // Use TCP for RTSP (more reliable)
		"-rtsp_flags", "prefer_tcp", // Prefer TCP
		// RTSP demuxer -timeout is an I/O timeout in microseconds; it bounds both
		// the connection and reads on an established session. (ffmpeg has no
		// -rw_timeout CLI option - that name exists only at the AVIO level.)
		"-timeout", "5000000", // 5s socket I/O timeout
		"-i", rtspURL,
		"-c:v", "copy", // Copy video codec (no transcoding)
		"-c:a", "aac", // Audio codec
		"-avoid_negative_ts", "make_zero", // Handle negative timestamps
		"-max_interleave_delta", "0", // Do not buffer to re-order; keep latency low
		"-hls_time", "2", // 2 second segments
		"-hls_list_size", "5", // Keep 5 segments in playlist
		"-hls_start_number_source", "epoch", // Keep sequence monotonic across reconnects
		"-hls_flags", "delete_segments+independent_segments", // Delete old segments
		"-hls_segment_type", "mpegts", // Use MPEG-TS segments
		"-f", "hls", // Output format
		filepath.Join(hlsDir, "stream.m3u8"),
	}

	cmd := exec.Command(ffmpegExecutable(sm.ffmpegBin), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	return cmd
}

// ffmpegExecutable resolves the encoder binary. Empty means the PATH's ffmpeg,
// which is the only value any production caller produces.
func ffmpegExecutable(override string) string {
	if strings.TrimSpace(override) == "" {
		return "ffmpeg"
	}
	return override
}

// monitorStreamWithReconnect monitors a stream and handles reconnection
func (sm *Manager) monitorStreamWithReconnect(process *Process, hlsDir string) {
	// Capture the channels THIS run owns. A resumed stream is given fresh Done
	// and Exited channels, so a late-deferring previous run must close its own
	// and never whatever the field happens to point at later.
	process.mutex.RLock()
	done := process.Done
	exited := process.Exited
	process.mutex.RUnlock()

	defer close(exited)
	defer process.closed.Do(func() { close(done) })

	for {
		startedAt := time.Now()
		// Remove stale metadata from a prior attempt so the new process gets its
		// complete startup grace period before health evaluation.
		_ = os.Remove(filepath.Join(hlsDir, "stream.m3u8"))
		cmd, err := sm.startFFmpegProcess(process, hlsDir)
		if err == nil {
			watchDone := make(chan struct{})
			go sm.watchHLSOutput(process, cmd, hlsDir, startedAt, watchDone)
			err = cmd.Wait()
			close(watchDone)
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
		if failures < 1 {
			failures = 1
			process.reconnectCount = failures
		}
		if failures >= maxReconnectAttempts {
			process.shouldReconnect = false
			process.Info.Status = "failed"
			process.mutex.Unlock()
			sm.publishState(process, "failed", "maximum reconnection attempts reached")
			sm.logger.LogError(process.Info.ID, "system", "Maximum reconnection attempts reached; stream stopped")
			return
		}
		delay := reconnectBackoff(failures)
		process.Info.Status = "reconnecting"
		process.Info.ReconnectCount = failures
		process.Info.ReconnectDelay = delay.String()
		rtspURL := process.Info.RtspURL
		process.mutex.Unlock()
		onvifAddress := ""
		if parsed, err := url.Parse(rtspURL); err == nil && parsed.Hostname() != "" {
			onvifAddress = net.JoinHostPort(parsed.Hostname(), "8000")
		}
		diagnosis := diagnoseReachability(rtspURL, onvifAddress, 2*time.Second)

		// A reachable camera is not necessarily a camera that will serve media.
		// Probe the RTSP session itself so an exhausted session table (the
		// ~1h "connected but no frames" stall) is identified instead of being
		// reported as a healthy host.
		probe, probeDetail := probeSessionState(rtspURL, sessionProbeTimeout, sessionProbeCollect)
		if probe.SessionTableFull() {
			// Retrying quickly cannot clear this; the camera reaps orphaned
			// sessions on its own schedule. Hold off and keep the stream
			// marked as reconnecting rather than burning reconnect attempts.
			process.mutex.Lock()
			process.Info.Status = "reconnecting"
			process.Info.ReconnectDelay = sessionTableBackoff.String()
			process.Info.ReconnectCount = failures
			process.mutex.Unlock()
			sm.publishState(process, "reconnecting",
				fmt.Sprintf("RTSP session table full; retrying in %s (%s)",
					sessionTableBackoff, probeDetail))
			sm.logger.LogWarn(process.Info.ID, "system",
				fmt.Sprintf("RTSP session table full (status %d); camera allows 2 concurrent sessions. "+
					"Backing off %s before retry. %s",
					rtspStatusSessionNotFound, sessionTableBackoff, probeDetail))
			timer := time.NewTimer(sessionTableBackoff)
			select {
			case <-timer.C:
			case <-done:
				timer.Stop()
				return
			}
			// Do not increment the failure count: this is a camera-side
			// resource limit, not a stream that keeps failing to start.
			process.mutex.Lock()
			process.reconnectCount = 0
			process.mutex.Unlock()
			continue
		} else if probe.Err == nil {
			diagnosis = fmt.Sprintf("%s; %s", diagnosis, probeDetail)
		}

		sm.publishState(process, "reconnecting", fmt.Sprintf("attempt %d in %s; %s", failures, delay, diagnosis))

		sm.logger.LogWarn(process.Info.ID, "system", fmt.Sprintf("Reconnection attempt %d/%d in %s", failures, maxReconnectAttempts, delay))
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-done:
			// done is the channel THIS run owns. A resume replaces the process's
			// Done/Exited with fresh ones, so waiting on the field would let an
			// old, superseded monitor wake up after the resume and spawn a
			// SECOND ffmpeg for the same stream.
			timer.Stop()
			return
		}
	}
}

// watchHLSOutput restarts a live FFmpeg process when its playlist stops
// advancing, preventing clients from replaying the final cached segments.
func (sm *Manager) watchHLSOutput(process *Process, cmd *exec.Cmd, hlsDir string, startedAt time.Time, done <-chan struct{}) {
	playlist := filepath.Join(hlsDir, "stream.m3u8")
	ticker := time.NewTicker(hlsHealthInterval)
	defer ticker.Stop()
	// Track progress across playlist and segment files, since this camera does
	// not create the playlist until its first segment closes.
	var lastProgress time.Time
	var lastName string
	for {
		select {
		case now := <-ticker.C:
			if info, err := os.Stat(playlist); err == nil {
				advanced := info.ModTime()
				process.mutex.Lock()
				if process.Info.LastHLSAdvance == nil || advanced.After(*process.Info.LastHLSAdvance) {
					process.Info.LastHLSAdvance = &advanced
				}
				process.mutex.Unlock()
			}
			if !hlsRunUnhealthy(hlsDir, &lastProgress, &lastName, now, startedAt, hlsStallTimeout) {
				continue
			}
			sm.publishState(process, "stalled", fmt.Sprintf("HLS output has not advanced for %s", hlsStallTimeout))
			sm.logger.LogWarn(process.Info.ID, "system", fmt.Sprintf("HLS output has not advanced for %s; restarting FFmpeg", hlsStallTimeout))
			if cmd.Process != nil {
				if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
					_ = syscall.Kill(-pgid, syscall.SIGTERM)
				} else {
					_ = cmd.Process.Signal(syscall.SIGTERM)
				}
			}
			return
		case <-done:
			return
		case <-process.Done:
			return
		}
	}
}

// ValidateCameraForStream binds credentialed ONVIF actions to the selected
// stream's profile and RTSP host without persisting ONVIF credentials.
func (sm *Manager) ValidateCameraForStream(streamID, cameraIP, profileToken string) error {
	sm.mutex.RLock()
	process, ok := sm.streams[streamID]
	sm.mutex.RUnlock()
	if !ok {
		return fmt.Errorf("stream not found")
	}
	process.mutex.RLock()
	rtspURL := process.Info.RtspURL
	activeProfile := process.Info.ProfileToken
	process.mutex.RUnlock()
	parsed, err := url.Parse(rtspURL)
	if err != nil || parsed.Hostname() == "" || parsed.Hostname() != cameraIP || activeProfile != profileToken {
		return fmt.Errorf("camera does not match stream")
	}
	return nil
}

// DiagnoseStream probes the camera RTSP and ONVIF service ports and publishes
// the sanitized result through the existing state SSE channel.
func (sm *Manager) DiagnoseStream(streamID string) (string, error) {
	sm.mutex.RLock()
	process, ok := sm.streams[streamID]
	sm.mutex.RUnlock()
	if !ok {
		return "", fmt.Errorf("stream not found")
	}
	process.mutex.RLock()
	rtspURL := process.Info.RtspURL
	status := process.Info.Status
	process.mutex.RUnlock()
	onvifAddress := ""
	if parsed, err := url.Parse(rtspURL); err == nil && parsed.Hostname() != "" {
		onvifAddress = net.JoinHostPort(parsed.Hostname(), "8000")
	}
	detail := diagnoseReachability(rtspURL, onvifAddress, 2*time.Second)
	sm.publishState(process, status, detail)
	return detail, nil
}

// ReconnectStream terminates FFmpeg; its monitor performs a controlled retry.
func (sm *Manager) ReconnectStream(streamID string) error {
	sm.mutex.RLock()
	process, ok := sm.streams[streamID]
	sm.mutex.RUnlock()
	if !ok {
		return fmt.Errorf("stream not found")
	}
	process.mutex.RLock()
	cmd := process.Command
	shouldReconnect := process.shouldReconnect
	process.mutex.RUnlock()
	if !shouldReconnect || cmd == nil || cmd.Process == nil {
		return fmt.Errorf("stream is not reconnectable")
	}
	sm.publishState(process, "reconnecting", "manual reconnect requested")
	if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
		return syscall.Kill(-pgid, syscall.SIGTERM)
	}
	return cmd.Process.Signal(syscall.SIGTERM)
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
	process.Info.ReconnectDelay = ""
	sm.logger.LogInfo(process.Info.ID, "system", "FFmpeg process started successfully")
	go sm.publishState(process, "running", "FFmpeg is running")
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
	if strings.Contains(lowerLine, "input #") ||
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
	return sm.stopStream(streamID, true)
}

func (sm *Manager) stopStream(streamID string, removeConfig bool) error {
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
	profileToken := stream.Info.ProfileToken
	stream.mutex.Unlock()
	if removeConfig {
		if err := sm.logger.DeleteStreamConfig(profileToken); err != nil {
			sm.logger.LogError(streamID, "system", fmt.Sprintf("Failed to remove saved stream configuration: %v", err))
		}
	}
	sm.publishState(stream, "stopped", "stream stopped manually")

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

// SuspendStreamsForProvider stands down every stream of one provider without
// forgetting it, and reports how many were suspended.
//
// This is the stream manager's half of the M6 Tuya session-loss degradation: a
// Tuya stream whose cloud session is dead has no source, and the HLS watchdog
// would otherwise restart ffmpeg against it forever. Only the named provider is
// touched, so an ONVIF stream can never be stopped by a Tuya session expiring.
//
// A per-stream failure is collected and returned rather than aborting the sweep:
// leaving the remaining streams running would be worse than a partial failure.
func (sm *Manager) SuspendStreamsForProvider(provider models.ProviderKind, reason string) (int, error) {
	provider = provider.OrDefault()
	var ids []string
	sm.mutex.RLock()
	for id, process := range sm.streams {
		process.mutex.RLock()
		match := process.Info.Provider.OrDefault() == provider && !process.suspended
		process.mutex.RUnlock()
		if match {
			ids = append(ids, id)
		}
	}
	sm.mutex.RUnlock()

	suspended := 0
	var failures []string
	for _, id := range ids {
		if err := sm.SuspendStreamForSessionLoss(id, reason); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", id, err))
			continue
		}
		suspended++
	}
	if len(failures) > 0 {
		return suspended, fmt.Errorf("failed to suspend %d stream(s): %s", len(failures), strings.Join(failures, "; "))
	}
	return suspended, nil
}

// StopStreamsForProvider stops every running stream of one provider and reports
// how many it stopped. Unlike SuspendStreamsForProvider it removes them, so
// they are not resumable.
func (sm *Manager) StopStreamsForProvider(provider models.ProviderKind) (int, error) {
	provider = provider.OrDefault()
	type target struct{ id, rtspURL string }
	var targets []target
	sm.mutex.RLock()
	for id, process := range sm.streams {
		process.mutex.RLock()
		match := process.Info.Provider.OrDefault() == provider
		rtspURL := process.Info.RtspURL
		process.mutex.RUnlock()
		if match {
			targets = append(targets, target{id: id, rtspURL: rtspURL})
		}
	}
	sm.mutex.RUnlock()

	stopped := 0
	var failures []string
	for _, t := range targets {
		if err := sm.StopStream(t.id); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", t.id, err))
			continue
		}
		// The stop must be ASSERTED, not assumed: StopStream removes the stream
		// from the registry, and a leaked ffmpeg from a superseded monitor would
		// otherwise keep retrying a dead source invisibly. The URL was captured
		// before the stop because the registry entry is gone by now. A freshly
		// killed process needs a moment to leave /proc, hence the bounded wait.
		if n := waitForNoFFmpegReader(sm, t.rtspURL, 3*time.Second); n > 0 {
			failures = append(failures, fmt.Sprintf("%s: %d ffmpeg process(es) survived the stop", t.id, n))
			continue
		}
		stopped++
	}
	if len(failures) > 0 {
		return stopped, fmt.Errorf("failed to stop %d stream(s): %s", len(failures), strings.Join(failures, "; "))
	}
	return stopped, nil
}

// countFFmpegProcessesFor counts live ffmpeg processes reading the given RTSP URL
// whose process GROUP this manager owns. It exists so a stop can be ASSERTED
// rather than assumed: the whole point of the M6 degradation is that no ffmpeg is
// left retrying a dead source, and a leaked process from a superseded monitor
// would silently defeat it.
//
// Ownership is checked by process group, not by URL alone. An RTSP URL is only
// unique within one engine instance — two viewer processes (or two test runs) on
// the same host can legitimately hold the same loopback URL — so a URL-only scan
// would report a foreign process as a leak. Every ffmpeg this manager spawns is
// put in its own process group (Setpgid), which makes the pgid the honest owner.
func countFFmpegProcessesFor(rtspURL string, ownedPGIDs map[int]bool) int {
	if rtspURL == "" || len(ownedPGIDs) == 0 {
		return 0
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	n := 0
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name()[0] < '0' || entry.Name()[0] > '9' {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if pgid, err := syscall.Getpgid(pid); err != nil || !ownedPGIDs[pgid] {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		// The URL field is NUL-separated in /proc/<pid>/cmdline.
		if strings.Contains(string(raw), rtspURL) {
			n++
		}
	}
	return n
}

// ownedProcessGroups collects the process groups of the ffmpeg children this
// manager currently tracks. A stream whose ffmpeg has already exited contributes
// nothing, which is the correct reading: there is no process to leak.
func (sm *Manager) ownedProcessGroups(rtspURL string) map[int]bool {
	owned := map[int]bool{}
	sm.mutex.RLock()
	processes := make([]*Process, 0, len(sm.streams))
	for _, p := range sm.streams {
		processes = append(processes, p)
	}
	sm.mutex.RUnlock()
	for _, process := range processes {
		process.mutex.RLock()
		cmd := process.Command
		url := process.Info.RtspURL
		process.mutex.RUnlock()
		if rtspURL != "" && url != rtspURL {
			continue
		}
		if cmd != nil && cmd.Process != nil {
			if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
				owned[pgid] = true
			}
		}
	}
	return owned
}

// SuspendStreamForSessionLoss stands a stream down WITHOUT forgetting it.
//
// Unlike StopStream it leaves the stream in the registry and leaves its
// persisted stream_configs row alone, so:
//   - /api/stream/list still reports it, with status "needs_relogin", which is
//     how the card stays on screen and says why instead of silently vanishing;
//   - ResumeSuspended can restart exactly the same profile token with the RTSP
//     URL the engine hands back after a fresh login.
//
// This is what makes "one-click re-login resumes the same cameras" possible
// without the user re-picking anything.
func (sm *Manager) SuspendStreamForSessionLoss(streamID, reason string) error {
	sm.mutex.RLock()
	process, ok := sm.streams[streamID]
	sm.mutex.RUnlock()
	if !ok {
		return fmt.Errorf("stream not found")
	}
	process.mutex.Lock()
	process.shouldReconnect = false
	process.suspended = true
	process.suspendedReason = redactSensitiveText(reason)
	cmd := process.Command
	process.Info.Status = StatusNeedsRelogin
	process.Info.Detail = redactSensitiveText(reason)
	process.Info.Suspended = true
	process.Info.SuspendedReason = process.suspendedReason
	process.mutex.Unlock()

	sm.logger.LogWarn(streamID, "system", fmt.Sprintf("Suspending stream: %s", reason))
	sm.publishState(process, StatusNeedsRelogin, reason)

	// Capture the channels and URL THIS process owns before terminating.
	process.mutex.RLock()
	rtspURL := process.Info.RtspURL
	currentCmd := process.Command
	process.mutex.RUnlock()
	if currentCmd == nil {
		currentCmd = cmd
	}
	// The previous monitor's Done: awaiting it proves that loop has returned and
	// cannot spawn another ffmpeg afterwards.
	process.mutex.RLock()
	previousDone := process.Done
	process.mutex.RUnlock()

	// Terminate the process group, then wait for the monitor to confirm exit so
	// no ffmpeg can be left reading a dead source.
	if currentCmd != nil && currentCmd.Process != nil {
		if pgid, err := syscall.Getpgid(currentCmd.Process.Pid); err == nil {
			_ = syscall.Kill(-pgid, syscall.SIGTERM)
		} else {
			_ = currentCmd.Process.Signal(syscall.SIGTERM)
		}
	}
	grace := time.NewTimer(streamStopTimeout)
	select {
	case <-previousDone:
		grace.Stop()
	case <-grace.C:
		if currentCmd != nil && currentCmd.Process != nil {
			if pgid, err := syscall.Getpgid(currentCmd.Process.Pid); err == nil {
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			} else {
				_ = currentCmd.Process.Kill()
			}
		}
	}

	// ASSERT the bleed is really stopped. If an ffmpeg is still reading this
	// stream's URL, say so loudly instead of reporting a clean degradation:
	// leaving one alive is exactly the endless-retry failure M6 exists to end.
	// A just-SIGKILLed process can need a moment to disappear from /proc, so the
	// check retries briefly rather than crying wolf.
	if n := waitForNoFFmpegReader(sm, rtspURL, 3*time.Second); n > 0 {
		msg := fmt.Sprintf("stream suspended but %d ffmpeg process(es) are still reading %s", n, rtspURL)
		sm.logger.LogError(streamID, "system", msg)
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// waitForNoFFmpegReader waits briefly for every ffmpeg reading rtspURL to be
// gone, then reports how many are left (0 = all clear).
func waitForNoFFmpegReader(sm *Manager, rtspURL string, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for {
		n := countFFmpegProcessesFor(rtspURL, sm.ownedProcessGroups(rtspURL))
		if n == 0 || !time.Now().Before(deadline) {
			return n
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// SuspendedStreams returns the suspended streams of a provider, in profile-token
// order so a resume is deterministic.
func (sm *Manager) SuspendedStreams(provider models.ProviderKind) []models.StreamInfo {
	provider = provider.OrDefault()
	var out []models.StreamInfo
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	for _, process := range sm.streams {
		process.mutex.RLock()
		if process.suspended && process.Info.Provider.OrDefault() == provider {
			out = append(out, process.Info)
		}
		process.mutex.RUnlock()
	}
	return out
}

// ResumeSuspended restarts a suspended stream with a (possibly new) RTSP URL.
//
// It is the recovery half of SuspendStreamForSessionLoss. The process registry
// entry and the persisted config are reused, so the same card, the same profile
// token and the same provider survive; only the RTSP URL changes, because the
// engine allocates a fresh loopback endpoint after a re-login.
func (sm *Manager) ResumeSuspended(streamID, rtspURL string, provider models.ProviderKind) (*models.StreamInfo, error) {
	sm.mutex.RLock()
	process, ok := sm.streams[streamID]
	sm.mutex.RUnlock()
	if !ok {
		return nil, fmt.Errorf("stream not found")
	}
	// The write lock is held only for the registry mutation; publishState
	// broadcasts to SSE clients, which re-takes sm.mutex as a reader, so it must
	// run after the unlock (Go's RWMutex is not reentrant).
	info, err := sm.resumeSuspendedProcess(process, rtspURL, provider)
	if err != nil {
		return nil, err
	}
	sm.publishState(process, "starting", "stream resumed after a successful Tuya re-login")
	return info, nil
}

// resumeSuspendedProcess performs the resume. It takes only the per-process lock
// (the process pointer is already resolved by the caller), so callers must NOT
// hold sm.mutex: publishState re-takes it as a reader and Go's RWMutex is not
// reentrant.
func (sm *Manager) resumeSuspendedProcess(process *Process, rtspURL string, provider models.ProviderKind) (*models.StreamInfo, error) {
	if process == nil {
		return nil, fmt.Errorf("stream not found")
	}
	process.mutex.Lock()
	if !process.suspended {
		streamID := process.Info.ID
		process.mutex.Unlock()
		return nil, fmt.Errorf("stream %s is not suspended", streamID)
	}
	if rtspURL == "" {
		process.mutex.Unlock()
		return nil, fmt.Errorf("an RTSP URL is required to resume a stream")
	}
	streamID := process.Info.ID
	process.Info.RtspURL = rtspURL
	process.Info.Provider = provider.OrDefault()
	process.reconnectCount = 0
	process.suspended = false
	process.suspendedReason = ""
	process.shouldReconnect = true
	process.Info.Status = "starting"
	process.Info.Suspended = false
	process.Info.SuspendedReason = ""
	// Done and Exited are single-use: the previous monitor closed them on its
	// way out. A resumed stream needs FRESH ones, or the new monitor would
	// close an already-closed channel and the stop path would return instantly.
	process.Done = make(chan bool)
	process.Exited = make(chan struct{})
	process.closed = sync.Once{}
	process.Info.ReconnectDelay = ""
	profileToken := process.Info.ProfileToken
	info := process.Info
	process.mutex.Unlock()

	if err := sm.logger.UpsertStreamConfig(profileToken, rtspURL, string(provider.OrDefault())); err != nil {
		return nil, fmt.Errorf("persist stream configuration: %w", err)
	}
	// A fresh monitor owns the ffmpeg lifecycle from here. The previous one has
	// already returned (the suspend path waited for Exited).
	go sm.monitorStreamWithReconnect(process, filepath.Join(sm.hlsBaseDir, streamID))
	return &info, nil
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
	for _, process := range sm.streams {
		process.mutex.RLock()
		info := process.Info
		process.mutex.RUnlock()
		select {
		case client.Channel <- sm.stateEntry(info, info.Detail):
		default:
		}
	}
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
		if err := sm.stopStream(id, false); err != nil {
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
