// Package tuyaengine supervises a Tuya-cloud -> RTSP bridge engine as a child
// process of the viewer and exposes the resulting RTSP URL, so the existing
// internal/stream HLS pipeline can consume a Tuya camera exactly like an ONVIF
// camera.
//
// The engine is a long-lived process that can serve many streams: one instance
// is shared by every Tuya camera, never one process per camera.
package tuyaengine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Event kinds published through the event sink.
const (
	EventStarting      = "starting"
	EventReady         = "ready"
	EventReadyFailed   = "ready_failed"
	EventExited        = "exited"
	EventRestarting    = "restarting"
	EventStopped       = "stopped"
	EventMaxRestarts   = "max_restarts_reached"
	EventStreamAdded   = "stream_added"
	EventStreamRemoved = "stream_removed"
)

// stableRunThreshold mirrors the stream manager's convention: a child that ran
// at least this long is treated as healthy, and its restart attempt counter is
// reset so a rare crash does not inherit an escalated backoff.
const stableRunThreshold = 30 * time.Second

// waitErrUnknown marks "the child was reaped but its exit status was never
// collected", which happens when the readiness race wins and the supervisor is
// still holding the wait result.
var waitErrUnknown = errors.New("tuyaengine: exit status not collected")

// Event describes one supervision transition.
type Event struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`
	Attempt int       `json:"attempt,omitempty"`
	PID     int       `json:"pid,omitempty"`
	DelayMS int64     `json:"delayMs,omitempty"`
	Detail  string    `json:"detail,omitempty"`
}

func (e Event) String() string {
	parts := []string{e.Time.Format(time.RFC3339), e.Kind}
	if e.PID != 0 {
		parts = append(parts, "pid="+strconv.Itoa(e.PID))
	}
	if e.Attempt != 0 {
		parts = append(parts, "attempt="+strconv.Itoa(e.Attempt))
	}
	if e.DelayMS != 0 {
		parts = append(parts, "delay="+strconv.FormatInt(e.DelayMS, 10)+"ms")
	}
	if e.Detail != "" {
		parts = append(parts, e.Detail)
	}
	return strings.Join(parts, " ")
}

// Engine supervises one Tuya->RTSP bridge child process shared by all streams.
type Engine struct {
	cfg Config

	mu        sync.Mutex
	streams   map[string]string // engine stream name -> tuya:// source URL
	streamURL map[string]string // engine stream name -> RTSP URL served to ffmpeg
	byToken   map[string]string // profile token -> engine stream name
	cmd       *exec.Cmd
	apiPort   int
	rtspPort  int
	attempt   int
	restarts  int
	startedAt time.Time
	stopped   bool
	running   bool
	lastErr   string
	waiters   []chan struct{}
	events    []Event
	sink      func(Event)

	superviseOnce sync.Once
	startOnce     sync.Once
	wg            sync.WaitGroup
}

// New creates an Engine. It does not start anything; the child is spawned
// lazily by EnsureRunning/AddStream.
func New(cfg Config) *Engine {
	return &Engine{
		cfg:       cfg.withDefaults(),
		streams:   map[string]string{},
		streamURL: map[string]string{},
		byToken:   map[string]string{},
	}
}

// Config returns the effective (defaulted) configuration.
func (e *Engine) Config() Config { return e.cfg }

// SetEventSink installs a callback invoked for every supervision event. It must
// not block: it runs on the supervisor goroutine.
func (e *Engine) SetEventSink(sink func(Event)) {
	e.mu.Lock()
	e.sink = sink
	e.mu.Unlock()
}

// Events returns a copy of the events recorded so far.
func (e *Engine) Events() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Event, len(e.events))
	copy(out, e.events)
	return out
}

func (e *Engine) record(event Event) {
	event.Time = time.Now()
	e.mu.Lock()
	e.events = append(e.events, event)
	if len(e.events) > 256 {
		e.events = e.events[len(e.events)-256:]
	}
	sink := e.sink
	e.mu.Unlock()
	log.Printf("tuyaengine: %s", event.String())
	if sink != nil {
		sink(event)
	}
}

// LogPath returns the file receiving the engine's own stdout/stderr.
func (e *Engine) LogPath() string { return filepath.Join(e.cfg.ConfigDir, defaultConfigName+".log") }

// ConfigPath returns the generated engine configuration file path.
func (e *Engine) ConfigPath() string {
	return filepath.Join(e.cfg.ConfigDir, defaultConfigName+".yaml")
}

// ---------------------------------------------------------------------------
// Stream registry
// ---------------------------------------------------------------------------

// AddStream registers a Tuya device with the engine and returns the RTSP URL to
// hand to stream.Manager.StartStream, plus the namespaced profile token.
//
// If the engine is already running the stream is registered live through the
// engine's own HTTP API, so no restart is needed; either way the generated
// configuration always contains the full set, so a respawn converges.
func (e *Engine) AddStream(spec DeviceSpec) (rtspURL, profileToken string, err error) {
	normalized, err := spec.Normalize(DeviceSpec{SessionFile: e.cfg.SessionFile, Host: e.cfg.TuyaHost})
	if err != nil {
		return "", "", err
	}
	name, err := normalized.StreamName()
	if err != nil {
		return "", "", err
	}
	token, err := normalized.ProfileToken()
	if err != nil {
		return "", "", err
	}
	source, err := normalized.EngineURL()
	if err != nil {
		return "", "", err
	}

	e.mu.Lock()
	e.streams[name] = source
	e.byToken[token] = name
	running := e.running && e.cmd != nil && e.cmd.Process != nil
	rtspPort := e.rtspPort
	e.mu.Unlock()

	e.record(Event{Kind: EventStreamAdded, Detail: fmt.Sprintf("stream=%s token=%s", name, token)})

	if running {
		if err := e.putStream(context.Background(), name, source); err != nil {
			// Not fatal: the stream is in the registry and will exist after the
			// next respawn. Report it so the caller can surface the degradation.
			e.lastError(err)
		}
	}
	if err := e.EnsureRunning(); err != nil {
		return "", "", err
	}

	e.mu.Lock()
	port := e.rtspPort
	if port == 0 {
		port = rtspPort
	}
	e.mu.Unlock()

	rtspURL = RTSPURL(e.cfg.RTSPHost, port, name)
	e.mu.Lock()
	e.streamURL[name] = rtspURL
	e.mu.Unlock()
	return rtspURL, token, nil
}

// RemoveStream drops a Tuya device from the engine registry (and from the live
// engine when it is running). It does not touch the viewer's FFmpeg process.
func (e *Engine) RemoveStream(deviceID string) error {
	token, err := ProfileTokenFor(deviceID)
	if err != nil {
		return err
	}
	e.mu.Lock()
	name, ok := e.byToken[token]
	if ok {
		delete(e.byToken, token)
		delete(e.streams, name)
		delete(e.streamURL, name)
	}
	running := e.running && e.cmd != nil
	e.mu.Unlock()
	if !ok {
		return fmt.Errorf("tuyaengine: device %s is not registered", deviceID)
	}
	e.record(Event{Kind: EventStreamRemoved, Detail: "stream=" + name})
	if running {
		if err := e.deleteStream(context.Background(), name); err != nil {
			e.lastError(err)
		}
	}
	return nil
}

// Resolve returns the RTSP URL for an already registered device id.
func (e *Engine) Resolve(deviceID string) (string, error) {
	token, err := ProfileTokenFor(deviceID)
	if err != nil {
		return "", err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	name, ok := e.byToken[token]
	if !ok {
		return "", fmt.Errorf("tuyaengine: device %s is not registered", deviceID)
	}
	if url := e.streamURL[name]; url != "" {
		return url, nil
	}
	if e.rtspPort == 0 {
		return "", fmt.Errorf("tuyaengine: engine is not running")
	}
	return RTSPURL(e.cfg.RTSPHost, e.rtspPort, name), nil
}

// ResolveStream returns the RTSP URL for a namespaced profile token.
func (e *Engine) ResolveStream(profileToken string) (string, error) {
	if !IsTuyaProfileToken(profileToken) {
		return "", fmt.Errorf("tuyaengine: %q is not a Tuya profile token", profileToken)
	}
	return e.Resolve(strings.TrimPrefix(profileToken, ProfileTokenPrefix))
}

// Streams returns the registered engine stream names, sorted.
func (e *Engine) Streams() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.streamNamesLocked()
}

func (e *Engine) streamNamesLocked() []string {
	names := make([]string, 0, len(e.streams))
	for name := range e.streams {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ---------------------------------------------------------------------------
// Supervision
// ---------------------------------------------------------------------------

// Running reports whether a supervised child currently exists.
func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running && e.cmd != nil && e.cmd.Process != nil
}

// PID returns the current child pid, or 0 when not running.
func (e *Engine) PID() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cmd == nil || e.cmd.Process == nil {
		return 0
	}
	return e.cmd.Process.Pid
}

// Restarts returns how many times the child has been respawned.
func (e *Engine) Restarts() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.restarts
}

// APIPort reports the engine HTTP API port of the current child (0 when stopped).
func (e *Engine) APIPort() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.apiPort
}

// RTSPPort reports the engine RTSP port of the current child (0 when stopped).
func (e *Engine) RTSPPort() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rtspPort
}

// EnsureRunning starts the supervisor and waits until the RTSP endpoint answers.
// It is idempotent and safe for concurrent use.
//
// The engine binary is resolved up front so a missing or non-executable binary is
// reported to the caller immediately instead of only being retried in the
// background. The supervisor is still started, so the engine recovers on its own
// once the binary appears.
func (e *Engine) EnsureRunning() error {
	e.startOnce.Do(func() {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.supervise(context.Background())
		}()
	})
	if _, err := FindEngineBinary(e.cfg.BinPath); err != nil {
		e.lastError(err)
		return err
	}
	if err := e.cfg.Validate(); err != nil {
		e.lastError(err)
		return err
	}
	return e.WaitReady(context.Background(), e.cfg.ReadyTimeout)
}

// WaitReady blocks until the engine's RTSP endpoint answers OPTIONS, or until
// the timeout elapses.
//
// The endpoint is unknown until the first spawn has allocated a port, so an empty
// URL is a "not yet" condition rather than a failure: concurrent callers all wait
// for the same first spawn.
func (e *Engine) WaitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if url := e.RTSPURL(); url != "" && e.rtspReachableCtx(ctx, url) {
			return nil
		}
		if time.Now().After(deadline) {
			if last := e.LastError(); last != "" {
				return fmt.Errorf("tuyaengine: engine not ready after %s: %s", timeout, last)
			}
			return fmt.Errorf("tuyaengine: engine not ready after %s (rtsp endpoint %q)", timeout, e.RTSPURL())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(defaultPollInterval):
		}
	}
}

// RTSPURL returns the base RTSP URL of the current child, e.g.
// rtsp://127.0.0.1:34567, or "" before the first spawn.
func (e *Engine) RTSPURL() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.rtspPort == 0 {
		return ""
	}
	return fmt.Sprintf("rtsp://%s:%d", e.cfg.RTSPHost, e.rtspPort)
}

func (e *Engine) rtspReachableCtx(ctx context.Context, url string) bool {
	probeCtx, cancel := context.WithTimeout(ctx, defaultProbeTimeout)
	defer cancel()
	listener, err := (&net.Dialer{Timeout: defaultProbeTimeout}).DialContext(probeCtx, "tcp", dialAddress(url))
	if err != nil {
		return false
	}
	_ = listener.Close()
	return rtspReachable(probeCtx, url, defaultProbeTimeout)
}

func dialAddress(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	port := parsed.Port()
	if port == "" {
		port = "554"
	}
	return net.JoinHostPort(parsed.Hostname(), port)
}

// Stop terminates the supervised child and prevents further restarts. It is
// idempotent and safe to call more than once.
func (e *Engine) Stop() {
	e.mu.Lock()
	if e.stopped {
		e.mu.Unlock()
		return
	}
	e.stopped = true
	cmd := e.cmd
	e.mu.Unlock()

	if cmd != nil && cmd.Process != nil {
		e.terminate(cmd)
	}
	e.wg.Wait()

	e.mu.Lock()
	e.running = false
	e.stopped = true
	e.mu.Unlock()
	e.releasePorts()
	e.record(Event{Kind: EventStopped})
}

// Wait blocks until the supervisor goroutine has exited.
func (e *Engine) Wait() { e.wg.Wait() }

// supervise owns the child lifecycle: spawn, wait, restart with bounded
// exponential backoff, until Stop is called.
func (e *Engine) supervise(ctx context.Context) {
	for {
		e.mu.Lock()
		if e.stopped {
			e.mu.Unlock()
			return
		}
		attempt := e.attempt
		streams := e.streamNamesLocked()
		e.mu.Unlock()

		if len(streams) == 0 {
			// Nothing to serve yet; re-check periodically instead of spawning an
			// engine with no streams.
			select {
			case <-ctx.Done():
				return
			case <-time.After(defaultPollInterval):
			}
			continue
		}

		if attempt > 0 {
			delay := e.backoff(attempt)
			e.record(Event{Kind: EventRestarting, Attempt: attempt, DelayMS: delay.Milliseconds(),
				Detail: fmt.Sprintf("respawning engine in %s", delay)})
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}

		waitErr := waitErrUnknown
		startedAt := time.Now()
		cmd, err := e.spawn()
		if err != nil {
			e.mu.Lock()
			// Only a spawn that never produced a child counts as a failed attempt.
			e.attempt++
			attempts := e.attempt
			maxRestarts := e.cfg.MaxRestarts
			e.mu.Unlock()
			e.record(Event{Kind: EventStarting, Attempt: attempts, Detail: "spawn failed: " + err.Error()})
			e.lastError(err)
			if maxRestarts > 0 && attempts > maxRestarts {
				e.record(Event{Kind: EventMaxRestarts, Attempt: attempts, Detail: err.Error()})
				return
			}
			continue
		}

		e.mu.Lock()
		e.cmd = cmd
		e.running = true
		e.lastErr = ""
		e.mu.Unlock()
		e.record(Event{Kind: EventStarting, PID: cmd.Process.Pid, Attempt: attempt,
			Detail: fmt.Sprintf("api=%d rtsp=%d streams=%s", e.apiPortOf(), e.rtspPortOf(), strings.Join(streams, ","))})

		// Readiness and process exit are raced on purpose: a child that dies while
		// its listener is still coming up must be noticed immediately, not after
		// ReadyTimeout. Waiting for the port first would also mean cmd.Wait is
		// never called while the child is dead, leaving a zombie and a stale
		// e.Running() for the whole timeout.
		waitCh := make(chan error, 1)
		go func() { waitCh <- cmd.Wait() }()
		readyCtx, cancelReady := context.WithCancel(ctx)
		readyCh := make(chan error, 1)
		go func() { readyCh <- e.waitPortReady(readyCtx) }()

		select {
		case waitErr = <-waitCh:
			cancelReady()
			e.record(Event{Kind: EventReadyFailed, PID: cmd.Process.Pid,
				Detail: fmt.Sprintf("engine exited before its RTSP listener became ready: %v", waitErr)})
		case readyErr := <-readyCh:
			cancelReady()
			if readyErr != nil {
				e.lastError(readyErr)
				e.record(Event{Kind: EventReadyFailed, PID: cmd.Process.Pid, Detail: readyErr.Error()})
			} else {
				e.record(Event{Kind: EventReady, PID: cmd.Process.Pid, Detail: fmt.Sprintf("rtsp=%s", e.RTSPURL())})
			}
			waitErr = <-waitCh
		}
		runDuration := time.Since(startedAt)

		e.mu.Lock()
		e.cmd = nil
		e.running = false
		stopping := e.stopped
		if runDuration >= stableRunThreshold {
			e.attempt = 0
		} else {
			e.attempt++
		}
		attempts := e.attempt
		maxRestarts := e.cfg.MaxRestarts
		e.mu.Unlock()

		detail := fmt.Sprintf("engine exited after %s", runDuration.Round(time.Millisecond))
		if waitErr != nil && waitErr != waitErrUnknown {
			detail += ": " + waitErr.Error()
		} else {
			detail += " (exit status 0)"
		}
		e.record(Event{Kind: EventExited, PID: cmd.Process.Pid, Detail: detail})

		if stopping {
			return
		}
		if maxRestarts > 0 && attempts > maxRestarts {
			e.record(Event{Kind: EventMaxRestarts, Attempt: attempts, Detail: detail})
			return
		}
	}
}

// spawn renders the configuration, allocates ports, and starts the child in its
// own process group so a graceful stop can terminate its whole tree.
func (e *Engine) spawn() (*exec.Cmd, error) {
	binary, err := FindEngineBinary(e.cfg.BinPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(e.cfg.ConfigDir, 0o700); err != nil {
		return nil, fmt.Errorf("tuyaengine: config dir: %w", err)
	}

	apiPort, rtspPort, err := e.ensurePorts()
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	rendered, renderErr := e.renderEngineConfig(apiPort, rtspPort)
	e.mu.Unlock()
	// Fatal on failure: continuing past this point would have the supervisor spin
	// on a missing binary with no streams ever becoming available.
	if renderErr != nil {
		return nil, renderErr
	}

	// 0600: the generated config embeds the absolute path of the read-only Tuya
	// session file. It must never contain credentials, and it must not be
	// world-readable.
	if err := os.WriteFile(e.ConfigPath(), []byte(rendered), 0o600); err != nil {
		return nil, fmt.Errorf("tuyaengine: write config: %w", err)
	}
	logFile, err := os.OpenFile(e.LogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("tuyaengine: open engine log: %w", err)
	}

	cmd := exec.Command(binary, "-c", e.ConfigPath())
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("tuyaengine: start engine: %w", err)
	}
	// The child holds its own descriptor; the parent copy can be closed so the
	// log file is not leaked across restarts.
	_ = logFile.Close()

	e.mu.Lock()
	e.startedAt = time.Now()
	e.restarts++
	e.mu.Unlock()
	return cmd, nil
}

// ensurePorts returns the ports this engine will use, allocating a free pair once
// and then reusing it for every spawn.
//
// Pinning matters for correctness, not tidiness: the RTSP URL is handed to
// ffmpeg and persisted in stream_configs, so it must stay valid across restarts.
// A per-spawn free port would silently invalidate every running and persisted
// stream on the first crash.
func (e *Engine) ensurePorts() (int, int, error) {
	e.mu.Lock()
	if e.apiPort != 0 && e.rtspPort != 0 {
		apiPort, rtspPort := e.apiPort, e.rtspPort
		e.mu.Unlock()
		return apiPort, rtspPort, nil
	}
	e.mu.Unlock()

	apiPort := e.cfg.APIPort
	if apiPort == 0 {
		apiPort = e.reservePort()
	}
	rtspPort := e.cfg.RTSPPort
	if rtspPort == 0 {
		if rtspPort = e.reservePort(); rtspPort == 0 {
			return 0, 0, fmt.Errorf("tuyaengine: could not allocate a free RTSP port")
		}
	}
	if apiPort == 0 {
		return 0, 0, fmt.Errorf("tuyaengine: could not allocate a free API port")
	}
	if apiPort == rtspPort {
		if e.cfg.APIPort == 0 {
			ReleaseFreePort(apiPort)
		}
		apiPort = e.reservePort()
		if apiPort == 0 {
			return 0, 0, fmt.Errorf("tuyaengine: could not allocate distinct API/RTSP ports")
		}
	}

	e.mu.Lock()
	e.apiPort = apiPort
	e.rtspPort = rtspPort
	e.mu.Unlock()
	return apiPort, rtspPort, nil
}

// reservePort wraps ReserveFreePort, returning 0 on failure.
func (e *Engine) reservePort() int {
	port, err := ReserveFreePort()
	if err != nil {
		e.lastError(err)
		return 0
	}
	return port
}

// releasePorts returns the allocated ports to the pool. Called after Stop.
func (e *Engine) releasePorts() {
	e.mu.Lock()
	apiPort, rtspPort := e.apiPort, e.rtspPort
	e.mu.Unlock()
	if apiPort != 0 && e.cfg.APIPort == 0 {
		ReleaseFreePort(apiPort)
	}
	if rtspPort != 0 && e.cfg.RTSPPort == 0 {
		ReleaseFreePort(rtspPort)
	}
}

// apiPortOf / rtspPortOf are lock-safe accessors used while a spawn is running.
func (e *Engine) apiPortOf() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.apiPort
}

func (e *Engine) rtspPortOf() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rtspPort
}

// waitPortReady waits until the engine's RTSP listener accepts a connection.
//
// Connection attempts run in a fresh goroutine per poll: on a rapid crash loop the
// OS can leave a half-open attempt to a just-freed port blocking longer than the
// poll interval, and that must never stall the supervisor. The overall wait stays
// bounded by ReadyTimeout.
func (e *Engine) waitPortReady(ctx context.Context) error {
	address := net.JoinHostPort(e.cfg.RTSPHost, strconv.Itoa(e.rtspPortOf()))
	// Fail fast: the supervisor owns liveness, so readiness never needs to sit
	// through a multi-second OS connect timeout to conclude "not ready yet".
	dialTimeout := defaultPollInterval
	if dialTimeout > defaultProbeTimeout {
		dialTimeout = defaultProbeTimeout
	}
	dial := func() bool {
		result := make(chan bool, 1)
		go func() {
			conn, err := net.DialTimeout("tcp", address, dialTimeout)
			if err != nil {
				result <- false
				return
			}
			_ = conn.Close()
			result <- true
		}()
		select {
		case ok := <-result:
			return ok
		case <-time.After(dialTimeout + defaultPollInterval):
			return false
		}
	}

	deadline := time.Now().Add(e.cfg.ReadyTimeout)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		e.mu.Lock()
		stopped := e.stopped
		e.mu.Unlock()
		if stopped {
			return errors.New("tuyaengine: stopped while waiting for readiness")
		}
		if dial() {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("tuyaengine: RTSP listener %s not accepting after %s", address, e.cfg.ReadyTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(defaultPollInterval):
		}
	}
}

// backoff returns the capped exponential restart delay for the given attempt.
func (e *Engine) backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := e.cfg.BaseBackoff
	for i := 1; i < attempt; i++ {
		if delay >= e.cfg.MaxBackoff {
			return e.cfg.MaxBackoff
		}
		delay *= 2
	}
	if delay > e.cfg.MaxBackoff {
		delay = e.cfg.MaxBackoff
	}
	return delay
}

// terminate sends SIGTERM to the child's whole process group, escalating to
// SIGKILL after StopTimeout.
func (e *Engine) terminate(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err == nil {
		_ = syscall.Kill(-pgid, syscall.SIGTERM)
	} else {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
	deadline := time.Now().Add(e.cfg.StopTimeout)
	for time.Now().Before(deadline) {
		// e.Running() is owned by the supervisor, so this never races cmd.Wait
		// and never mistakes a reaped (and possibly reused) pid for a live child.
		if !e.Running() || !processAlive(cmd.Process.Pid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	} else {
		_ = cmd.Process.Kill()
	}
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

func (e *Engine) lastError(err error) {
	if err == nil {
		return
	}
	e.mu.Lock()
	e.lastErr = err.Error()
	e.mu.Unlock()
}

// LastError reports the most recent supervision error, for diagnostics.
func (e *Engine) LastError() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastErr
}

// ---------------------------------------------------------------------------
// Engine HTTP API (used to add/remove streams without a restart)
// ---------------------------------------------------------------------------

func (e *Engine) putStream(ctx context.Context, name, source string) error {
	port := e.apiPortOf()
	if port == 0 {
		return fmt.Errorf("tuyaengine: engine API not running")
	}
	endpoint := fmt.Sprintf("http://127.0.0.1:%d/api/streams?name=%s&src=%s",
		port, url.QueryEscape(name), url.QueryEscape(source))
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, nil)
	if err != nil {
		return err
	}
	return e.doAPIRequest(request, "register stream "+name)
}

func (e *Engine) deleteStream(ctx context.Context, name string) error {
	port := e.apiPortOf()
	if port == 0 {
		return fmt.Errorf("tuyaengine: engine API not running")
	}
	endpoint := fmt.Sprintf("http://127.0.0.1:%d/api/streams?src=%s", port, url.QueryEscape(name))
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	return e.doAPIRequest(request, "remove stream "+name)
}

func (e *Engine) doAPIRequest(request *http.Request, what string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("tuyaengine: %s: %w", what, err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		return fmt.Errorf("tuyaengine: %s: engine API returned %s", what, response.Status)
	}
	return nil
}
