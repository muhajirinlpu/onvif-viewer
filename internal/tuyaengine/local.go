package tuyaengine

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"dengan.dev/camera-streamer/internal/tuyartsp"
)

// ---------------------------------------------------------------------------
// In-process engine (default)
//
// The default backend is entirely in-repo: internal/tuyartsp serves the Tuya
// WebRTC source over a loopback RTSP listener that the viewer's existing ffmpeg
// pipeline opens exactly like an ONVIF stream. No child process is spawned and
// no external executable is required.
//
// The supervised external-binary backend is still present for operators who
// explicitly set Config.BinPath (or TUYA_ENGINE_BIN / TUYA_ENGINE_MODE=external);
// see engine.go. It is never used unless asked for.
// ---------------------------------------------------------------------------

// Mode values for Config.Mode.
const (
	// ModeInProcess runs the Tuya source inside the viewer process. This is the
	// default and requires no external executable.
	ModeInProcess = "inprocess"
	// ModeExternal supervises an external Tuya->RTSP engine binary. Opt-in only.
	ModeExternal = "external"
)

// localServer is the in-process RTSP server type. It is an alias so the engine
// can swap in a test double without a second interface.
type localServer = tuyartsp.Server

// newLocalServer constructs the in-process RTSP server.
func newLocalServer() *localServer { return tuyartsp.New() }

// usesExternalEngine reports whether the external-binary backend was requested.
//
// Precedence: an explicit Mode wins; otherwise an explicit BinPath means the
// operator named a binary and therefore wants the external backend. Everything
// else is in-process.
func (e *Engine) usesExternalEngine() bool {
	switch e.cfg.Mode {
	case ModeExternal:
		return true
	case ModeInProcess:
		return false
	}
	return e.cfg.BinPath != ""
}
// ensureLocal starts the in-process RTSP server if it is not running yet. It is
// idempotent and safe for concurrent use.
func (e *Engine) ensureLocal() error {
	e.localOnce.Do(func() {
		e.localErr = e.startLocal()
	})
	return e.localErr
}

func (e *Engine) startLocal() error {
	port := e.cfg.RTSPPort
	// A port may already have been pinned by an earlier call to ensurePorts
	// (for example when the operator later forced external mode); reuse it so
	// the RTSP URL handed to ffmpeg never changes mid-flight.
	if port == 0 {
		e.mu.Lock()
		port = e.rtspPort
		e.mu.Unlock()
	}
	if port == 0 {
		allocated, err := ReserveFreePort()
		if err != nil {
			return err
		}
		port = allocated
	}

	address := net.JoinHostPort(e.cfg.RTSPHost, strconv.Itoa(port))
	server := newLocalServer()
	if err := server.Listen(address); err != nil {
		if e.cfg.RTSPPort == 0 {
			ReleaseFreePort(port)
		}
		return err
	}
	bound := server.Port()

	e.mu.Lock()
	e.local = server
	e.rtspPort = bound
	e.localRunning = true
	// Register every stream the registry already knows about, so a stream added
	// before the first EnsureRunning (or while the server was down) is served
	// without a second call.
	names := e.streamNamesLocked()
	sources := make(map[string]string, len(names))
	for _, name := range names {
		sources[name] = e.streams[name]
	}
	e.mu.Unlock()

	for name, source := range sources {
		if err := server.AddStream(name, source); err != nil {
			return fmt.Errorf("tuyaengine: register stream %s: %w", name, err)
		}
	}

	e.record(Event{Kind: EventReady, Detail: fmt.Sprintf("in-process rtsp=%s streams=%d", e.RTSPURL(), len(sources))})
	return nil
}

// addLocalStream registers a stream with the running in-process server.
func (e *Engine) addLocalStream(name, source string) error {
	if err := e.ensureLocal(); err != nil {
		return err
	}
	e.mu.Lock()
	server := e.local
	e.mu.Unlock()
	if server == nil {
		return fmt.Errorf("tuyaengine: in-process engine is not running")
	}
	return server.AddStream(name, source)
}

// removeLocalStream drops a stream from the running in-process server.
func (e *Engine) removeLocalStream(name string) {
	e.mu.Lock()
	server := e.local
	e.mu.Unlock()
	if server != nil {
		server.RemoveStream(name)
	}
}

// stopLocal closes the in-process RTSP server. It is idempotent.
func (e *Engine) stopLocal() {
	e.mu.Lock()
	server := e.local
	e.local = nil
	e.localRunning = false
	e.mu.Unlock()
	if server != nil {
		_ = server.Close()
	}
}

// waitLocalReady blocks until the in-process RTSP endpoint answers OPTIONS.
func (e *Engine) waitLocalReady(ctx context.Context, timeout time.Duration) error {
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
				return fmt.Errorf("tuyaengine: in-process engine not ready after %s: %s", timeout, last)
			}
			return fmt.Errorf("tuyaengine: in-process engine not ready after %s (rtsp endpoint %q)", timeout, e.RTSPURL())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(defaultPollInterval):
		}
	}
}
