package tuyaengine

import (
	"strings"
	"sync"
	"testing"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/models"
)

// --- M9: RegisterStream is the NARROW half of StartStream --------------------
//
// The start-up path needs to put a persisted camera back into the engine WITHOUT
// starting a stream. StartStream cannot be used for that: it would spawn a second
// ffmpeg for a camera that is about to be restored, and it would re-persist a
// stream_configs row that already exists.
//
// These tests pin the two halves of that contract against a REAL in-process
// engine (no camera, no cloud: registering a stream does not dial Tuya - only an
// RTSP DESCRIBE does).

// recordingStarter records every StartStream the bridge performs, so "did not
// start a stream" is an assertion rather than a promise.
type recordingStarter struct {
	mu    sync.Mutex
	calls []string
	info  *models.StreamInfo
}

func (r *recordingStarter) StartStream(profileToken, rtspURL string) (*models.StreamInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, profileToken+" "+rtspURL)
	if r.info != nil {
		return r.info, nil
	}
	return &models.StreamInfo{ProfileToken: profileToken, RtspURL: rtspURL}, nil
}

func (r *recordingStarter) started() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.calls))
	copy(out, r.calls)
	return out
}

func newRecordingBridge(t *testing.T) (*Bridge, *recordingStarter, *Engine) {
	t.Helper()
	engine := New(Config{ConfigDir: t.TempDir()})
	t.Cleanup(engine.Stop)
	starter := &recordingStarter{}
	return NewBridge(engine, starter), starter, engine
}

// TestRegisterStreamRegistersWithTheEngineAndStartsNothing: the device must end
// up in the engine's registry with a live loopback URL, and the starter must not
// have been called even once.
func TestRegisterStreamRegistersWithTheEngineAndStartsNothing(t *testing.T) {
	bridge, starter, engine := newRecordingBridge(t)
	spec := fakeSpec(t, "eb9f1d6e677b1b39f222ag")

	rtspURL, token, err := bridge.RegisterStream(spec)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}
	if token != ProfileTokenPrefix+spec.DeviceID {
		t.Errorf("profile token = %q, want %q", token, ProfileTokenPrefix+spec.DeviceID)
	}
	if !strings.HasPrefix(rtspURL, "rtsp://127.0.0.1:") {
		t.Errorf("rtsp url = %q, want a loopback URL", rtspURL)
	}

	// The engine now knows the device: this is what restore will ask for.
	resolved, err := bridge.ResolveProfileToken(ProfileTokenPrefix + spec.DeviceID)
	if err != nil {
		t.Fatalf("ResolveProfileToken after registration: %v", err)
	}
	if resolved != rtspURL {
		t.Errorf("resolved url = %q, want the registered %q", resolved, rtspURL)
	}
	if streams := engine.Streams(); len(streams) != 1 || streams[0] != StreamNamePrefix+spec.DeviceID {
		t.Errorf("engine streams = %v, want exactly [%s]", streams, StreamNamePrefix+spec.DeviceID)
	}
	if calls := starter.started(); len(calls) != 0 {
		t.Fatalf("RegisterStream started %d stream(s): %v; it must only register", len(calls), calls)
	}
}

// TestRegisterStreamThenResolveIsIdempotent: registering the same device twice
// (the sweep runs once per stored row, and a row can be duplicated) must leave
// exactly one engine stream and must keep working.
func TestRegisterStreamThenResolveIsIdempotent(t *testing.T) {
	bridge, starter, engine := newRecordingBridge(t)
	spec := fakeSpec(t, "eb9f1d6e677b1b39f222ag")

	first, _, err := bridge.RegisterStream(spec)
	if err != nil {
		t.Fatalf("first RegisterStream: %v", err)
	}
	second, _, err := bridge.RegisterStream(spec)
	if err != nil {
		t.Fatalf("second RegisterStream: %v", err)
	}
	if len(engine.Streams()) != 1 {
		t.Fatalf("engine streams = %v, want exactly 1", engine.Streams())
	}
	// The port is pinned per engine, so both registrations agree on the URL,
	// which is what lets a restore resolve the SAME address the engine serves.
	if first != second {
		t.Errorf("first url %q != second url %q; the engine must not move the stream", first, second)
	}
	if calls := starter.started(); len(calls) != 0 {
		t.Fatalf("registration started %d stream(s): %v", len(calls), calls)
	}
}

// TestRegisterStreamReportsAnInvalidSpec covers the engine-refusal path: a bad
// device id must be an error the caller can log and skip, never a panic.
func TestRegisterStreamReportsAnInvalidSpec(t *testing.T) {
	bridge, _, _ := newRecordingBridge(t)
	_, _, err := bridge.RegisterStream(DeviceSpec{DeviceID: "not a device id!", SessionFile: sessionFile(t)})
	if err == nil {
		t.Fatal("expected an error for an invalid device id")
	}
}

// TestNewBridgeForSessionIsAlwaysUsable is the Bug 3 contract at the engine
// layer: a bridge is built even when NO session is configured, because the flag
// that used to disable it was answered once at boot and left the process unable
// to stream for its whole lifetime once a session appeared later.
//
// The second assertion is the reason this is safe: building the bridge must NOT
// bind a port or spawn anything, so an install without Tuya pays nothing.
func TestNewBridgeForSessionIsAlwaysUsable(t *testing.T) {
	bridge, err := NewBridgeForSession(&recordingStarter{}, loggerForTest(t))
	if err != nil {
		t.Fatalf("NewBridgeForSession: %v", err)
	}
	if bridge == nil {
		t.Fatal("NewBridgeForSession returned a nil bridge; a session that appears after start-up must be usable without a restart")
	}
	engine := bridge.Engine()
	if engine == nil {
		t.Fatal("bridge has no engine")
	}
	if engine.RTSPPort() != 0 {
		t.Errorf("building a bridge already pinned RTSP port %d; it must cost nothing until the first stream", engine.RTSPPort())
	}
	if engine.LocalRunning() {
		t.Error("building a bridge already started the in-process RTSP listener; it must stay down until a stream is registered")
	}
	if engine.Running() {
		t.Error("building a bridge left the engine reported as running")
	}
	if streams := engine.Streams(); len(streams) != 0 {
		t.Errorf("a fresh bridge has %d stream(s): %v", len(streams), streams)
	}
	// And it must still work at that point: registering a device brings the
	// listener up with no restart.
	if _, _, err := bridge.RegisterStream(fakeSpec(t, "eb9f1d6e677b1b39f222ag")); err != nil {
		t.Fatalf("RegisterStream on a freshly built bridge: %v", err)
	}
	if !engine.LocalRunning() {
		t.Error("the in-process listener did not come up on the first registration")
	}
}

// TestNewBridgeForSessionNeverFailsForAMissingSession keeps the "must not break
// startup" property explicit at the constructor.
func TestNewBridgeForSessionNeverFailsForAMissingSession(t *testing.T) {
	bridge, err := NewBridgeForSession(&recordingStarter{}, loggerForTest(t))
	if err != nil {
		t.Fatalf("a missing session must not make the constructor fail: %v", err)
	}
	defer bridge.Stop()
	// Resolving an unknown token must be an error, not an empty success.
	if _, err := bridge.ResolveProfileToken("tuya:unknown"); err == nil {
		t.Error("ResolveProfileToken of an unregistered token returned no error")
	}
	if _, err := bridge.Resolve("nonexistent"); err == nil {
		t.Error("Resolve of an unregistered device must report an error")
	}
}

// loggerForTest builds a throwaway database-backed logger.
func loggerForTest(t *testing.T) *logger.Logger {
	t.Helper()
	l, err := logger.NewLogger(t.TempDir() + "/bridge_test.db")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	t.Cleanup(l.Close)
	return l
}

// TestBridgeErrorsAreWrappedNotSwallowed is a small guard that the two error
// paths the start-up sweep relies on stay informative.
func TestBridgeErrorsAreWrappedNotSwallowed(t *testing.T) {
	var nilBridge *Bridge
	if _, _, err := nilBridge.RegisterStream(DeviceSpec{}); err == nil {
		t.Error("RegisterStream on a nil bridge must report an error")
	}
	bridge := NewBridge(New(Config{ConfigDir: t.TempDir()}), nil)
	if _, err := bridge.StartStream(fakeSpec(t, "eb9f1d6e677b1b39f222ag")); err == nil {
		t.Error("StartStream with no stream starter must report an error")
	}
}
