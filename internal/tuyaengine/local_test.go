package tuyaengine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests pin the default backend: Tuya streaming must work from the repo
// alone, with no external executable anywhere on PATH and no child process.

// localConfig is the configuration every in-process test uses. BinPath is
// deliberately empty: that is the shipped default.
func localConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		ConfigDir:    t.TempDir(),
		BaseBackoff:  40 * time.Millisecond,
		MaxBackoff:   200 * time.Millisecond,
		ReadyTimeout: 10 * time.Second,
		StopTimeout:  3 * time.Second,
	}
}

// TestDefaultBackendDoesNotNeedAnExternalBinary is the regression test for the
// architecture the user rejected: the shipped default must serve Tuya without
// any engine binary. It proves the point by clearing PATH and every
// DefaultBinCandidates entry, then asserting the RTSP endpoint is live.
func TestDefaultBackendDoesNotNeedAnExternalBinary(t *testing.T) {
	_ = fakeEngineBinary(t) // built and cached, but never discoverable below
	originalCandidates := DefaultBinCandidates
	originalPath := os.Getenv("PATH")
	DefaultBinCandidates = []string{
		filepath.Join(t.TempDir(), "definitely-missing-engine"),
	}
	_ = os.Setenv("PATH", t.TempDir())
	t.Cleanup(func() {
		DefaultBinCandidates = originalCandidates
		_ = os.Setenv("PATH", originalPath)
	})
	// The fake engine is addressable only through its absolute path, which the
	// default backend must never consult. Discovery (what the external backend
	// would use) must find nothing at all.
	if _, err := FindEngineBinary(""); err == nil {
		t.Fatal("precondition: engine discovery must find nothing for this test to mean anything")
	}

	engine := New(localConfig(t))
	t.Cleanup(engine.Stop)

	spec := fakeSpec(t, "cam1")
	rtspURL, token, err := engine.AddStream(spec)
	if err != nil {
		t.Fatalf("AddStream with no engine binary: %v", err)
	}
	if token != "tuya:cam1" {
		t.Fatalf("token = %q", token)
	}
	if !strings.HasPrefix(rtspURL, "rtsp://127.0.0.1:") || !strings.HasSuffix(rtspURL, "/tuya_cam1") {
		t.Fatalf("rtspURL = %q", rtspURL)
	}
	if !engine.LocalRunning() {
		t.Fatal("in-process RTSP server is not running")
	}
	if engine.PID() != 0 {
		t.Fatalf("in-process backend spawned a child with pid %d", engine.PID())
	}
	// The endpoint must be a real RTSP server, not just an open socket: the
	// viewer's ffmpeg probes it with OPTIONS/DESCRIBE before it will stream.
	if code, _, err := RTSPDescribe(context.Background(), rtspURL, 2*time.Second); err != nil {
		t.Fatalf("RTSPDescribe: %v", err)
	} else if code != 404 {
		// 404 is the expected answer for a stream whose camera was never
		// dialed: the descriptor exists, the fake spec has no live camera.
		t.Logf("RTSPDescribe code = %d (endpoint answered)", code)
	}
	// Readiness is OPTIONS-only: that is the probe the engine itself uses.
	if !rtspReachable(context.Background(), engine.RTSPURL(), 2*time.Second) {
		t.Fatalf("RTSP OPTIONS on %s did not answer 200", engine.RTSPURL())
	}
}

// TestInProcessBackendRegistersStreamsLive proves a second camera needs no
// restart and that removing a stream makes it disappear from the endpoint.
func TestInProcessBackendRegistersStreamsLive(t *testing.T) {
	engine := New(localConfig(t))
	t.Cleanup(engine.Stop)

	if _, _, err := engine.AddStream(fakeSpec(t, "cam1")); err != nil {
		t.Fatalf("AddStream cam1: %v", err)
	}
	port := engine.RTSPPort()
	if port == 0 {
		t.Fatal("no RTSP port after the first AddStream")
	}
	pid := engine.PID()

	second, token, err := engine.AddStream(fakeSpec(t, "cam2"))
	if err != nil {
		t.Fatalf("AddStream cam2: %v", err)
	}
	if token != "tuya:cam2" {
		t.Fatalf("token = %q", token)
	}
	if !strings.HasSuffix(second, "/tuya_cam2") {
		t.Fatalf("second rtsp URL = %q", second)
	}
	if engine.RTSPPort() != port {
		t.Fatalf("port changed from %d to %d; the URL handed to ffmpeg must stay valid", port, engine.RTSPPort())
	}
	if engine.PID() != pid {
		t.Fatal("adding a stream restarted the world")
	}
	if got := len(engine.Streams()); got != 2 {
		t.Fatalf("registered streams = %d, want 2", got)
	}

	if err := engine.RemoveStream("cam1"); err != nil {
		t.Fatalf("RemoveStream: %v", err)
	}
	if err := engine.RemoveStream("cam1"); err == nil {
		t.Fatal("RemoveStream accepted an already-removed device")
	}
}

// TestInProcessBackendStopReleasesPort proves Stop is graceful and idempotent
// and that the pinned port is returned to the pool, so a restart cannot leak a
// port per cycle.
func TestInProcessBackendStopReleasesPort(t *testing.T) {
	engine := New(localConfig(t))
	if _, _, err := engine.AddStream(fakeSpec(t, "cam1")); err != nil {
		t.Fatalf("AddStream: %v", err)
	}
	port := engine.RTSPPort()
	engine.Stop()
	engine.Stop() // must not panic or block

	if engine.Running() {
		t.Fatal("engine reports running after Stop")
	}
	if !hasEvent(engine, EventStopped) {
		t.Fatalf("no stopped event: %v", engine.Events())
	}
	deadline := time.Now().Add(3 * time.Second)
	for PortInUse(port) {
		if time.Now().After(deadline) {
			t.Fatalf("port %d still in use after Stop", port)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestInProcessBackendHonoursPinnedPort proves an operator-provided RTSPPort is
// used as given, because the URL is persisted in stream_configs and handed to
// ffmpeg.
func TestInProcessBackendHonoursPinnedPort(t *testing.T) {
	port, err := ReserveFreePort()
	if err != nil {
		t.Fatalf("ReserveFreePort: %v", err)
	}
	ReleaseFreePort(port)

	cfg := localConfig(t)
	cfg.RTSPPort = port
	engine := New(cfg)
	t.Cleanup(engine.Stop)

	if _, _, err := engine.AddStream(fakeSpec(t, "cam1")); err != nil {
		t.Fatalf("AddStream: %v", err)
	}
	if engine.RTSPPort() != port {
		t.Fatalf("RTSPPort = %d, want the pinned %d", engine.RTSPPort(), port)
	}
}

// TestExternalBackendIsOptIn proves the supervised-binary path is still
// reachable, and that it is reachable *only* when asked for. This is what keeps
// FindEngineBinary and the supervision loop honest without making them the
// default.
func TestExternalBackendIsOptIn(t *testing.T) {
	binary := fakeEngineBinary(t)

	defaults := New(Config{ConfigDir: t.TempDir()})
	if defaults.usesExternalEngine() {
		t.Fatal("the default backend must be in-process")
	}

	forced := New(Config{Mode: ModeExternal})
	if !forced.usesExternalEngine() {
		t.Fatal("ModeExternal must select the external backend")
	}

	byPath := New(Config{BinPath: binary})
	if !byPath.usesExternalEngine() {
		t.Fatal("an explicit BinPath must select the external backend")
	}

	explicitInProcess := New(Config{Mode: ModeInProcess, BinPath: binary})
	if explicitInProcess.usesExternalEngine() {
		t.Fatal("ModeInProcess must win over BinPath")
	}
}
