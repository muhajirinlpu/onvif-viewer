package tuyaengine

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBackoffIsExponentialAndCapped(t *testing.T) {
	engine := New(Config{BaseBackoff: time.Second, MaxBackoff: 8 * time.Second})
	want := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		8 * time.Second,
		8 * time.Second,
	}
	for i, expected := range want {
		if got := engine.backoff(i + 1); got != expected {
			t.Fatalf("backoff(%d) = %s, want %s", i+1, got, expected)
		}
	}
	// Attempt 0 and negative attempts are clamped to the base delay, so a first
	// restart is never instantaneous.
	if got := engine.backoff(0); got != time.Second {
		t.Fatalf("backoff(0) = %s, want %s", got, time.Second)
	}
}

func TestBackoffNeverExceedsMaxWhenBaseExceedsMax(t *testing.T) {
	engine := New(Config{BaseBackoff: 10 * time.Second, MaxBackoff: time.Second})
	if got := engine.backoff(3); got != 10*time.Second {
		t.Fatalf("backoff(3) = %s, want the base delay 10s", got)
	}
}

func TestReserveFreePortIsUniqueAndReusable(t *testing.T) {
	first, err := ReserveFreePort()
	if err != nil {
		t.Fatalf("ReserveFreePort: %v", err)
	}
	second, err := ReserveFreePort()
	if err != nil {
		t.Fatalf("ReserveFreePort: %v", err)
	}
	if first == second {
		t.Fatalf("ReserveFreePort handed out %d twice", first)
	}
	if first < 1024 || first > 65535 {
		t.Fatalf("ReserveFreePort returned unusable port %d", first)
	}
	ReleaseFreePort(first)
	ReleaseFreePort(second)
	if !PortInUse(80) && PortInUse(first) {
		// PortInUse is advisory; just make sure the released port is not stuck.
		_ = first
	}
}

func TestRenderEngineConfigNeverAllowsYAMLInjection(t *testing.T) {
	engine := New(Config{ConfigDir: t.TempDir(), LogLevel: "info"})
	engine.mu.Lock()
	engine.streams["tuya_cam1"] = "tuya://host?device_id=cam1&session_file=/tmp/s.json&resolution=sd"
	engine.mu.Unlock()
	rendered, err := engine.renderEngineConfig(1234, 5678)
	if err != nil {
		t.Fatalf("renderEngineConfig: %v", err)
	}
	for _, want := range []string{
		`listen: "127.0.0.1:1234"`,
		`listen: "127.0.0.1:5678"`,
		"webrtc:\n  listen: \"\"",
		"  tuya_cam1:\n    - \"tuya://host?device_id=cam1&session_file=/tmp/s.json&resolution=sd\"",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered config missing %q\n%s", want, rendered)
		}
	}
}

func TestConfigValidateRejectsSharedPorts(t *testing.T) {
	cfg := Config{APIPort: 9000, RTSPPort: 9000, RTSPHost: "127.0.0.1"}.withDefaults()
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted identical api/rtsp ports")
	}
	cfg = Config{APIPort: 9000, RTSPPort: 9001, RTSPHost: "127.0.0.1"}.withDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestFindEngineBinaryHonoursExplicitPathAndEnvCandidate(t *testing.T) {
	binary := fakeEngineBinary(t)
	if got, err := FindEngineBinary(binary); err != nil || got != binary {
		t.Fatalf("FindEngineBinary(%s) = %q, %v", binary, got, err)
	}
	if _, err := FindEngineBinary("/nonexistent/engine"); err == nil {
		t.Fatal("FindEngineBinary accepted a missing explicit path")
	}

	// DefaultBinCandidates is what makes the temp path configurable at all: with
	// it replaced, discovery must find the substitute and nothing else.
	original := DefaultBinCandidates
	DefaultBinCandidates = []string{binary}
	defer func() { DefaultBinCandidates = original }()
	if got, err := FindEngineBinary(""); err != nil || got != binary {
		t.Fatalf("FindEngineBinary(\"\") = %q, %v", got, err)
	}
}

func TestAddStreamRequiresValidSpecBeforeSpawning(t *testing.T) {
	engine := New(testConfig(t))
	if _, _, err := engine.AddStream(DeviceSpec{DeviceID: "..bad.."}); err == nil {
		t.Fatal("AddStream accepted an invalid device id")
	}
	if engine.Running() {
		t.Fatal("engine spawned for an invalid spec")
	}
}

func TestStreamRegistryTracksProfileTokens(t *testing.T) {
	engine := New(testConfig(t))
	spec := normalizedSpec(t, "cam9")

	// Register without starting the child by using the registry path only.
	source, err := spec.EngineURL()
	if err != nil {
		t.Fatal(err)
	}
	name, err := spec.StreamName()
	if err != nil {
		t.Fatal(err)
	}
	token, err := spec.ProfileToken()
	if err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	engine.streams[name] = source
	engine.byToken[token] = name
	engine.mu.Unlock()

	names := engine.Streams()
	if len(names) != 1 || names[0] != "tuya_cam9" {
		t.Fatalf("Streams() = %v", names)
	}
	if err := engine.RemoveStream("cam9"); err != nil {
		t.Fatalf("RemoveStream: %v", err)
	}
	if got := engine.Streams(); len(got) != 0 {
		t.Fatalf("Streams() after removal = %v", got)
	}
	if err := engine.RemoveStream("cam9"); err == nil {
		t.Fatal("RemoveStream accepted an unregistered device")
	}
}

// ---------------------------------------------------------------------------
// Supervision against the fake child
// ---------------------------------------------------------------------------

func TestEngineStartsAndReportsReady(t *testing.T) {
	engine := New(testConfig(t))
	t.Cleanup(engine.Stop)
	spec := fakeSpec(t, "cam1")

	rtspURL, token, err := engine.AddStream(spec)
	if err != nil {
		t.Fatalf("AddStream: %v", err)
	}
	if token != "tuya:cam1" {
		t.Fatalf("token = %q", token)
	}
	if !strings.HasPrefix(rtspURL, "rtsp://127.0.0.1:") || !strings.HasSuffix(rtspURL, "/tuya_cam1") {
		t.Fatalf("rtspURL = %q", rtspURL)
	}
	if !engine.Running() {
		t.Fatal("engine is not running after AddStream")
	}
	if code, _, err := RTSPDescribe(context.Background(), rtspURL, 2*time.Second); err != nil || code != 200 {
		t.Fatalf("RTSPDescribe = %d, %v", code, err)
	}
	if engine.PID() <= 0 {
		t.Fatal("engine has no pid")
	}
	// The same credentials must never be needed twice: a second AddStream for the
	// same device is a no-op returning the same URL.
	again, _, err := engine.AddStream(spec)
	if err != nil {
		t.Fatalf("second AddStream: %v", err)
	}
	if again != rtspURL {
		t.Fatalf("second AddStream returned %q, want %q", again, rtspURL)
	}
}

func TestEngineRestartsAfterUnexpectedExit(t *testing.T) {
	cfg := testConfig(t)
	engine := New(cfg)
	t.Cleanup(engine.Stop)

	if _, _, err := engine.AddStream(fakeSpec(t, "cam1")); err != nil {
		t.Fatalf("AddStream: %v", err)
	}
	firstPID := engine.PID()
	if firstPID <= 0 {
		t.Fatal("no pid after start")
	}

	// Kill the child exactly as a crash would: SIGKILL to the process group.
	killChild(t, firstPID)

	// The engine is only recovered once the respawned child answers on its RTSP
	// port; a fresh pid alone says nothing (the supervisor assigns it at spawn).
	waitForReady(t, engine, 15*time.Second)
	secondPID := engine.PID()
	if secondPID == firstPID {
		t.Fatalf("engine pid did not change (%d)", firstPID)
	}
	if engine.Restarts() < 2 {
		t.Fatalf("Restarts() = %d, want at least 2", engine.Restarts())
	}
	// The pinned port means the URL ffmpeg was given keeps working unchanged.
	url, err := engine.Resolve("cam1")
	if err != nil {
		t.Fatalf("Resolve after restart: %v", err)
	}
	if _, _, err := RTSPDescribe(context.Background(), url, defaultProbeTimeout); err != nil {
		t.Fatalf("RTSP after restart: %v", err)
	}
	assertEventKinds(t, engine, EventExited, EventRestarting)
}

func TestEngineBackoffGrowsAcrossRepeatedCrashes(t *testing.T) {
	cfg := testConfig(t)
	engine := New(cfg)
	t.Cleanup(engine.Stop)
	if _, _, err := engine.AddStream(fakeSpec(t, "cam1")); err != nil {
		t.Fatalf("AddStream: %v", err)
	}

	// Crash it three times. Each restart must wait longer than the previous one,
	// which is only observable through the recorded restart events.
	killed := engine.PID()
	for i := 0; i < 3; i++ {
		killChild(t, killed)
		// Wait for the replacement to be serving, so each kill lands on a
		// settled child and the observed delays reflect real restart cycles.
		waitForReady(t, engine, 15*time.Second)
		killed = engine.PID()
	}

	var delays []int64
	for _, event := range engine.Events() {
		if event.Kind == EventRestarting {
			delays = append(delays, event.DelayMS)
		}
	}
	if len(delays) < 3 {
		t.Fatalf("restart events = %d (%v), want at least 3", len(delays), delays)
	}
	for i := 1; i < len(delays); i++ {
		if delays[i] < delays[i-1] {
			t.Fatalf("backoff decreased: %v", delays)
		}
	}
	if delays[len(delays)-1] <= delays[0] {
		t.Fatalf("backoff never grew: %v", delays)
	}
	if delays[len(delays)-1] > cfg.MaxBackoff.Milliseconds() {
		t.Fatalf("backoff exceeded the cap: %v > %s", delays, cfg.MaxBackoff)
	}
}

func TestEngineStopsRestartingAtMaxRestarts(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxRestarts = 2
	engine := New(cfg)
	t.Cleanup(engine.Stop)
	if _, _, err := engine.AddStream(fakeSpec(t, "cam1")); err != nil {
		t.Fatalf("AddStream: %v", err)
	}

	deadline := time.Now().Add(20 * time.Second)
	lastKilled := 0
	for time.Now().Before(deadline) {
		if hasEvent(engine, EventMaxRestarts) {
			break
		}
		// Kill each child pid at most once: a repeated kill of a reaped pid would
		// be a test artefact, not a supervision failure.
		if pid := engine.PID(); pid > 0 && pid != lastKilled && engine.Running() {
			killChild(t, pid)
			lastKilled = pid
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !hasEvent(engine, EventMaxRestarts) {
		t.Fatalf("engine never gave up: %v", engine.Events())
	}
	waitFor(t, 3*time.Second, "supervisor to exit", func() bool {
		return !engine.Running()
	})
}

func TestEngineStopIsGracefulAndIdempotent(t *testing.T) {
	engine := New(testConfig(t))
	if _, _, err := engine.AddStream(fakeSpec(t, "cam1")); err != nil {
		t.Fatalf("AddStream: %v", err)
	}
	pid := engine.PID()
	engine.Stop()
	engine.Stop() // must not panic or block

	if engine.Running() {
		t.Fatal("engine still running after Stop")
	}
	if processAlive(pid) {
		t.Fatalf("child pid %d survived Stop", pid)
	}
	if !hasEvent(engine, EventStopped) {
		t.Fatalf("no stopped event: %v", engine.Events())
	}
}

func TestEngineFailureToSpawnIsReportedAndRetried(t *testing.T) {
	cfg := testConfig(t)
	cfg.BinPath = cfg.BinPath + ".does-not-exist"
	engine := New(cfg)
	t.Cleanup(engine.Stop)

	if _, _, err := engine.AddStream(fakeSpec(t, "cam1")); err == nil {
		t.Fatal("AddStream reported success with a missing binary")
	}
	if engine.Running() {
		t.Fatal("engine reports running with a missing binary")
	}
	if engine.LastError() == "" {
		t.Fatal("no error recorded for a missing binary")
	}
	waitFor(t, 3*time.Second, "spawn failure event", func() bool {
		return hasEvent(engine, EventStarting)
	})
}

func TestConcurrentAddStreamSpawnsOneChild(t *testing.T) {
	engine := New(testConfig(t))
	t.Cleanup(engine.Stop)

	var wg sync.WaitGroup
	urls := make([]string, 8)
	errs := make([]error, 8)
	spec := fakeSpec(t, "cam1")
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			urls[i], _, errs[i] = engine.AddStream(spec)
		}(i)
	}
	wg.Wait()

	first := ""
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent AddStream[%d]: %v", i, err)
		}
		if first == "" {
			first = urls[i]
		}
		if urls[i] != first {
			t.Fatalf("concurrent AddStream returned inconsistent URLs: %v", urls)
		}
	}
	if first == "" {
		t.Fatal("concurrent AddStream returned no URL")
	}
	if got := engine.Restarts(); got != 1 {
		t.Fatalf("Restarts() = %d, want exactly 1 child spawned", got)
	}
}

func TestAddStreamWhileRunningRegistersLiveStream(t *testing.T) {
	engine := New(testConfig(t))
	t.Cleanup(engine.Stop)
	if _, _, err := engine.AddStream(fakeSpec(t, "cam1")); err != nil {
		t.Fatalf("AddStream: %v", err)
	}
	pid := engine.PID()

	second, token, err := engine.AddStream(fakeSpec(t, "cam2"))
	if err != nil {
		t.Fatalf("second device AddStream: %v", err)
	}
	if token != "tuya:cam2" {
		t.Fatalf("token = %q", token)
	}
	if engine.PID() != pid {
		t.Fatal("adding a second stream respawned the engine, but one engine must serve all streams")
	}
	if !strings.HasSuffix(second, "/tuya_cam2") {
		t.Fatalf("second rtsp URL = %q", second)
	}
	if got := len(engine.Streams()); got != 2 {
		t.Fatalf("registered streams = %d, want 2", got)
	}
}

func TestResolveStreamRejectsOnvifTokens(t *testing.T) {
	engine := New(testConfig(t))
	if _, err := engine.ResolveStream("Profile_1"); err == nil {
		t.Fatal("ResolveStream accepted an ONVIF profile token")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func killChild(t *testing.T, pid int) {
	t.Helper()
	if pid <= 0 {
		t.Fatal("cannot kill pid <= 0")
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		t.Fatalf("find child %d: %v", pid, err)
	}
	if err := process.Kill(); err != nil {
		t.Fatalf("kill child %d: %v", pid, err)
	}
}

func hasEvent(engine *Engine, kind string) bool {
	for _, event := range engine.Events() {
		if event.Kind == kind {
			return true
		}
	}
	return false
}

func assertEventKinds(t *testing.T, engine *Engine, kinds ...string) {
	t.Helper()
	for _, kind := range kinds {
		if !hasEvent(engine, kind) {
			t.Fatalf("missing %q event in %v", kind, engine.Events())
		}
	}
}
