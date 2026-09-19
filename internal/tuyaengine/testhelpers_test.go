package tuyaengine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// binaryOnce caches the compiled fake engine so every test in the package pays
// the build cost at most once.
var (
	binaryOnce sync.Once
	binaryPath string
	binaryErr  error
)

// fakeEngineBinary compiles testdata/fakeengine and returns its path. testdata is
// invisible to `go build ./...`, so it can never leak into the shipped binary,
// but it is still type-checked and vet-able as a normal package.
func fakeEngineBinary(t *testing.T) string {
	t.Helper()
	binaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "tuyaengine-fake")
		if err != nil {
			binaryErr = err
			return
		}
		out := filepath.Join(dir, "fake-engine")
		cmd := exec.Command("go", "build", "-o", out, "./testdata/fakeengine")
		cmd.Env = os.Environ()
		if output, err := cmd.CombinedOutput(); err != nil {
			binaryErr = fmt.Errorf("build fake engine: %v: %s", err, output)
			return
		}
		binaryPath = out
	})
	if binaryErr != nil {
		t.Fatalf("fake engine unavailable: %v", binaryErr)
	}
	return binaryPath
}

// sessionFile writes a minimal, permission-correct stand-in for the real Tuya
// session file. Tests never need its contents: the fake engine only checks that
// the path exists and is 0600.
func sessionFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session.json")
	contents := `{"sessionData":{"serverHost":"protect-us.ismartlife.me","cookies":[{"name":"fast-sid","value":"x"},{"name":"s-sid","value":"y"}]}}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write session fixture: %v", err)
	}
	return path
}

// fakeSpec builds a DeviceSpec bound to a fake session file.
func fakeSpec(t *testing.T, deviceID string) DeviceSpec {
	t.Helper()
	return DeviceSpec{DeviceID: deviceID, SessionFile: sessionFile(t), Resolution: ResolutionSD}
}

// testConfig is the fast-timing configuration used by every supervision test.
func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		BinPath:      fakeEngineBinary(t),
		ConfigDir:    t.TempDir(),
		BaseBackoff:  40 * time.Millisecond,
		MaxBackoff:   200 * time.Millisecond,
		ReadyTimeout: 10 * time.Second,
		StopTimeout:  3 * time.Second,
	}
}

// waitForReady polls until the engine's RTSP endpoint answers.
//
// Waiting on "a new pid exists" is not enough: the supervisor assigns a fresh
// child the instant it spawns one, which is before that child has bound its
// listener. Only RTSP answering proves the engine actually recovered.
func waitForReady(t *testing.T, engine *Engine, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastCode int
	var lastErr error
	for time.Now().Before(deadline) {
		url := engine.RTSPURL()
		if url != "" {
			code, _, err := RTSPDescribe(context.Background(), url, defaultProbeTimeout)
			lastCode, lastErr = code, err
			if err == nil && code == 200 {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("engine RTSP %q never became ready within %s (last code=%d err=%v)", engine.RTSPURL(), timeout, lastCode, lastErr)
}

// waitFor polls until condition returns true or the timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}
