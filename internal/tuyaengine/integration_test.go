package tuyaengine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/models"
	"dengan.dev/camera-streamer/internal/stream"
)

// These tests drive the REAL Tuya engine and the REAL HLS pipeline. They are
// opt-in because they need the camera's saved session and consume Tuya cloud
// WebRTC capacity.
//
//	TUYA_ENGINE_INTEGRATION=1 \
//	TUYA_ENGINE_BIN=/path/to/go2rtc \
//	TUYA_ENGINE_SESSION_FILE=$HOME/tuya-es06/.tuya-data/<account>.json \
//	go test -run Integration -v -timeout 15m ./internal/tuyaengine/
//
// Optional:
//
//	TUYA_ENGINE_DEVICE_ID  camera device id (defaults to the bring-up ES06)
//	TUYA_ENGINE_TEST_HLS   keep HLS output in this directory instead of a temp dir

const (
	envIntegration = "TUYA_ENGINE_INTEGRATION"
	envTestHLS     = "TUYA_ENGINE_TEST_HLS"
	envDeviceID    = "TUYA_ENGINE_DEVICE_ID"
	// defaultDevice is the ES06 used during bring-up.
	defaultDevice = "eb9f1d6e677b1b39f222ag"
	// decodeFramesTarget is the number of frames each decode must produce. The
	// task requires a counted frame total; 30 frames is ~1.5s at the camera's 20fps.
	decodeFramesTarget = 30
)

func integrationSpec(t *testing.T) DeviceSpec {
	t.Helper()
	if os.Getenv(envIntegration) != "1" {
		t.Skip("set " + envIntegration + "=1 to run the live-camera integration tests")
	}
	path := os.Getenv(EnvSessionFile)
	if path == "" {
		t.Fatalf("%s must point at the read-only Tuya session file", EnvSessionFile)
	}
	deviceID := os.Getenv(envDeviceID)
	if deviceID == "" {
		deviceID = defaultDevice
	}
	spec, err := DeviceSpec{DeviceID: deviceID, SessionFile: path}.Normalize(DeviceSpec{})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	return spec
}

// liveStack is one engine + one stream manager wired exactly as main.go wires
// them, over private HLS and database directories.
type liveStack struct {
	engine    *Engine
	bridge    *Bridge
	manager   *stream.Manager
	hlsDir    string
	info      *models.StreamInfo
	streamDir string
	playlist  string
}

func startLiveStack(t *testing.T) *liveStack {
	t.Helper()
	spec := integrationSpec(t)

	hlsDir := os.Getenv(envTestHLS)
	if hlsDir == "" {
		hlsDir = t.TempDir()
	}
	if err := os.MkdirAll(hlsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := logger.NewLogger(filepath.Join(hlsDir, "integration.db"))
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	t.Cleanup(db.Close)
	manager := stream.NewManager(hlsDir, db)
	t.Cleanup(manager.Shutdown)
	go manager.CleanupInactiveClients()

	engine := New(DefaultConfig())
	t.Cleanup(engine.Stop)
	engine.SetEventSink(func(event Event) { t.Logf("engine event: %s", event) })
	bridge := NewBridge(engine, manager)

	info, err := bridge.StartStream(spec)
	if err != nil {
		t.Fatalf("Bridge.StartStream: %v", err)
	}
	t.Logf("streamID=%s profileToken=%s hlsURL=%s status=%s engineRTSP=%s enginePID=%d engineRestarts=%d",
		info.ID, info.ProfileToken, info.HlsURL, info.Status, engine.RTSPURL(), engine.PID(), engine.Restarts())

	stack := &liveStack{
		engine:    engine,
		bridge:    bridge,
		manager:   manager,
		hlsDir:    hlsDir,
		info:      info,
		streamDir: filepath.Join(hlsDir, info.ID),
	}
	stack.playlist = filepath.Join(stack.streamDir, "stream.m3u8")
	return stack
}

// segments returns the HLS segment file names currently on disk.
func (s *liveStack) segments() []string {
	entries, err := os.ReadDir(s.streamDir)
	if err != nil {
		return nil
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".ts") {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.Size() == 0 {
			continue
		}
		names = append(names, entry.Name())
	}
	return names
}

// playlistText returns the raw playlist, or "" when it does not exist yet.
func (s *liveStack) playlistText() string {
	data, err := os.ReadFile(s.playlist)
	if err != nil {
		return ""
	}
	return string(data)
}

// waitForSegments waits until at least n non-empty segments exist and reports how
// long that took.
func (s *liveStack) waitForSegments(t *testing.T, n int, timeout time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	deadline := start.Add(timeout)
	for time.Now().Before(deadline) {
		if len(s.segments()) >= n {
			return time.Since(start)
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("only %d segments after %s (playlist=%q)", len(s.segments()), timeout, s.playlistText())
	return 0
}

// hlsURL returns the loopback URL of the playlist, as an ffmpeg input.
func (s *liveStack) hlsURL() string { return fmt.Sprintf("file://%s", s.playlist) }

// runWithTimeout runs a command with a hard cap so a stalled ffmpeg/ffprobe can
// never hang the test. A live HLS playlist legitimately has no end, and
// `ffprobe -count_frames` on one blocks forever waiting for more segments, so
// every external command here is bounded.
func runWithTimeout(t *testing.T, timeout time.Duration, name string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Errorf("%s timed out after %s: %s", name, timeout, strings.Join(args, " "))
	}
	return strings.TrimSpace(string(output)), err
}

// probeVideo reports codec, dimensions and frame rate of the produced HLS.
// It deliberately avoids -count_frames: counting frames of a live playlist is
// unbounded. The exact frame count comes from a counted decode instead.
func (s *liveStack) probeVideo(t *testing.T) string {
	t.Helper()
	output, err := runWithTimeout(t, 60*time.Second, "ffprobe",
		"-v", "error", "-select_streams", "v:0",
		"-show_entries", "stream=codec_name,width,height,r_frame_rate",
		"-of", "default=nw=1", s.playlist)
	if err != nil {
		t.Fatalf("ffprobe: %v\n%s", err, output)
	}
	return output
}

// probeLiveFrameCount counts frames in the newest completed segment. A single
// .ts has a definite end, so -count_frames terminates here and yields an exact
// integer without racing the live playlist.
func (s *liveStack) probeLiveFrameCount(t *testing.T) string {
	t.Helper()
	segments := s.segments()
	if len(segments) == 0 {
		t.Fatal("no segments to count")
	}
	segment := filepath.Join(s.streamDir, segments[len(segments)-1])
	output, err := runWithTimeout(t, 90*time.Second, "ffprobe",
		"-v", "error", "-select_streams", "v:0", "-count_frames",
		"-show_entries", "stream=codec_name,width,height,nb_read_frames,r_frame_rate",
		"-of", "default=nw=1", segment)
	if err != nil {
		t.Fatalf("ffprobe -count_frames %s: %v\n%s", segment, err, output)
	}
	return fmt.Sprintf("segment=%s\n%s", segment, output)
}

// decodeFrames decodes n frames to JPEG and returns the exact number of files
// produced plus the directory they landed in.
//
// This is the only accepted proof that video is present: `-f null` is not usable
// in this environment ("Output file does not contain any stream").
func (s *liveStack) decodeFrames(t *testing.T, n int) (int, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "tuyaengine-frames")
	if err != nil {
		t.Fatal(err)
	}
	pattern := filepath.Join(dir, "m3_%03d.jpg")
	t.Logf("decode command: ffmpeg -v error -y -i %s -frames:v %d -f image2 %s", s.playlist, n, pattern)
	t.Logf("frame count by hand: ls %s/m3_*.jpg | wc -l", dir)
	// -frames:v stops at exactly n frames; the timeout is a safety net only.
	output, err := runWithTimeout(t, 3*time.Minute, "ffmpeg", "-v", "error", "-y",
		"-i", s.playlist, "-frames:v", strconv.Itoa(n), "-f", "image2", pattern)
	produced, _ := filepath.Glob(filepath.Join(dir, "m3_*.jpg"))
	if output != "" {
		t.Logf("decode stderr: %s", output)
	}
	t.Logf("decode exit=%v frames on disk=%d", err, len(produced))
	return len(produced), dir
}

// TestIntegrationTuyaFramesReachHLSThroughExistingPipeline is the end-to-end
// proof: one Bridge call turns a Tuya device into HLS served by the viewer's
// normal ffmpeg pipeline, and real frames can be decoded out of it.
func TestIntegrationTuyaFramesReachHLSThroughExistingPipeline(t *testing.T) {
	stack := startLiveStack(t)

	if !IsTuyaProfileToken(stack.info.ProfileToken) {
		t.Fatalf("profile token %q is not namespaced", stack.info.ProfileToken)
	}
	elapsed := stack.waitForSegments(t, 3, 3*time.Minute)
	t.Logf("first 3 segments after %s", elapsed.Round(time.Second))
	t.Logf("playlist:\n%s", stack.playlistText())

	if code, sdp, err := RTSPDescribe(context.Background(), stack.engine.RTSPURL()+"/tuya_"+stack.specDeviceID(t), 5*time.Second); err != nil || code != 200 {
		t.Errorf("engine RTSP DESCRIBE = %d, %v", code, err)
	} else {
		t.Logf("engine SDP:\n%s", sdp)
	}

	t.Logf("ffprobe (video spec):\n%s", stack.probeVideo(t))
	t.Logf("ffprobe -count_frames (newest segment):\n%s", stack.probeLiveFrameCount(t))

	frames, dir := stack.decodeFrames(t, decodeFramesTarget)
	if frames < decodeFramesTarget {
		t.Fatalf("decoded %d frames, want %d (dir %s)", frames, decodeFramesTarget, dir)
	}
	t.Logf("MEASURED: %d frames decoded from HLS", frames)
}

// TestIntegrationEngineRestartRecoversStream kills the engine child process and
// proves the supervisor respawns it and the HLS output advances again.
func TestIntegrationEngineRestartRecoversStream(t *testing.T) {
	stack := startLiveStack(t)
	stack.waitForSegments(t, 3, 3*time.Minute)

	beforePID := stack.engine.PID()
	beforeSegments := len(stack.segments())
	beforeFrames, beforeDir := stack.decodeFrames(t, decodeFramesTarget)
	t.Logf("BEFORE: pid=%d segments=%d frames=%d dir=%s", beforePID, beforeSegments, beforeFrames, beforeDir)
	if beforePID <= 0 {
		t.Fatal("engine has no pid before the kill")
	}

	// Kill exactly the child the supervisor is watching.
	process, err := os.FindProcess(beforePID)
	if err != nil {
		t.Fatalf("find engine pid %d: %v", beforePID, err)
	}
	if err := process.Kill(); err != nil {
		t.Fatalf("kill engine pid %d: %v", beforePID, err)
	}
	t.Logf("killed engine pid %d", beforePID)

	waitFor(t, 30*time.Second, "supervisor respawn", func() bool {
		return stack.engine.Running() && stack.engine.PID() != beforePID && stack.engine.PID() > 0
	})
	afterPID := stack.engine.PID()
	t.Logf("AFTER RESPAWN: pid=%d restarts=%d lastError=%q", afterPID, stack.engine.Restarts(), stack.engine.LastError())

	// The RTSP URL must be identical: it is pinned and persisted, so ffmpeg's
	// input keeps working across the engine restart.
	if got := stack.engine.RTSPURL(); !strings.HasPrefix(got, "rtsp://127.0.0.1:") {
		t.Fatalf("RTSP base URL after restart = %q", got)
	}
	stack.waitForSegments(t, beforeSegments+2, 3*time.Minute)
	afterFrames, afterDir := stack.decodeFrames(t, decodeFramesTarget)
	t.Logf("AFTER: pid=%d segments=%d frames=%d dir=%s", afterPID, len(stack.segments()), afterFrames, afterDir)
	if afterFrames < decodeFramesTarget {
		t.Fatalf("stream did not recover: %d frames after restart (want %d)", afterFrames, decodeFramesTarget)
	}
	t.Logf("MEASURED: %d frames before kill, %d frames after supervised restart", beforeFrames, afterFrames)
}

func (s *liveStack) specDeviceID(t *testing.T) string {
	t.Helper()
	deviceID := os.Getenv(envDeviceID)
	if deviceID == "" {
		deviceID = defaultDevice
	}
	return deviceID
}
