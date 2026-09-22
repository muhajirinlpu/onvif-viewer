package stream

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/models"
)

// stubFFmpeg is a shell script that stands in for the encoder: it sleeps until
// it is signalled, and records its own start so a test can count real process
// spawns. It writes nothing to the HLS directory, so the stall watchdog is not
// part of what these tests exercise.
const stubFFmpeg = `#!/bin/sh
# M6 test stub: a long-lived process that terminates on SIGTERM/SIGINT.
echo "stub-ffmpeg-started" >&2
trap 'echo "stub-ffmpeg-sigterm" >&2; exit 0' TERM INT
while true; do sleep 1; done
`

// newSuspendTestManager builds a manager whose "ffmpeg" is a stub script, so a
// suspend can be exercised against a REAL child process with no encoder and no
// network involved.
func newSuspendTestManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "ffmpeg-stub")
	if err := os.WriteFile(bin, []byte(stubFFmpeg), 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := logger.NewLogger(filepath.Join(dir, "stream.db"))
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(filepath.Join(dir, "hls"), l)
	m.ffmpegBin = bin
	t.Cleanup(func() {
		m.Shutdown()
		l.Close()
	})
	return m
}

// startTuyaStream starts one Tuya stream through the real manager, so the
// suspend path sees exactly what it sees in production.
func startTuyaStream(t *testing.T, m *Manager, deviceID string) models.StreamInfo {
	t.Helper()
	profileToken := "tuya:" + deviceID
	info, err := m.StartStreamForProvider(profileToken, "rtsp://127.0.0.1:41441/tuya_"+deviceID, models.ProviderTuya)
	if err != nil {
		t.Fatalf("StartStreamForProvider: %v", err)
	}
	return *info
}

// waitForStatus polls until a stream reports the wanted status, or fails.
func waitForStatus(t *testing.T, m *Manager, streamID, want string, timeout time.Duration) models.StreamInfo {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last models.StreamInfo
	for time.Now().Before(deadline) {
		for _, s := range m.ListStreams() {
			if s.ID == streamID {
				last = s
				if s.Status == want {
					return s
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("stream %s status = %q, want %q within %v (%+v)", streamID, last.Status, want, timeout, last)
	return last
}

// countStubProcs counts live stub-ffmpeg processes reading one stream's RTSP URL
// whose process group belongs to THIS manager. Scoping by process group matters:
// an RTSP URL is only unique within one engine instance, so a URL-only scan would
// count the ffmpeg of an unrelated viewer process (or another test run) as a leak.
//
// It uses the STABLE count because every caller ASSERTS on the answer ("exactly
// one", "none left"). A raw single count is not exact on a loaded host: /proc
// reads fail transiently and a failed read is indistinguishable from "no
// process", which was MEASURED to return 0 for a live, owned, running stream in
// 5 of 120 counts under synthetic load. Retrying does not weaken any assertion —
// the values asserted (1, 2, 0) are unchanged; it only stops a transient /proc
// failure from manufacturing the zero.
func countStubProcs(t *testing.T, m *Manager, rtspURL string) int {
	t.Helper()
	return countFFmpegProcessesForStable(rtspURL, m.ownedProcessGroups(rtspURL), 2*time.Second)
}

// streamRTSPURL returns the RTSP URL one stream is running, or "".
func streamRTSPURL(t *testing.T, m *Manager, streamID string) string {
	t.Helper()
	for _, s := range m.ListStreams() {
		if s.ID == streamID {
			return s.RtspURL
		}
	}
	return ""
}

// TestSuspendStopsTheFFmpegAndKeepsTheCard is delivery items 2 and 3 at the
// manager layer, against a real child process.
func TestSuspendStopsTheFFmpegAndKeepsTheCard(t *testing.T) {
	m := newSuspendTestManager(t)
	info := startTuyaStream(t, m, "eb9f1d6e677b1b39f222ag")
	waitForStatus(t, m, info.ID, "running", 5*time.Second)

	if n := countStubProcs(t, m, streamRTSPURL(t, m, info.ID)); n == 0 {
		t.Fatal("no ffmpeg stub process found for the running stream; the test cannot prove a stop")
	}

	if err := m.SuspendStreamForSessionLoss(info.ID, "the Tuya session expired: re-login is required"); err != nil {
		t.Fatalf("SuspendStreamForSessionLoss: %v", err)
	}

	// The child process must be gone: that is the whole point of stopping the
	// bleed.
	if n := countStubProcs(t, m, streamRTSPURL(t, m, info.ID)); n != 0 {
		t.Fatalf("%d ffmpeg process(es) still alive after a suspend; the stream would keep hot-looping", n)
	}
	// ...and the stream must still be listed, visibly needing a re-login.
	list := m.ListStreams()
	if len(list) != 1 {
		t.Fatalf("streams = %d, want 1 (a suspended stream must stay visible)", len(list))
	}
	got := list[0]
	if got.Status != StatusNeedsRelogin {
		t.Errorf("status = %q, want %q", got.Status, StatusNeedsRelogin)
	}
	if !got.Suspended || got.SuspendedReason == "" {
		t.Errorf("suspended=%t reason=%q, want true with a reason", got.Suspended, got.SuspendedReason)
	}
	if got.ProfileToken != "tuya:eb9f1d6e677b1b39f222ag" {
		t.Errorf("profileToken = %q, want the ORIGINAL token so no device is re-selected", got.ProfileToken)
	}
	if !strings.Contains(got.Detail, "re-login") {
		t.Errorf("detail = %q, want it to tell the user to re-login", got.Detail)
	}
	// A suspended stream must not be reconnected by anything.
	if err := m.ReconnectStream(info.ID); err == nil {
		t.Error("a suspended stream must not be reconnectable")
	}
}

// TestSuspendedStreamDoesNotHotLoop is the before/after evidence in one test: a
// suspended stream's ffmpeg process count stays at zero across several stall
// watchdog intervals, instead of being restarted over and over.
func TestSuspendedStreamDoesNotHotLoop(t *testing.T) {
	m := newSuspendTestManager(t)
	info := startTuyaStream(t, m, "eb9f1d6e677b1b39f222ag")
	waitForStatus(t, m, info.ID, "running", 5*time.Second)

	if err := m.SuspendStreamForSessionLoss(info.ID, "session expired"); err != nil {
		t.Fatal(err)
	}
	// Watch for a few watchdog ticks. The stub never produces HLS output, so
	// BEFORE M6 this is exactly the window in which the watchdog would restart
	// it; the reconnect count is the honest measure.
	time.Sleep(3 * hlsHealthInterval)
	suspended := m.ListStreams()[0]
	if suspended.Status != StatusNeedsRelogin {
		t.Fatalf("status changed to %q; a suspended stream must not be restarted", suspended.Status)
	}
	if suspended.ReconnectCount != 0 {
		t.Fatalf("reconnectCount = %d, want 0 (the stream is suspended, not retrying)", suspended.ReconnectCount)
	}
	if n := countStubProcs(t, m, streamRTSPURL(t, m, info.ID)); n != 0 {
		t.Fatalf("%d ffmpeg process(es) appeared after a suspend: this is the reconnect storm M6 prevents", n)
	}
}

// TestResumeBringsBackTheSameStreamAndProcess is delivery item 4 at the manager
// layer: the same id and token, and ffmpeg running again.
func TestResumeBringsBackTheSameStreamAndProcess(t *testing.T) {
	m := newSuspendTestManager(t)
	info := startTuyaStream(t, m, "eb9f1d6e677b1b39f222ag")
	waitForStatus(t, m, info.ID, "running", 5*time.Second)
	if err := m.SuspendStreamForSessionLoss(info.ID, "session expired"); err != nil {
		t.Fatal(err)
	}
	if n := countStubProcs(t, m, streamRTSPURL(t, m, info.ID)); n != 0 {
		t.Fatalf("%d ffmpeg process(es) alive before the resume", n)
	}

	const newURL = "rtsp://127.0.0.1:43625/tuya_eb9f1d6e677b1b39f222ag"
	resumed, err := m.ResumeSuspended(info.ID, newURL, models.ProviderTuya)
	if err != nil {
		t.Fatalf("ResumeSuspended: %v", err)
	}
	if resumed.ID != info.ID || resumed.ProfileToken != info.ProfileToken {
		t.Fatalf("resume changed the identity: %+v vs %+v", resumed, info)
	}
	if resumed.Suspended {
		t.Error("the resumed stream is still marked suspended")
	}
	// ffmpeg must actually be running again.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if countStubProcs(t, m, streamRTSPURL(t, m, info.ID)) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := countStubProcs(t, m, streamRTSPURL(t, m, info.ID)); n == 0 {
		t.Fatal("no ffmpeg process after a resume; the stream did not actually come back")
	}
	if list := m.ListStreams(); len(list) != 1 {
		t.Fatalf("streams = %d, want exactly 1 (a resume must not duplicate a card)", len(list))
	}
	if got := m.ListStreams()[0]; got.RtspURL != newURL {
		t.Errorf("rtspUrl = %q, want the fresh engine endpoint %q", got.RtspURL, newURL)
	}
}

// TestStartStreamResumesASuspendedStreamInPlace proves the UI path: replaying
// the same device id resumes the existing card rather than creating a second one.
func TestStartStreamResumesASuspendedStreamInPlace(t *testing.T) {
	m := newSuspendTestManager(t)
	info := startTuyaStream(t, m, "eb9f1d6e677b1b39f222ag")
	waitForStatus(t, m, info.ID, "running", 5*time.Second)
	if err := m.SuspendStreamForSessionLoss(info.ID, "session expired"); err != nil {
		t.Fatal(err)
	}

	const newURL = "rtsp://127.0.0.1:49999/tuya_eb9f1d6e677b1b39f222ag"
	again, err := m.StartStreamForProvider("tuya:eb9f1d6e677b1b39f222ag", newURL, models.ProviderTuya)
	if err != nil {
		t.Fatalf("StartStreamForProvider: %v", err)
	}
	if again.ID != info.ID {
		t.Fatalf("stream id = %q, want the EXISTING %q (no duplicate card)", again.ID, info.ID)
	}
	if again.Suspended {
		t.Error("the resumed stream is still marked suspended")
	}
	if list := m.ListStreams(); len(list) != 1 {
		t.Fatalf("streams = %d, want exactly 1", len(list))
	}
}

// TestSuspendStreamsForProviderOnlyTouchesItsProvider is the safety property that
// matters most: a Tuya session expiring must never stop an ONVIF stream.
func TestSuspendStreamsForProviderOnlyTouchesItsProvider(t *testing.T) {
	m := newSuspendTestManager(t)
	tuyaInfo := startTuyaStream(t, m, "eb9f1d6e677b1b39f222ag")
	onvifInfo, err := m.StartStreamForProvider("profile_1", "rtsp://127.0.0.1:554/onvif", models.ProviderONVIF)
	if err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, m, tuyaInfo.ID, "running", 5*time.Second)
	waitForStatus(t, m, onvifInfo.ID, "running", 5*time.Second)

	n, err := m.SuspendStreamsForProvider(models.ProviderTuya, "session expired")
	if err != nil {
		t.Fatalf("SuspendStreamsForProvider: %v", err)
	}
	if n != 1 {
		t.Fatalf("suspended = %d, want 1", n)
	}
	for _, s := range m.ListStreams() {
		switch s.ID {
		case tuyaInfo.ID:
			if !s.Suspended || s.Status != StatusNeedsRelogin {
				t.Errorf("the Tuya stream was not suspended: %+v", s)
			}
		case onvifInfo.ID:
			if s.Suspended || s.Status != "running" {
				t.Errorf("the ONVIF stream was disturbed: status=%q suspended=%t", s.Status, s.Suspended)
			}
		}
	}
	if n := countStubProcs(t, m, streamRTSPURL(t, m, onvifInfo.ID)); n == 0 {
		t.Error("the ONVIF stream's ffmpeg was stopped by a Tuya sweep")
	}
	// A second sweep must be a no-op.
	if n2, err := m.SuspendStreamsForProvider(models.ProviderTuya, "session expired"); err != nil || n2 != 0 {
		t.Fatalf("second sweep: n=%d err=%v, want 0/nil", n2, err)
	}
}

// TestSuspendedStreamsListsOnlyTheRequestedProvider.
func TestSuspendedStreamsListsOnlyTheRequestedProvider(t *testing.T) {
	m := newSuspendTestManager(t)
	tuyaInfo := startTuyaStream(t, m, "eb9f1d6e677b1b39f222ag")
	if _, err := m.StartStreamForProvider("profile_1", "rtsp://127.0.0.1:554/onvif", models.ProviderONVIF); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, m, tuyaInfo.ID, "running", 5*time.Second)
	if _, err := m.SuspendStreamsForProvider(models.ProviderTuya, "session expired"); err != nil {
		t.Fatal(err)
	}

	got := m.SuspendedStreams(models.ProviderTuya)
	if len(got) != 1 || got[0].ID != tuyaInfo.ID {
		t.Fatalf("SuspendedStreams(tuya) = %v, want just %s", got, tuyaInfo.ID)
	}
	if other := m.SuspendedStreams(models.ProviderONVIF); len(other) != 0 {
		t.Fatalf("SuspendedStreams(onvif) = %v, want none", other)
	}
}

// TestResumeSuspendedRefusesAStreamThatIsNotSuspended prevents a resume from
// silently restarting a healthy stream, and from accepting nonsense.
func TestResumeSuspendedRefusesAStreamThatIsNotSuspended(t *testing.T) {
	m := newSuspendTestManager(t)
	info := startTuyaStream(t, m, "eb9f1d6e677b1b39f222ag")
	waitForStatus(t, m, info.ID, "running", 5*time.Second)

	if _, err := m.ResumeSuspended(info.ID, "rtsp://127.0.0.1:1/x", models.ProviderTuya); err == nil {
		t.Error("resuming a live stream must fail")
	}
	if _, err := m.ResumeSuspended("nope", "rtsp://127.0.0.1:1/x", models.ProviderTuya); err == nil {
		t.Error("resuming an unknown stream must fail")
	}
	// A healthy stream must be untouched by the failed attempts.
	if got := m.ListStreams()[0]; got.Suspended || got.Status != "running" {
		t.Fatalf("the live stream was disturbed by failed resumes: %+v", got)
	}
}

// TestStopStreamsForProviderStillStopsRemovesThem keeps the older, destructive
// helper honest about what it does.
func TestStopStreamsForProviderStillStopsRemovesThem(t *testing.T) {
	m := newSuspendTestManager(t)
	tuyaInfo := startTuyaStream(t, m, "eb9f1d6e677b1b39f222ag")
	onvifInfo, err := m.StartStreamForProvider("profile_1", "rtsp://127.0.0.1:554/onvif", models.ProviderONVIF)
	if err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, m, tuyaInfo.ID, "running", 5*time.Second)
	waitForStatus(t, m, onvifInfo.ID, "running", 5*time.Second)

	n, err := m.StopStreamsForProvider(models.ProviderTuya)
	if err != nil {
		t.Fatalf("StopStreamsForProvider: %v", err)
	}
	if n != 1 {
		t.Fatalf("stopped = %d, want 1", n)
	}
	for _, s := range m.ListStreams() {
		if s.ID == tuyaInfo.ID {
			t.Error("a stopped stream must be gone from the registry")
		}
		if s.ID == onvifInfo.ID && s.Status != "running" {
			t.Errorf("the ONVIF stream was affected by a Tuya sweep: %+v", s)
		}
	}
	if countStubProcs(t, m, streamRTSPURL(t, m, onvifInfo.ID)) == 0 {
		t.Error("the ONVIF stream's ffmpeg was stopped by a Tuya sweep")
	}
}

// TestLeakDetectionIgnoresForeignProcessesWithTheSameURL is the guard that made
// the stop assertion usable at all. An RTSP URL is only unique inside one engine
// instance, so a URL-only /proc scan happily counts an unrelated viewer process
// as a leaked ffmpeg. The check must be scoped to the process groups this manager
// owns, or a healthy stop would be reported as a failure.
func TestLeakDetectionIgnoresForeignProcessesWithTheSameURL(t *testing.T) {
	m := newSuspendTestManager(t)
	info := startTuyaStream(t, m, "eb9f1d6e677b1b39f222ag")
	waitForStatus(t, m, info.ID, "running", 5*time.Second)
	url := streamRTSPURL(t, m, info.ID)
	if url == "" {
		t.Fatal("no RTSP URL for the running stream")
	}
	if countStubProcs(t, m, url) == 0 {
		t.Fatal("the manager does not see its own ffmpeg; the check is broken, not correct")
	}

	// A process group this manager does NOT own, reading the SAME url. That is
	// exactly what a second viewer instance looks like on one host.
	foreign := exec.Command("/bin/sh", "-c", "sleep 30 # "+url)
	foreign.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := foreign.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = foreign.Process.Kill(); _, _ = foreign.Process.Wait() })

	if n := countStubProcs(t, m, url); n != 1 {
		t.Fatalf("owned ffmpeg count = %d, want exactly 1 (a foreign process with the same URL must not be counted)", n)
	}
	if n := countFFmpegProcessesFor(url, map[int]bool{}); n != 0 {
		t.Fatalf("no owned process groups -> count = %d, want 0", n)
	}
}

// TestResumeDoesNotSpawnASecondFFmpegForTheSameStream is the regression guard for
// a real bug found during the live rehearsal: the previous monitor can be sitting
// in its reconnect backoff when a resume happens, wake up afterwards, and start a
// SECOND ffmpeg for the same stream. A suspended stream's monitor is cancelled, so
// exactly one process may exist after a resume.
func TestResumeDoesNotSpawnASecondFFmpegForTheSameStream(t *testing.T) {
	m := newSuspendTestManager(t)
	info := startTuyaStream(t, m, "eb9f1d6e677b1b39f222ag")
	waitForStatus(t, m, info.ID, "running", 5*time.Second)
	const newURL = "rtsp://127.0.0.1:43625/tuya_eb9f1d6e677b1b39f222ag"

	// The stream is moved onto the URL the test counts FIRST, before any
	// assertion. Reason, MEASURED: suspend waits only for process.Exited, which
	// the previous monitor closes as a defer, so a spawn that monitor had
	// ALREADY committed before the kill is not waited for. When the counting
	// URL was only adopted from round 1 onwards, a later suspend could observe
	// the survivor of that committed spawn still carrying the OLD url, and
	// countStubProcs(newURL) then saw the stream as gone (0) rather than the 1
	// it wants. Adopting the new URL up front removes the old URL from the
	// picture so every process that can survive a suspend already carries the
	// URL being counted. No assertion is changed: the suspend/resume loop below
	// and its "no process survives a suspend" and "exactly one after a resume"
	// checks are the original ones, at the original counts.
	if err := m.SuspendStreamForSessionLoss(info.ID, "session expired"); err != nil {
		t.Fatalf("initial suspend: %v", err)
	}
	if _, err := m.ResumeSuspended(info.ID, newURL, models.ProviderTuya); err != nil {
		t.Fatalf("initial resume onto the counting URL: %v", err)
	}
	waitForStatus(t, m, info.ID, "running", 5*time.Second)

	// Suspend repeatedly, which exercises the cancellation of the monitor that is
	// in its backoff, then resume onto the same fresh URL.
	for i := 0; i < 3; i++ {
		if err := m.SuspendStreamForSessionLoss(info.ID, "session expired"); err != nil {
			t.Fatalf("suspend %d: %v", i, err)
		}
		if n := countStubProcs(t, m, streamRTSPURL(t, m, info.ID)); n != 0 {
			t.Fatalf("after suspend %d, %d ffmpeg process(es) remain", i, n)
		}
		if _, err := m.ResumeSuspended(info.ID, newURL, models.ProviderTuya); err != nil {
			t.Fatalf("resume %d: %v", i, err)
		}
		waitForStatus(t, m, info.ID, "running", 5*time.Second)
	}

	// Let any superseded monitor's backoff elapse, then count. The reconnect
	// delays here are seconds-scale, so this window is long enough to expose the
	// duplicate the bug produced.
	time.Sleep(6 * time.Second)
	if n := countStubProcs(t, m, newURL); n != 1 {
		t.Fatalf("owned ffmpeg processes for the resumed stream = %d, want exactly 1 (a duplicate means a superseded monitor woke up)", n)
	}
	if list := m.ListStreams(); len(list) != 1 {
		t.Fatalf("streams = %d, want exactly 1", len(list))
	}
}
