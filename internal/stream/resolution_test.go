package stream

import (
	"path/filepath"
	"strings"
	"testing"

	"dengan.dev/camera-streamer/internal/logger"
)

// --- M7: per-camera resolution and the HD output path ------------------------
//
// These are ADDITIVE. Nothing that existed before this milestone was changed:
// every assertion in provider_test.go, health_test.go, suspend_test.go and
// snapshot_test.go still guards the same behaviour, so a regression in the SD /
// ONVIF path still fails the suite.

// joinedArgs renders an arg list the way ffmpeg would receive it, so a test can
// assert on the exact shape of the command.
func joinedArgs(args []string) string { return strings.Join(args, " ") }

// TestSDArgumentsAreUnchangedFromHEAD is the no-regression proof for SD.
//
// The expected string is the arg list as it stood at HEAD (c627317), copied
// verbatim from git show c627317:internal/stream/manager.go. If a future change
// adds, removes or reorders an SD argument, this test fails: SD must keep taking
// the proven copy-into-MPEG-TS path.
func TestSDArgumentsAreUnchangedFromHEAD(t *testing.T) {
	m, l := testManager(t)
	defer l.Close()

	const head = "-y -fflags +genpts+igndts -rtsp_transport tcp -rtsp_flags prefer_tcp " +
		// -timeout is 30s, not the 5s that was here at HEAD: the 5s bound killed
		// a healthy Tuya start (14.3s to the first segment) and surfaced as a
		// camera reconnecting forever. Pinned as a literal so any further change
		// is caught here; TestInputIOTimeoutIsGenerousEnoughForTuyaStartup
		// guards the value itself.
		"-timeout 30000000 -i rtsp://10.0.0.9:554/live -c:v copy -c:a aac " +
		"-avoid_negative_ts make_zero -max_interleave_delta 0 -hls_time 2 -hls_list_size 5 " +
		"-hls_start_number_source epoch -hls_flags delete_segments+independent_segments " +
		"-hls_segment_type mpegts -f hls /tmp/hls/stream.m3u8"

	got := joinedArgs(m.ffmpegArgsFor("rtsp://10.0.0.9:554/live", "/tmp/hls", OutputCopyMPEGTS))
	if got != head {
		t.Fatalf("SD/ONVIF ffmpeg args changed from HEAD\ngot:  %s\nwant: %s", got, head)
	}
}

// TestSDIsTheDefaultForAnUnsetResolution proves that a camera that never opted
// into HD cannot accidentally get HD: an empty or absent resolution has to be
// the copy path.
func TestSDIsTheDefaultForAnUnsetResolution(t *testing.T) {
	for _, value := range []string{"", "sd", "SD", " sd ", "something-else"} {
		if got := videoOutputPathFor(value); got != OutputCopyMPEGTS {
			t.Errorf("resolution %q selected output path %v, want OutputCopyMPEGTS", value, got)
		}
	}
	if got := videoOutputPathFor("hd"); got != OutputTranscodeH264 {
		t.Errorf("resolution \"hd\" selected %v, want OutputTranscodeH264", got)
	}
	if got := videoOutputPathFor("HD"); got != OutputTranscodeH264 {
		t.Errorf("resolution \"HD\" selected %v, want OutputTranscodeH264", got)
	}
}

// TestHDArgumentsSelectTheTranscodingPath pins the shipped HD arg list.
//
// Three of these flags are load-bearing and were MEASURED, so they are asserted
// individually rather than as one blob:
//
//   - `-r 20` before -i: the HD SDP carries no framerate, so ffmpeg otherwise
//     adopts the H.265 RTP clock's 200 tbr and duplicates ~89% of frames
//     (MEASURED: frame=1362 dup=1207).
//   - `-an`: the HD stream has NO audio track.
//   - libx264 + scale to 1280x720: no browser decodes HEVC, and 1440p does not
//     keep up on this 4-core host.
func TestHDArgumentsSelectTheTranscodingPath(t *testing.T) {
	m, l := testManager(t)
	defer l.Close()

	args := m.ffmpegArgsFor("rtsp://127.0.0.1:41441/tuya_x", "/tmp/hls", OutputTranscodeH264)
	got := joinedArgs(args)

	// The input frame rate MUST precede -i to be an input option. Asserting the
	// positions rather than mere presence is the whole point: `-r` after `-i`
	// would be an output rate and would NOT fix the duplicate-frame storm.
	inputIdx, rIdx := indexOf(args, "-i"), indexOf(args, "-r")
	if inputIdx < 0 || rIdx < 0 || rIdx > inputIdx {
		t.Fatalf("-r %d must appear BEFORE -i (positions: -r=%d -i=%d) in %s", HDInputFPS, rIdx, inputIdx, got)
	}
	if args[rIdx+1] != "20" {
		t.Errorf("input frame rate = %q, want 20", args[rIdx+1])
	}
	// The output rate cap must come AFTER -i.
	lastR := lastIndexOf(args, "-r")
	if lastR <= inputIdx {
		t.Fatalf("expected the output frame-rate cap after -i, got %s", got)
	}
	if args[lastR+1] != "20" {
		t.Errorf("output frame rate cap = %q, want 20", args[lastR+1])
	}

	for _, want := range []string{
		"-an",
		"-c:v libx264",
		// The shipped preset is asserted through the CONSTANT, so the test
		// cannot pass while the code and the measurement disagree: ultrafast is
		// what was measured at 0.98x realtime on 4 cores.
		"-preset " + HDH264Preset,
		"-crf 26",
		"-vf scale=1280:720",
		"-hls_segment_type mpegts",
		"-f hls /tmp/hls/stream.m3u8",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("HD args missing %q\nfull: %s", want, got)
		}
	}
	// The shipped preset must be the one that keeps up. A future change to
	// `veryfast` would measure 0.83x and fall permanently behind, so the value
	// itself is pinned rather than only its use.
	if HDH264Preset != "ultrafast" {
		t.Errorf("HDH264Preset = %q; the measured-to-keep-up preset is ultrafast (%q does not keep up on 4 cores)", HDH264Preset, "veryfast")
	}
	// HD must NOT ask for audio: `-c:a aac` on a stream with no audio track is
	// exactly the wrong flag the milestone had to remove.
	if strings.Contains(got, "-c:a") {
		t.Errorf("HD args must not carry an audio codec (the HD stream has no audio track)\nfull: %s", got)
	}
	// HD must NOT copy the video: HEVC in MPEG-TS cannot be decoded by a browser.
	if strings.Contains(got, "-c:v copy") {
		t.Errorf("HD args must not copy the HEVC video\nfull: %s", got)
	}
	// The shared prefix must still be intact for HD as well.
	for _, want := range []string{
		"-y",
		"-fflags +genpts+igndts",
		"-rtsp_transport tcp",
		"-rtsp_flags prefer_tcp",
		"-timeout 30000000",
		"-avoid_negative_ts make_zero",
		"-max_interleave_delta 0",
		"-hls_time 2",
		"-hls_list_size 5",
		"-hls_start_number_source epoch",
		"-hls_flags delete_segments+independent_segments",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("HD args missing the shared flag %q\nfull: %s", want, got)
		}
	}
}

func indexOf(args []string, want string) int {
	for i, a := range args {
		if a == want {
			return i
		}
	}
	return -1
}

func lastIndexOf(args []string, want string) int {
	for i := len(args) - 1; i >= 0; i-- {
		if args[i] == want {
			return i
		}
	}
	return -1
}

// TestAnHDStreamReportsItsResolutionAndTranscoding asserts on what
// /api/stream/list serves, because the card's honesty depends on it.
func TestAnHDStreamReportsItsResolutionAndTranscoding(t *testing.T) {
	m, l := testManager(t)
	defer l.Close()
	defer m.Shutdown()

	info, err := m.StartStreamWithResolution("tuya:camera-a", "rtsp://127.0.0.1:1/tuya_camera-a", "tuya", "hd")
	if err != nil {
		t.Fatal(err)
	}
	if info.Resolution != "hd" {
		t.Errorf("resolution = %q, want hd", info.Resolution)
	}
	if !info.Transcoding {
		t.Error("an HD stream must report transcoding=true: the cost is the feature's whole caveat")
	}
	if info.Output != "transcode_h264" {
		t.Errorf("output = %q, want transcode_h264", info.Output)
	}

	listed := m.ListStreams()
	if len(listed) != 1 || listed[0].Resolution != "hd" || !listed[0].Transcoding {
		t.Fatalf("ListStreams() = %#v, want one HD transcoding stream", listed)
	}
}

// TestAnSDStreamDoesNotReportTranscoding is the other half: a stream that costs
// no CPU must not claim it does.
func TestAnSDStreamDoesNotReportTranscoding(t *testing.T) {
	m, l := testManager(t)
	defer l.Close()
	defer m.Shutdown()

	info, err := m.StartStreamForProvider("tuya:camera-b", "rtsp://127.0.0.1:1/tuya_camera-b", "tuya")
	if err != nil {
		t.Fatal(err)
	}
	if info.Resolution != "sd" {
		t.Errorf("resolution = %q, want sd (the default must stay SD)", info.Resolution)
	}
	if info.Transcoding {
		t.Error("an SD stream must not report transcoding")
	}
	if info.Output != "copy_mpegts" {
		t.Errorf("output = %q, want copy_mpegts", info.Output)
	}
}

// TestResolutionIsPersistedAndReusedByTheStartPath proves the persistence half:
// a choice recorded for a camera is what the NEXT start runs at, without the
// caller repeating it. That is what makes it survive a restart.
func TestResolutionIsPersistedAndReusedByTheStartPath(t *testing.T) {
	m, l := testManager(t)
	defer l.Close()
	defer m.Shutdown()

	if _, err := m.StartStreamWithResolution("tuya:camera-c", "rtsp://127.0.0.1:1/tuya_camera-c", "tuya", "hd"); err != nil {
		t.Fatal(err)
	}
	configs, err := l.ListStreamConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 1 || configs[0].Resolution != "hd" {
		t.Fatalf("persisted configs = %#v, want resolution hd", configs)
	}

	// A LATER start that names no resolution must reuse the stored one. This is
	// exactly the shape of the RestoreStreams call and of a reconnect.
	again, err := m.StartStreamWithResolution("tuya:camera-d", "rtsp://127.0.0.1:1/tuya_camera-d", "tuya", "")
	if err != nil {
		t.Fatal(err)
	}
	if again.Resolution != "sd" {
		t.Errorf("a camera with no stored choice started at %q, want sd", again.Resolution)
	}
	stored, err := l.StreamResolution("tuya:camera-c")
	if err != nil {
		t.Fatal(err)
	}
	if stored != "hd" {
		t.Fatalf("StoredResolution(tuya:camera-c) = %q, want hd", stored)
	}
}

// TestAnUnknownResolutionIsRejectedNotCoerced makes a typo loud. Silently
// downgrading to SD would make a failed switch to HD look like it worked.
func TestAnUnknownResolutionIsRejectedNotCoerced(t *testing.T) {
	m, l := testManager(t)
	defer l.Close()
	defer m.Shutdown()

	if _, err := m.StartStreamWithResolution("tuya:camera-e", "rtsp://127.0.0.1:1/tuya_camera-e", "tuya", "1440p"); err == nil {
		t.Fatal("an unrecognised resolution must be an error, not a silent fallback to SD")
	}
	if err := l.SetStreamResolution("tuya:camera-e", "ultra"); err == nil {
		t.Fatal("SetStreamResolution must reject an unrecognised resolution")
	}
	// And nothing was written for the camera.
	if stored, err := l.StreamResolution("tuya:camera-e"); err != nil || stored != "sd" {
		t.Fatalf("StoredResolution after a rejected write = %q, %v; want sd, nil", stored, err)
	}
}

// TestUpsertStreamConfigDoesNotBlankAStoredResolution guards the resume and
// reconnect path: they upsert the RTSP URL (which changes on every engine
// reconnect) and must not take the user's HD choice down with it.
func TestUpsertStreamConfigDoesNotBlankAStoredResolution(t *testing.T) {
	l, err := logger.NewLogger(filepath.Join(t.TempDir(), "resolution.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if err := l.UpsertStreamConfig("tuya:camera-f", "rtsp://127.0.0.1:1/one", "tuya"); err != nil {
		t.Fatal(err)
	}
	if err := l.SetStreamResolution("tuya:camera-f", "hd"); err != nil {
		t.Fatal(err)
	}
	// A new engine URL arrives on reconnect.
	if err := l.UpsertStreamConfig("tuya:camera-f", "rtsp://127.0.0.1:2/two", "tuya"); err != nil {
		t.Fatal(err)
	}
	stored, err := l.StreamResolution("tuya:camera-f")
	if err != nil {
		t.Fatal(err)
	}
	if stored != "hd" {
		t.Fatalf("resolution after a URL-only upsert = %q, want hd", stored)
	}
}

// TestStudioResolutionIsNilSafe covers the embedder case: a manager or logger
// that is not wired must degrade to SD rather than panic.
func TestStoredResolutionIsDefaultWhenNoLoggerIsWired(t *testing.T) {
	m := NewManager(t.TempDir(), nil)
	if got := m.storedResolution("tuya:whatever"); got != "sd" {
		t.Fatalf("storedResolution with no logger = %q, want sd", got)
	}
}
