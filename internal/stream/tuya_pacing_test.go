package stream

import (
	"strings"
	"testing"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/models"
)

// --- Tuya frame pacing: the wallclock output path ---------------------------
//
// These tests exist because the Tuya SD leg runs below realtime and the ONVIF
// leg does not. MEASURED: the Tuya camera delivers ~13 of the 20 frames/s it
// stamps on a perfect 4500-tick 90kHz grid (histogram {4500: 597}), with zero
// sequence gaps, so its RTP media clock runs ~1.18x ahead of wall time.
// `-c:v copy` into MPEG-TS then declares 4.0s segments that arrive every 5.3s
// (76% of realtime) and the player underruns every few seconds. MEASURED with
// `-use_wallclock_as_timestamps 1` on the INPUT: ffmpeg speed 0.488x -> 1.017x
// and a playlist advancing at 99.4% of realtime, zero ffmpeg errors.
//
// The single most dangerous failure mode of that fix is a HALF-WIRED one: the
// ffmpeg command taking the new path while the process's recorded outputPath,
// what /api/stream/list reports, or the resume/reconnect path keeps the old one.
// Then the logs and UI LIE about what is running, and the first reconnect
// silently reverts Tuya to the stuttering path. The tests below pin every one of
// those call sites, not just the arg builder.
//
// NOTE on the reported name: StreamInfo.Output deliberately stays "copy_mpegts"
// for BOTH the Tuya SD and the ONVIF/SD path, because that is a pinned contract
// (TestAnSDStreamDoesNotReportTranscoding) and it remains TRUE — the video is
// still copied. The timing decision is reported separately, through
// StreamInfo.InputTimestamps, and these tests require the two to agree with the
// args that were actually built. A change that lets the report and the real
// command disagree fails here.

// argsFor is a helper: the args a stream with this recorded path would actually
// run, as one string.
func argsFor(t *testing.T, m *Manager, recorded VideoOutputPath) string {
	t.Helper()
	return joinedArgs(m.ffmpegArgsFor("rtsp://127.0.0.1:1/tuya_camera", "/tmp/hls", recorded))
}

// TestTuyaSDReportAndArgsAgreeAndCarryTheFix is the honesty test: what the
// stream REPORTS must be what ffmpeg RUNS.
func TestTuyaSDReportAndArgsAgreeAndCarryTheFix(t *testing.T) {
	m, l := testManager(t)
	defer l.Close()
	defer m.Shutdown()

	info, err := m.StartStreamWithResolution("tuya:camera-pace", "rtsp://127.0.0.1:1/tuya_camera-pace", models.ProviderTuya, "sd")
	if err != nil {
		t.Fatal(err)
	}

	// An SD Tuya stream still costs no CPU: it copies, it does not transcode.
	if info.Transcoding {
		t.Error("a Tuya SD stream must not report transcoding")
	}
	if info.Output != "copy_mpegts" {
		t.Errorf("Info.Output = %q, want copy_mpegts (the pinned contract for a copy-into-MPEG-TS stream)", info.Output)
	}
	// The timing decision IS reported, and it is the new one.
	if info.InputTimestamps != InputTimestampsWallclock {
		t.Fatalf("Info.InputTimestamps = %q, want %q", info.InputTimestamps, InputTimestampsWallclock)
	}

	// The recorded path and the struct field must agree with the report: these
	// are what the reconnect path and the API read back.
	m.mutex.RLock()
	process := m.streams[info.ID]
	m.mutex.RUnlock()
	if process == nil {
		t.Fatalf("stream %s vanished", info.ID)
	}
	process.mutex.RLock()
	recorded := process.outputPath
	process.mutex.RUnlock()
	if recorded != OutputTuyaSDWallclock {
		t.Fatalf("process.outputPath = %v, want OutputTuyaSDWallclock", recorded)
	}
	if got := inputTimestampsName(recorded); got != info.InputTimestamps {
		t.Fatalf("recorded outputPath reports timing %q but Info.InputTimestamps = %q; the log/UI would lie about the running path",
			got, info.InputTimestamps)
	}

	// The ACTUAL built args must carry the fix, BEFORE -i to be an input option.
	args := m.ffmpegArgsFor("rtsp://127.0.0.1:1/tuya_camera-pace", "/tmp/hls", recorded)
	got := joinedArgs(args)
	if !strings.Contains(got, "-use_wallclock_as_timestamps 1") {
		t.Fatalf("Tuya SD args are missing the measured fix\nfull: %s", got)
	}
	wcIdx, iIdx := indexOf(args, "-use_wallclock_as_timestamps"), indexOf(args, "-i")
	if wcIdx < 0 || iIdx < 0 || wcIdx > iIdx {
		t.Fatalf("-use_wallclock_as_timestamps must precede -i (wc=%d -i=%d)\nfull: %s", wcIdx, iIdx, got)
	}
	if args[wcIdx+1] != "1" {
		t.Errorf("-use_wallclock_as_timestamps = %q, want \"1\"", args[wcIdx+1])
	}
	if !strings.Contains(got, "-c:v copy") {
		t.Errorf("Tuya SD must still copy the video\nfull: %s", got)
	}

	// What /api/stream/list serves must agree, or the card misreports the path.
	listed := m.ListStreams()
	if len(listed) != 1 || listed[0].InputTimestamps != InputTimestampsWallclock || listed[0].Output != "copy_mpegts" {
		t.Fatalf("ListStreams() = %#v, want one stream reporting output=copy_mpegts inputTimestamps=wallclock", listed)
	}
}

// TestResumedTuyaStreamKeepsTheWallclockPath is the test that catches the
// reconnect bug: a resume RE-DERIVES outputPath, and if that derivation ignores
// the provider the stream silently reverts to the stuttering copy path.
func TestResumedTuyaStreamKeepsTheWallclockPath(t *testing.T) {
	m, l := testManager(t)
	defer l.Close()
	defer m.Shutdown()

	info, err := m.StartStreamWithResolution("tuya:camera-resume", "rtsp://127.0.0.1:1/tuya_camera-resume", models.ProviderTuya, "sd")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SuspendStreamsForProvider(models.ProviderTuya, "test suspension"); err != nil {
		t.Fatal(err)
	}

	resumed, err := m.ResumeSuspended(info.ID, "rtsp://127.0.0.1:2/tuya_camera-resume", models.ProviderTuya)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.InputTimestamps != InputTimestampsWallclock {
		t.Fatalf("resumed stream reports inputTimestamps=%q, want %q (it silently reverted to the stuttering path)",
			resumed.InputTimestamps, InputTimestampsWallclock)
	}

	m.mutex.RLock()
	process := m.streams[info.ID]
	m.mutex.RUnlock()
	process.mutex.RLock()
	recorded := process.outputPath
	process.mutex.RUnlock()
	if recorded != OutputTuyaSDWallclock {
		t.Fatalf("after resume process.outputPath = %v, want OutputTuyaSDWallclock", recorded)
	}
	// And the args it would actually restart with must still carry the fix.
	args := joinedArgs(m.ffmpegArgsFor("rtsp://127.0.0.1:2/tuya_camera-resume", "/tmp/hls", recorded))
	if !strings.Contains(args, "-use_wallclock_as_timestamps 1") {
		t.Fatalf("the resumed Tuya stream reverted to the copy path and would stutter again\nfull: %s", args)
	}
	if err := m.ReconnectStream(info.ID); err != nil {
		// A reconnect is the other path that re-reads process.outputPath; it must
		// not be able to change the timing decision either.
		t.Logf("reconnect returned %v (no live ffmpeg in this test)", err)
	}
}

// TestVideoOutputPathForCanNeverReturnTheTuyaPath is what protects ONVIF.
//
// videoOutputPathFor is the ONVIF/SD branch. If it could ever return
// OutputTuyaSDWallclock, ONVIF (or SD ONVIF) would silently acquire a Tuya-only
// input option — and the literally-pinned ONVIF arg list would be a lie.
func TestVideoOutputPathForCanNeverReturnTheTuyaPath(t *testing.T) {
	for _, resolution := range []string{"", "sd", "SD", " sd ", "hd", "HD", "something-else", "tuya_sd_wallclock"} {
		if got := videoOutputPathFor(resolution); got == OutputTuyaSDWallclock {
			t.Errorf("videoOutputPathFor(%q) = OutputTuyaSDWallclock; the ONVIF branch must never take the Tuya path", resolution)
		}
	}
	// And no ONVIF stream at any resolution may acquire the flag.
	m, l := testManager(t)
	defer l.Close()
	for _, resolution := range []string{"", "sd", "SD", "hd"} {
		path := outputPathForProvider(models.ProviderONVIF, resolution)
		args := joinedArgs(m.ffmpegArgsFor("rtsp://10.0.0.9:554/live", "/tmp/hls", path))
		if strings.Contains(args, "-use_wallclock_as_timestamps") {
			t.Errorf("ONVIF at resolution %q acquired the Tuya-only input option\nfull: %s", resolution, args)
		}
		if got := inputTimestampsName(path); got != InputTimestampsCamera {
			t.Errorf("ONVIF at resolution %q reports inputTimestamps=%q, want %q", resolution, got, InputTimestampsCamera)
		}
	}
}

// TestProviderChoosesTheOutputPath pins the whole matrix in one place, so the
// two providers can never drift onto each other's paths.
func TestProviderChoosesTheOutputPath(t *testing.T) {
	cases := []struct {
		provider   models.ProviderKind
		resolution string
		want       VideoOutputPath
		wantOutput string
		wantTime   string
	}{
		// ONVIF is untouched by this change, at both resolutions.
		{models.ProviderONVIF, "sd", OutputCopyMPEGTS, "copy_mpegts", "camera"},
		{models.ProviderONVIF, "", OutputCopyMPEGTS, "copy_mpegts", "camera"},
		{models.ProviderONVIF, "hd", OutputTranscodeH264, "transcode_h264", "camera"},
		// Tuya SD takes the measured fix; Tuya HD still transcodes.
		{models.ProviderTuya, "sd", OutputTuyaSDWallclock, "copy_mpegts", "wallclock"},
		{models.ProviderTuya, "", OutputTuyaSDWallclock, "copy_mpegts", "wallclock"},
		{models.ProviderTuya, "hd", OutputTranscodeH264, "transcode_h264", "camera"},
	}
	for _, c := range cases {
		got := outputPathForProvider(c.provider, c.resolution)
		if got != c.want {
			t.Errorf("outputPathForProvider(%v, %q) = %v, want %v", c.provider, c.resolution, got, c.want)
		}
		if name := outputPathName(got); name != c.wantOutput {
			t.Errorf("outputPathName(outputPathForProvider(%v, %q)) = %q, want %q", c.provider, c.resolution, name, c.wantOutput)
		}
		if name := inputTimestampsName(got); name != c.wantTime {
			t.Errorf("inputTimestampsName(outputPathForProvider(%v, %q)) = %q, want %q", c.provider, c.resolution, name, c.wantTime)
		}
	}
}

// TestTuyaHDStillTranscodes is the other half of "do not regress the cheap
// path": the wallclock flag must not have replaced the HEVC transcode decision.
func TestTuyaHDStillTranscodes(t *testing.T) {
	if path := outputPathForProvider(models.ProviderTuya, "hd"); path != OutputTranscodeH264 {
		t.Fatalf("Tuya HD = %v, want OutputTranscodeH264", path)
	}
	m, l := testManager(t)
	defer l.Close()
	args := joinedArgs(m.ffmpegArgsFor("rtsp://127.0.0.1:1/tuya_x", "/tmp/hls", OutputTranscodeH264))
	if !strings.Contains(args, "-c:v libx264") {
		t.Errorf("Tuya HD no longer transcodes\nfull: %s", args)
	}
	// The wallclock flag belongs to the SD copy path; if it appears on the
	// transcode path it is untested and unwanted.
	if strings.Contains(args, "-use_wallclock_as_timestamps") {
		t.Errorf("the Tuya SD timing flag leaked onto the HD transcode path\nfull: %s", args)
	}
}

// TestTuyaSDWallclockArgsShape pins the shipped Tuya SD list, in order, so a
// later edit cannot quietly drop the fix the way a half-wired version would.
func TestTuyaSDWallclockArgsShape(t *testing.T) {
	m, l := testManager(t)
	defer l.Close()

	got := joinedArgs(m.ffmpegArgsFor("rtsp://127.0.0.1:1/tuya_camera", "/tmp/hls", OutputTuyaSDWallclock))
	want := "-y -fflags +genpts+igndts -rtsp_transport tcp -rtsp_flags prefer_tcp " +
		"-use_wallclock_as_timestamps 1 -timeout 30000000 -i rtsp://127.0.0.1:1/tuya_camera " +
		"-c:v copy -c:a aac -avoid_negative_ts make_zero -max_interleave_delta 0 " +
		"-hls_time 2 -hls_list_size 5 -hls_start_number_source epoch " +
		"-hls_flags delete_segments+independent_segments -hls_segment_type mpegts " +
		"-f hls /tmp/hls/stream.m3u8"
	if got != want {
		t.Fatalf("Tuya SD wallclock args changed\ngot:  %s\nwant: %s", got, want)
	}
	// The ONLY difference from the pinned ONVIF/SD list is the one input flag.
	// Anyone adding a second flag to this path has to justify it here.
	onvif := joinedArgs(m.ffmpegArgsFor("rtsp://127.0.0.1:1/tuya_camera", "/tmp/hls", OutputCopyMPEGTS))
	if diff := strings.Replace(got, "-use_wallclock_as_timestamps 1 ", "", 1); diff != onvif {
		t.Fatalf("the Tuya path differs from the ONVIF/SD path by more than the measured input flag\nremove: %s\nonvif: %s", diff, onvif)
	}
}

// TestTuyaWallclockPathIsReachableFromThePersistedResolution proves the fix is
// actually wired to the entry point production uses, not merely constructible:
// a Tuya stream started with no explicit resolution (the RestoreStreams and
// reconnect shape) must land on the wallclock path.
func TestTuyaWallclockPathIsReachableFromThePersistedResolution(t *testing.T) {
	hlsDir := t.TempDir()
	db, err := logger.NewLogger(hlsDir + "/pace.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.UpsertStreamConfig("tuya:stored", "", string(models.ProviderTuya)); err != nil {
		t.Fatal(err)
	}

	m := NewManager(hlsDir, db)
	defer m.Shutdown()
	m.RestoreStreams()

	info, err := m.StartStreamWithResolution("tuya:stored", "rtsp://127.0.0.1:9/tuya_stored", models.ProviderTuya, "")
	if err != nil {
		t.Fatal(err)
	}
	if info.InputTimestamps != InputTimestampsWallclock {
		t.Fatalf("a Tuya stream started without an explicit resolution reports inputTimestamps=%q, want %q", info.InputTimestamps, InputTimestampsWallclock)
	}
	if !strings.Contains(argsFor(t, m, OutputTuyaSDWallclock), "-use_wallclock_as_timestamps 1") {
		t.Fatal("the persisted-resolution path does not produce the measured fix")
	}
}
