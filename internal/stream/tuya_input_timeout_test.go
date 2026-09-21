package stream

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// --- The Tuya "reconnecting forever" regression -----------------------------
//
// A Tuya stream is served by the in-process engine over loopback. On a fresh
// RTSP connection the engine returns nothing until it has finished its WebRTC
// handshake with the cloud and received a keyframe: MEASURED 14.3s to the first
// HLS segment (engine-internal start ~6s).
//
// The ffmpeg input I/O timeout used to be 5s, which killed that healthy stream
// 6s in with "Failed reading RTSP data: Connection timed out". ffmpeg's
// open-failure exit made the manager count it as a failed attempt, so the card
// showed "reconnecting" indefinitely while the engine was fine. These tests
// exist so that value can never be quietly tightened back into a false failure.

// tuyaMeasuredFirstSegmentLatency is the measured time from ffmpeg start to the
// first HLS segment on the ES06 Tuya camera. Recorded as the basis for the
// input timeout; if this measurement changes, change it here and justify it.
const tuyaMeasuredFirstSegmentLatency = 14300 * time.Millisecond

func TestInputIOTimeoutIsGenerousEnoughForTuyaStartup(t *testing.T) {
	// The whole point of the bug: the bound must comfortably exceed the measured
	// cold-start latency, or a healthy Tuya stream is killed before it produces
	// anything. A strict ">" is not enough -- a limit that only just clears the
	// measurement would still fail on a slower handshake.
	if ffmpegInputIOTimeout <= tuyaMeasuredFirstSegmentLatency {
		t.Fatalf("ffmpegInputIOTimeout (%s) does not exceed the measured Tuya first-segment latency (%s); a healthy stream would be killed before it produces output",
			ffmpegInputIOTimeout, tuyaMeasuredFirstSegmentLatency)
	}
	if margin := ffmpegInputIOTimeout - tuyaMeasuredFirstSegmentLatency; margin < 10*time.Second {
		t.Fatalf("ffmpegInputIOTimeout (%s) clears the measured start by only %s; leave real headroom for a slower cloud handshake",
			ffmpegInputIOTimeout, margin)
	}
	// And it must stay far below the stall detector, which owns "connected but
	// silent". If the input timeout ever approached hlsStallTimeout the two
	// would fight, and a genuine stall would be reported as an input error.
	if ffmpegInputIOTimeout >= hlsStallTimeout {
		t.Fatalf("ffmpegInputIOTimeout (%s) must stay well below hlsStallTimeout (%s): the watchdog owns the stall case",
			ffmpegInputIOTimeout, hlsStallTimeout)
	}
}

func TestFFmpegArgsCarryTheInputIOTimeoutInMicroseconds(t *testing.T) {
	m, l := testManager(t)
	defer l.Close()

	want := strconv.FormatInt(ffmpegInputIOTimeout.Microseconds(), 10)
	for _, path := range []VideoOutputPath{OutputCopyMPEGTS, OutputTranscodeH264} {
		args := m.ffmpegArgsFor("rtsp://127.0.0.1:41441/tuya_x", "/tmp/hls", path)
		joined := strings.Join(args, " ")

		idx := -1
		for i, a := range args {
			if a == "-timeout" {
				idx = i
				break
			}
		}
		if idx < 0 || idx+1 >= len(args) {
			t.Fatalf("%v: no -timeout value found in %q", path, joined)
		}
		if got := args[idx+1]; got != want {
			t.Fatalf("%v: -timeout = %q, want %q (microseconds of %s)", path, got, want, ffmpegInputIOTimeout)
		}
		// The old bug shipped the literal 5s. Guard against it reappearing.
		if args[idx+1] == "5000000" {
			t.Fatalf("%v: the 5s input timeout is back; it kills a healthy Tuya start", path)
		}
		// -timeout must precede -i: it is an INPUT option, so after -i it would
		// silently apply to the output side and do nothing useful.
		iIdx := -1
		for i, a := range args {
			if a == "-i" {
				iIdx = i
				break
			}
		}
		if iIdx >= 0 && idx > iIdx {
			t.Fatalf("%v: -timeout appears after -i, where it does not bound the input: %q", path, joined)
		}
	}
}

// TestDiagnoseReachabilityDoesNotBlameTheCameraOnALoopbackSource covers the
// second half of the same user-visible bug. The Tuya source is 127.0.0.1 (the
// in-process engine), but the diagnostic probed "the camera's" RTSP and ONVIF
// ports -- which a Tuya camera does not expose -- and reported "camera host
// reachable; RTSP port reachable; ONVIF port unreachable", reading as a camera
// fault. On this path the engine is what must be reported.
func TestDiagnoseReachabilityDoesNotBlameTheCameraOnALoopbackSource(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not open a listener to stand in for the engine: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	got := diagnoseReachability("rtsp://127.0.0.1:"+strconv.Itoa(port)+"/tuya_x", "", 2*time.Second)
	if strings.Contains(got, "ONVIF port unreachable") {
		t.Fatalf("a loopback Tuya source must not be diagnosed against the camera's ONVIF port: %q", got)
	}
	if !strings.Contains(got, "engine") {
		t.Fatalf("the loopback diagnosis should name the in-process engine, got %q", got)
	}
	if !strings.Contains(got, "reachable") {
		t.Fatalf("a listening engine port should be reported reachable, got %q", got)
	}

	// A dead loopback port must say the ENGINE is unreachable, not the camera.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not reserve a dead port: %v", err)
	}
	deadPort := dead.Addr().(*net.TCPAddr).Port
	dead.Close()

	got = diagnoseReachability("rtsp://127.0.0.1:"+strconv.Itoa(deadPort)+"/tuya_x", "", 2*time.Second)
	if !strings.Contains(got, "engine") || !strings.Contains(got, "unreachable") {
		t.Fatalf("a dead loopback port should report the engine unreachable, got %q", got)
	}
	if strings.Contains(got, "camera host reachable") {
		t.Fatalf("a dead loopback source must not claim the camera host is reachable: %q", got)
	}

	// A REAL LAN camera must keep the original diagnosis: this change must not
	// swallow the ONVIF port report for the path that actually has those ports.
	got = diagnoseReachability("rtsp://10.255.255.1:554/live", "10.255.255.1:8000", 300*time.Millisecond)
	if !strings.Contains(got, "ONVIF port") {
		t.Fatalf("a LAN camera must still report its ONVIF port state, got %q", got)
	}
	// A LOOPBACK source that carries an ONVIF endpoint is a real camera reached
	// over loopback (tunnel/port-forward), not the engine, so its ONVIF port
	// must still be reported. This is why the engine branch also requires the
	// ONVIF address to be empty.
	got = diagnoseReachability("rtsp://127.0.0.1:554/live", "127.0.0.1:8000", 300*time.Millisecond)
	if !strings.Contains(got, "ONVIF port") {
		t.Fatalf("a loopback camera WITH an ONVIF endpoint must still report its ONVIF port, got %q", got)
	}
	if strings.Contains(got, "engine") {
		t.Fatalf("a loopback camera WITH an ONVIF endpoint must not be called the engine: %q", got)
	}
}
