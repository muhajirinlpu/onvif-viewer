package stream

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHLSOutputUnhealthyAfterGraceWhenPlaylistMissing(t *testing.T) {
	// A completely absent playlist is only treated as a stall once the run has
	// exceeded hlsStallTimeout PLUS the first-segment grace. This camera's HLS
	// muxer does not create stream.m3u8 until its first segment closes, which
	// can take 30-90s with -c:v copy; flagging it at hlsStallTimeout alone
	// caused the watchdog to kill a healthy start forever.
	now := time.Now()
	dir := t.TempDir()
	playlist := filepath.Join(dir, "missing.m3u8")

	// Within the grace window: not a stall.
	if hlsOutputUnhealthy(playlist, now, now.Add(-hlsStallTimeout-time.Second), hlsStallTimeout) {
		t.Fatal("missing playlist must NOT be unhealthy inside the first-segment grace")
	}
	// Past the grace window: a stall.
	past := now.Add(-(hlsStallTimeout + playlistFirstSegmentGrace + time.Second))
	if !hlsOutputUnhealthy(playlist, now, past, hlsStallTimeout) {
		t.Fatal("missing playlist must be unhealthy past the first-segment grace")
	}
}

func TestHLSRunUnhealthyIgnoresMissingPlaylistWhenSegmentsAdvance(t *testing.T) {
	// The real behaviour of this camera: no playlist yet, but .ts files being
	// produced. That is PROGRESS, not a stall.
	dir := t.TempDir()
	segment := filepath.Join(dir, "stream123.ts")
	if err := os.WriteFile(segment, []byte("ts"), 0o644); err != nil {
		t.Fatal(err)
	}
	var last time.Time
	var lastName string
	now := time.Now()
	if hlsRunUnhealthy(dir, &last, &lastName, now, now.Add(-10*time.Minute), hlsStallTimeout) {
		t.Fatal("segments advancing without a playlist must count as healthy")
	}
	if lastName == "" {
		t.Fatal("newest segment name should have been recorded")
	}
}

func TestHLSRunUnhealthyDetectsStallAfterOutputStarts(t *testing.T) {
	dir := t.TempDir()
	segment := filepath.Join(dir, "stream123.ts")
	if err := os.WriteFile(segment, []byte("ts"), 0o644); err != nil {
		t.Fatal(err)
	}
	last := time.Now().Add(-10 * time.Minute)
	lastName := "stream123.ts" // no new segment has appeared since
	if !hlsRunUnhealthy(dir, &last, &lastName, time.Now(), time.Now(), hlsStallTimeout) {
		t.Fatal("no new segment name within the timeout must be a stall")
	}
}

func TestHLSRunUnhealthyCountsNewSegmentNameAsProgress(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"stream100.ts", "stream200.ts", "stream300.ts"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("ts"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var last time.Time
	var lastName string
	now := time.Now()
	// First call adopts stream300.ts as the baseline.
	if hlsRunUnhealthy(dir, &last, &lastName, now, now.Add(-10*time.Minute), hlsStallTimeout) {
		t.Fatal("first observation must not be a stall")
	}
	if lastName != "stream300.ts" {
		t.Fatalf("expected newest name stream300.ts, got %q", lastName)
	}
	// A newer segment appearing resets the stall clock even if the previous
	// baseline was already older than the timeout.
	last = now.Add(-10 * time.Minute)
	if err := os.WriteFile(filepath.Join(dir, "stream400.ts"), []byte("ts"), 0o644); err != nil {
		t.Fatal(err)
	}
	if hlsRunUnhealthy(dir, &last, &lastName, now, now, hlsStallTimeout) {
		t.Fatal("a new segment name must count as progress")
	}
}

func TestRedactSensitiveTextRemovesRTSPUserInfo(t *testing.T) {
	got := redactSensitiveText("open rtsp://alice:secret@camera/live failed")
	if got != "open rtsp://REDACTED@camera/live failed" {
		t.Fatalf("got %q", got)
	}
}

func TestDiagnoseReachabilityDistinguishesRTSPAndONVIF(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	rtspURL := "rtsp://user:secret@" + listener.Addr().String() + "/live"
	detail := diagnoseReachability(rtspURL, "127.0.0.1:1", 100*time.Millisecond)
	if !strings.Contains(detail, "camera host reachable") || !strings.Contains(detail, "RTSP port reachable") || !strings.Contains(detail, "ONVIF port unreachable") {
		t.Fatalf("unexpected diagnosis: %q", detail)
	}
	if strings.Contains(detail, "secret") || strings.Contains(detail, "user") {
		t.Fatalf("credentials leaked: %q", detail)
	}
}
