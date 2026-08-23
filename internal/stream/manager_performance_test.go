package stream

import (
	"encoding/json"
	"strings"

	"dengan.dev/camera-streamer/internal/models"
	"testing"
	"time"
)

func TestReconnectDelayUsesExponentialBackoff(t *testing.T) {
	tests := []struct {
		failures int
		want     time.Duration
	}{
		{1, 5 * time.Second},
		{2, 10 * time.Second},
		{3, 20 * time.Second},
		{4, 40 * time.Second},
		{5, 60 * time.Second},
		{20, 60 * time.Second},
	}
	for _, tt := range tests {
		if got := reconnectBackoff(tt.failures); got != tt.want {
			t.Fatalf("reconnectBackoff(%d) = %v, want %v", tt.failures, got, tt.want)
		}
	}
}

func TestStableRunResetsFailureCount(t *testing.T) {
	if got := nextReconnectFailureCount(7, 31*time.Second); got != 1 {
		t.Fatalf("stable run should reset failures to 1, got %d", got)
	}
	if got := nextReconnectFailureCount(7, 2*time.Second); got != 8 {
		t.Fatalf("short run should increment failures, got %d", got)
	}
}

func TestFFmpegLogFilterDropsRoutineBannerAndProgress(t *testing.T) {
	dropped := []string{
		"ffmpeg version 7.1.5 Copyright",
		"configuration: --prefix=/usr --enable-gpl",
		"libavutil      59. 39.100 / 59. 39.100",
		"Duration: N/A, start: 0.000000, bitrate: N/A",
		"frame= 123 fps=30 q=-1.0 size=1234kB time=00:00:04.00",
		"Press [q] to stop, [?] for help",
	}
	for _, line := range dropped {
		if shouldLogFFmpegLine(line) {
			t.Errorf("routine FFmpeg line should be dropped: %q", line)
		}
	}

	kept := []string{
		"Connection timed out",
		"Error opening input: Invalid data found",
		"deprecated pixel format used",
		"Stream mapping:",
	}
	for _, line := range kept {
		if !shouldLogFFmpegLine(line) {
			t.Errorf("important FFmpeg line should be kept: %q", line)
		}
	}
}

func TestSanitizeFFmpegArgsRedactsRTSPCredentials(t *testing.T) {
	args := []string{"-i", "rtsp://admin:secret@10.0.0.4:554/live", "-c:v", "copy"}
	got := strings.Join(sanitizeFFmpegArgs(args), " ")
	if strings.Contains(got, "secret") || strings.Contains(got, "admin") {
		t.Fatalf("credentials leaked in sanitized args: %s", got)
	}
	if !strings.Contains(got, "rtsp://REDACTED@10.0.0.4:554/live") {
		t.Fatalf("unexpected sanitized args: %s", got)
	}
}

func TestRedactSensitiveURLIsCaseInsensitiveAndWorksInsideLines(t *testing.T) {
	input := "Opening input RTSP://admin:secret@10.0.0.4:554/live failed"
	got := redactSensitiveText(input)
	if strings.Contains(got, "admin") || strings.Contains(got, "secret") {
		t.Fatalf("credentials leaked: %s", got)
	}
	if !strings.Contains(got, "RTSP://REDACTED@10.0.0.4:554/live") {
		t.Fatalf("unexpected redaction: %s", got)
	}
}

func TestStreamInfoSnapshotDoesNotExposeRTSPURL(t *testing.T) {
	info := models.StreamInfo{ID: "x", RtspURL: "rtsp://admin:secret@camera/live"}
	encoded, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "rtsp") || strings.Contains(string(encoded), "secret") {
		t.Fatalf("RTSP URL exposed in API JSON: %s", encoded)
	}
}

func TestFilteredLogWriterHandlesSplitLines(t *testing.T) {
	var lines []string
	w := &filteredLogWriter{handle: func(line string) { lines = append(lines, line) }}
	if _, err := w.Write([]byte("first line\nsecond")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(" line\n")); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[0] != "first line" || lines[1] != "second line" {
		t.Fatalf("unexpected lines: %#v", lines)
	}
}
