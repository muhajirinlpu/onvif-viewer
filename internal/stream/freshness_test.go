package stream

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/models"
)

// The fixture is an advancing HLS playlist, not a simulated camera consumer.
func freshnessPlaylist(t *testing.T, dir string, seq int, seconds float64, discontinuity bool) {
	t.Helper()
	content := fmt.Sprintf("#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:%d\n", seq)
	for i := seq; i < seq+5; i++ {
		if discontinuity && i == seq+4 {
			content += "#EXT-X-DISCONTINUITY\n"
		}
		content += fmt.Sprintf("#EXTINF:%.6f,\nstream%d.ts\n", seconds, i)
	}
	for i := seq; i < seq+5; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("stream%d.ts", i)), []byte("synthetic segment"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "stream.m3u8"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestAdvancingHLSCanAccumulateDriftAndRecoverOnlyTuya(t *testing.T) {
	base := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	var tuya, onvif hlsFreshness
	for i := 0; i <= 130; i++ {
		now := base.Add(time.Duration(i) * 6 * time.Second)
		freshnessPlaylist(t, dir, i, 7, false)
		a := tuya.observe(dir, now, models.ProviderTuya)
		b := onvif.observe(dir, now, models.ProviderONVIF)
		if b.recover {
			t.Fatal("ONVIF must never auto-reconnect for this metric")
		}
		if i < 122 && a.recover {
			t.Fatalf("premature recovery at %d: %+v", i, a)
		}
		if i == 122 {
			if !a.recover {
				t.Fatalf("advancing output drifted 122 seconds with no recovery: %+v", a)
			}
			if a.driftSeconds < 120 {
				t.Fatalf("drift = %v, want >120 seconds", a.driftSeconds)
			}
		}
	}
}

func TestFreshnessSteadySourceGapDiscontinuityAndCooldown(t *testing.T) {
	base := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	var f hlsFreshness
	freshnessPlaylist(t, dir, 1, 6, false)
	f.observe(dir, base, models.ProviderTuya)
	for i := 2; i <= 110; i++ {
		freshnessPlaylist(t, dir, i, 6, false)
		s := f.observe(dir, base.Add(time.Duration(i-1)*6*time.Second), models.ProviderTuya)
		if s.recover || s.driftSeconds > 1 || s.driftSeconds < -1 {
			t.Fatalf("steady sample %d: %+v", i, s)
		}
	}
	// A source gap is not positive drift and must re-anchor, not kill the stream.
	freshnessPlaylist(t, dir, 111, 6, false)
	s := f.observe(dir, base.Add(30*time.Minute), models.ProviderTuya)
	if s.recover || s.driftSeconds != 0 {
		t.Fatalf("source gap: %+v", s)
	}
	// An explicit discontinuity invalidates timing even if the playlist advances.
	freshnessPlaylist(t, dir, 112, 900, true)
	s = f.observe(dir, base.Add(30*time.Minute+6*time.Second), models.ProviderTuya)
	if s.recover || s.driftSeconds != 0 {
		t.Fatalf("timestamp discontinuity: %+v", s)
	}
	// Restart/cooldown cannot immediately re-trigger from a retained old playlist.
	f.resetRun(base.Add(31 * time.Minute))
	freshnessPlaylist(t, dir, 113, 900, false)
	s = f.observe(dir, base.Add(31*time.Minute+6*time.Second), models.ProviderTuya)
	if s.recover || s.driftSeconds != 0 {
		t.Fatalf("reset run: %+v", s)
	}
}

func TestFreshnessTruncatedPlaylistIsNotAValidTimingSample(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "stream0.ts"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stream.m3u8"), []byte("#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:0\n#EXTINF:7,\nstream0.ts"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := parseHLSClock(dir); ok {
		t.Fatal("partially written playlist accepted")
	}
}

func TestFreshnessAppendThenRotateCountsEachSegmentOnce(t *testing.T) {
	base := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	var f hlsFreshness
	a := map[int64]time.Duration{0: 6 * time.Second, 1: 6 * time.Second}
	b := map[int64]time.Duration{0: 6 * time.Second, 1: 6 * time.Second, 2: 6 * time.Second}
	c := map[int64]time.Duration{1: 6 * time.Second, 2: 6 * time.Second, 3: 6 * time.Second}
	f.observeWindow(0, a, base, models.ProviderTuya)
	f.observeWindow(0, b, base.Add(6*time.Second), models.ProviderTuya)
	s := f.observeWindow(1, c, base.Add(12*time.Second), models.ProviderTuya)
	if !s.valid || s.mediaSeconds != 12 || s.driftSeconds != 0 {
		t.Fatalf("appended then rotated double-counted segment: %+v", s)
	}
}

func TestFreshnessMissingPublishedSegmentInvalidatesMeasurement(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	var f hlsFreshness
	freshnessPlaylist(t, dir, 1, 6, false)
	f.observe(dir, base, models.ProviderTuya)
	freshnessPlaylist(t, dir, 2, 7, false)
	if err := os.Remove(filepath.Join(dir, "stream6.ts")); err != nil {
		t.Fatal(err)
	}
	s := f.observe(dir, base.Add(6*time.Second), models.ProviderTuya)
	if s.valid || s.recover {
		t.Fatalf("missing HLS media was counted: %+v", s)
	}
}

func TestFreshnessAdvancingTailWithoutSequenceRotation(t *testing.T) {
	base := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	var f hlsFreshness
	window := func(end int64) map[int64]time.Duration {
		m := map[int64]time.Duration{}
		for i := int64(0); i < end; i++ {
			m[i] = 7 * time.Second
		}
		return m
	}
	f.observeWindow(0, window(1), base, models.ProviderTuya)
	for i := int64(2); i <= 123; i++ {
		s := f.observeWindow(0, window(i), base.Add(time.Duration(i-1)*6*time.Second), models.ProviderTuya)
		if i == 123 && (!s.recover || s.driftSeconds < 120) {
			t.Fatalf("advancing append-only HLS was invisible: %+v", s)
		}
	}
}

func TestFreshnessTelemetryIsNotCaptureAge(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	var f hlsFreshness
	freshnessPlaylist(t, dir, 0, 6, false)
	s := f.observe(dir, base, models.ProviderTuya)
	if s.valid {
		t.Fatalf("one snapshot cannot measure a rate: %+v", s)
	}
	freshnessPlaylist(t, dir, 1, 6, false)
	s = f.observe(dir, base.Add(6*time.Second), models.ProviderTuya)
	if !s.valid || s.driftSeconds != 0 || s.wallSeconds != 6 || s.mediaSeconds != 6 {
		t.Fatalf("elapsed timing: %+v", s)
	}
}
