package stream

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/models"
)

// The tests in this file are the M9 regression guards for the SECOND half of the
// Tuya lifecycle defect. 862ed3b made a Tuya row store an EMPTY url and made
// restore resolve the live one from the engine -- correct, and pinned by
// tuya_restore_test.go. But nothing put the device back into the engine at boot,
// so restore asked about a device the engine had never heard of and correctly
// SKIPPED it. Measured live: 1 stream before a restart, 0 after.
//
// The tests below did NOT exist while the defect shipped, which is why the suite
// was green with a camera that vanished on every restart. They exercise the REAL
// RestoreStreams path (a real database row, a real manager, a real ffmpeg stub)
// rather than the resolver in isolation, because "the resolver works" was
// already true and the camera still did not come back.

// countingRestoreManager builds a manager whose ffmpeg is a stub, together with
// the logger that owns its database, so a test can restore real rows.
func countingRestoreManager(t *testing.T) (*Manager, *logger.Logger) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "ffmpeg-stub")
	if err := os.WriteFile(bin, []byte(stubFFmpeg), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := logger.NewLogger(filepath.Join(dir, "stream.db"))
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	m := NewManager(filepath.Join(dir, "hls"), db)
	m.ffmpegBin = bin
	t.Cleanup(func() {
		m.Shutdown()
		db.Close()
	})
	return m, db
}

// waitForStreams polls until the manager reports the wanted number of streams,
// or fails. RestoreStreams runs in a goroutine by design ("without delaying HTTP
// server startup"), so a test must wait for the effect rather than assume it.
func waitForStreams(t *testing.T, m *Manager, want int, timeout time.Duration) []models.StreamInfo {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last []models.StreamInfo
	for time.Now().Before(deadline) {
		last = m.ListStreams()
		if len(last) == want {
			return last
		}
		time.Sleep(20 * time.Millisecond)
	}
	ids := make([]string, 0, len(last))
	for _, s := range last {
		ids = append(ids, s.ID+"/"+string(s.Provider)+"/"+s.ProfileToken)
	}
	t.Fatalf("got %d stream(s) after %s, want %d: %v", len(last), timeout, want, ids)
	return nil
}

// TestRestoreStartsATuyaRowTheEngineKnows is the core M9 assertion: a Tuya row
// whose device IS registered in the engine must come back from RestoreStreams,
// as a Tuya stream, at the resolution that was stored.
//
// Before the fix this was the failing case: the stored row was correct (Tuya,
// empty url), the resolver was installed, and the camera still did not restore,
// because the engine had no entry for it. The row here is written the way a real
// run writes it (empty url, provider=tuya) and the resolver is only made to
// succeed for a device the engine is genuinely serving.
func TestRestoreStartsATuyaRowTheEngineKnows(t *testing.T) {
	m, db := countingRestoreManager(t)

	const token = "tuya:eb9f1d6e677b1b39f222ag"
	const liveURL = "rtsp://127.0.0.1:45011/tuya_eb9f1d6e677b1b39f222ag"
	// Stored exactly as Bug 1's fix writes it: Tuya, EMPTY url, resolution hd
	// (the user's choice must survive the restart too).
	if err := db.UpsertStreamConfig(token, "", string(models.ProviderTuya)); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	if err := db.SetStreamResolution(token, ResolutionHD); err != nil {
		t.Fatalf("seed resolution: %v", err)
	}

	// The engine now serves the device (this is what the start-up
	// re-registration achieves in production).
	engineStreams := map[string]string{token: liveURL}
	m.SetTuyaURLResolver(func(profileToken string) (string, error) {
		url, ok := engineStreams[profileToken]
		if !ok {
			return "", os.ErrNotExist
		}
		return url, nil
	})

	m.RestoreStreams()
	restored := waitForStreams(t, m, 1, 5*time.Second)

	if got := string(restored[0].Provider); got != string(models.ProviderTuya) {
		t.Errorf("restored provider = %q, want %q (a Tuya row must not come back as ONVIF)", got, models.ProviderTuya)
	}
	if restored[0].ProfileToken != token {
		t.Errorf("restored profile token = %q, want %q", restored[0].ProfileToken, token)
	}
	if restored[0].Resolution != ResolutionHD {
		t.Errorf("restored resolution = %q, want the stored %q", restored[0].Resolution, ResolutionHD)
	}
	// The live URL must be the one the ENGINE gave, not a stored one: this is
	// the whole point of resolving at restore time.
	if restored[0].RtspURL != liveURL {
		t.Errorf("restored RTSP URL = %q, want the engine's live %q", restored[0].RtspURL, liveURL)
	}
}

// TestRestoreSkipsATuyaRowTheEngineDoesNotKnow is the guard on the existing safe
// behaviour. The M9 fix registers devices BEFORE restore; it must not turn
// restore into something that starts ffmpeg against an empty URL for a row whose
// device the engine is not serving (a camera that was never started, or one that
// just failed to register because it is offline).
func TestRestoreSkipsATuyaRowTheEngineDoesNotKnow(t *testing.T) {
	m, db := countingRestoreManager(t)

	const token = "tuya:eb9f1d6e677b1b39f222ag"
	const onvifToken = "onvif-194"
	const onvifURL = "rtsp://10.2.56.194:5543/19efe2cb88c09c4db24478f5f39db29d/live/channel0"

	if err := db.UpsertStreamConfig(token, "", string(models.ProviderTuya)); err != nil {
		t.Fatalf("seed tuya config: %v", err)
	}
	// A control row that MUST still restore, so the test cannot pass by
	// restoring nothing at all.
	if err := db.UpsertStreamConfig(onvifToken, onvifURL, string(models.ProviderONVIF)); err != nil {
		t.Fatalf("seed onvif config: %v", err)
	}

	// The engine knows nothing: this is the offline / never-registered case.
	m.SetTuyaURLResolver(func(string) (string, error) {
		return "", os.ErrNotExist
	})

	m.RestoreStreams()
	restored := waitForStreams(t, m, 1, 5*time.Second)

	for _, s := range restored {
		if string(s.Provider.OrDefault()) == string(models.ProviderTuya) {
			t.Fatalf("a Tuya row the engine is not serving was restored: %+v", s)
		}
		if s.ProfileToken == token {
			t.Fatalf("the unregistered Tuya row was restored: %+v", s)
		}
	}
	if s := restored[0]; s.ProfileToken != onvifToken || s.RtspURL != onvifURL {
		t.Fatalf("the ONVIF control row did not restore as itself: %+v", s)
	}
}

// TestRestoreDoesNotPersistOverTheStoredRow proves the restore path is READ-ONLY
// with respect to the persisted row: restore is passed persist=false, so the
// ephemeral live URL must not be written back. If it were, the next restart
// would replay a frozen port -- reintroducing Bug 1 through the fix for Bug 2.
func TestRestoreDoesNotPersistOverTheStoredRow(t *testing.T) {
	m, db := countingRestoreManager(t)

	const token = "tuya:eb9f1d6e677b1b39f222ag"
	const liveURL = "rtsp://127.0.0.1:45011/tuya_eb9f1d6e677b1b39f222ag"
	if err := db.UpsertStreamConfig(token, "", string(models.ProviderTuya)); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	m.SetTuyaURLResolver(func(string) (string, error) { return liveURL, nil })

	m.RestoreStreams()
	waitForStreams(t, m, 1, 5*time.Second)

	configs, err := db.ListStreamConfigs()
	if err != nil {
		t.Fatalf("list configs: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d configs, want exactly 1 (restore must not add or drop rows): %+v", len(configs), configs)
	}
	if configs[0].RTSPURL != "" {
		t.Errorf("restore wrote the ephemeral engine URL %q back into the row; it must stay empty or the next restart replays a dead port", configs[0].RTSPURL)
	}
	if strings.TrimSpace(configs[0].Provider) != string(models.ProviderTuya) {
		t.Errorf("provider = %q, want %q", configs[0].Provider, models.ProviderTuya)
	}
}
