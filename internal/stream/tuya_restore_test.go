package stream

import (
	"os"
	"path/filepath"
	"testing"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/models"
)

// TestATuyaStreamDoesNotPersistItsLoopbackURL pins the defect directly: a Tuya
// stream's RTSP URL is a loopback address on our OWN in-process engine, and that
// engine binds an ephemeral port which changes on every start. Persisting the
// resolved URL freezes a port the engine will not own again, so a restored Tuya
// stream retries a dead address forever -- which is exactly what happened live
// (17 reconnect attempts with the backoff grown to a minute).
//
// The URL must therefore be stored EMPTY, with the profile token carrying the
// device id, and resolved from the engine at restore time.
func TestATuyaStreamDoesNotPersistItsLoopbackURL(t *testing.T) {
	dir := t.TempDir()
	db, err := logger.NewLogger(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer db.Close()

	m := NewManager(dir, db)
	// A Tuya URL as the engine really reports it: loopback, ephemeral port.
	m.SetTuyaURLResolver(func(profileToken string) (string, error) {
		return "rtsp://127.0.0.1:38383/tuya_eb9f1d6e677b1b39f222ag", nil
	})

	info, err := m.StartStreamForProvider("tuya:eb9f1d6e677b1b39f222ag",
		"rtsp://127.0.0.1:38383/tuya_eb9f1d6e677b1b39f222ag", models.ProviderTuya)
	if err != nil {
		t.Fatalf("start tuya stream: %v", err)
	}
	defer m.StopStream(info.ID)

	configs, err := db.ListStreamConfigs()
	if err != nil {
		t.Fatalf("list configs: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d configs, want 1 (the Tuya row must still be returned)", len(configs))
	}
	if configs[0].RTSPURL != "" {
		t.Errorf("a Tuya stream persisted its loopback URL %q; it must persist empty so the port is not frozen", configs[0].RTSPURL)
	}
	if configs[0].Provider != string(models.ProviderTuya) {
		t.Errorf("provider = %q, want %q", configs[0].Provider, models.ProviderTuya)
	}
}

// TestAnONVIFStreamStillPersistsItsURL is the control: ONVIF URLs point at a
// real camera on a stable address, so they MUST keep being stored, or a restart
// would silently forget every ONVIF camera.
func TestAnONVIFStreamStillPersistsItsURL(t *testing.T) {
	dir := t.TempDir()
	db, err := logger.NewLogger(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer db.Close()

	m := NewManager(dir, db)
	const camURL = "rtsp://10.2.56.194:5543/19efe2cb88c09c4db24478f5f39db29d/live/channel0"
	info, err := m.StartStreamForProvider("onvif-194", camURL, models.ProviderONVIF)
	if err != nil {
		t.Fatalf("start onvif stream: %v", err)
	}
	defer m.StopStream(info.ID)

	configs, err := db.ListStreamConfigs()
	if err != nil {
		t.Fatalf("list configs: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d configs, want 1", len(configs))
	}
	if configs[0].RTSPURL != camURL {
		t.Errorf("ONVIF URL = %q, want it preserved as %q", configs[0].RTSPURL, camURL)
	}
}

// TestRestoreAsksTheEngineForTheLiveTuyaURL covers the other half of the fix:
// restoring must RESOLVE a Tuya URL rather than replay a stored one. A stored
// URL would be empty (by design), and reusing it would start ffmpeg against ""
// -- so the resolver is the only way restore can work at all.
func TestRestoreAsksTheEngineForTheLiveTuyaURL(t *testing.T) {
	dir := t.TempDir()
	db, err := logger.NewLogger(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer db.Close()

	const token = "tuya:eb9f1d6e677b1b39f222ag"
	const liveURL = "rtsp://127.0.0.1:44001/tuya_eb9f1d6e677b1b39f222ag"

	// A row as a previous run left it: Tuya, empty URL.
	if err := db.UpsertStreamConfig(token, "", string(models.ProviderTuya)); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	m := NewManager(dir, db)
	if _, ok := m.resolveTuyaURL(token); ok {
		t.Fatal("resolveTuyaURL succeeded with no resolver installed; it must report not-found")
	}

	asked := make(chan string, 1)
	m.SetTuyaURLResolver(func(profileToken string) (string, error) {
		asked <- profileToken
		return liveURL, nil
	})

	got, ok := m.resolveTuyaURL(token)
	if !ok {
		t.Fatal("resolveTuyaURL did not find the live URL from the resolver")
	}
	if got != liveURL {
		t.Errorf("resolved URL = %q, want %q", got, liveURL)
	}
	select {
	case profileToken := <-asked:
		if profileToken != token {
			t.Errorf("resolver asked for %q, want %q", profileToken, token)
		}
	default:
		t.Error("resolver was never called")
	}
}

// TestRestoreSkipsATuyaStreamTheEngineIsNotRunning makes sure a placeholder row
// (a camera whose resolution was chosen before its first start) is not replayed
// as a start. With no engine entry there is no URL, and starting ffmpeg against
// an empty URL is the failure we are preventing.
func TestRestoreSkipsATuyaStreamTheEngineIsNotRunning(t *testing.T) {
	dir := t.TempDir()
	db, err := logger.NewLogger(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer db.Close()

	const token = "tuya:eb9f1d6e677b1b39f222ag"
	if err := db.UpsertStreamConfig(token, "", string(models.ProviderTuya)); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	m := NewManager(dir, db)
	// Resolver installed but the engine does not know this token yet.
	m.SetTuyaURLResolver(func(string) (string, error) {
		return "", os.ErrNotExist
	})

	if _, ok := m.resolveTuyaURL(token); ok {
		t.Fatal("a token the engine is not running must not resolve to a URL")
	}

	configs, err := db.ListStreamConfigs()
	if err != nil {
		t.Fatalf("list configs: %v", err)
	}
	if len(configs) != 1 || configs[0].RTSPURL != "" {
		t.Fatalf("placeholder row should be returned with an empty URL, got %+v", configs)
	}
}
