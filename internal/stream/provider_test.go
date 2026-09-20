package stream

import (
	"path/filepath"
	"testing"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/models"
)

// testManager builds a manager with no FFmpeg work: startStream only spawns the
// monitor goroutine, which the caller cancels via Shutdown.
func testManager(t *testing.T) (*Manager, *logger.Logger) {
	t.Helper()
	l, err := logger.NewLogger(filepath.Join(t.TempDir(), "provider.db"))
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(t.TempDir(), l)
	return m, l
}

// A stream started through the legacy two-argument API must persist and report
// ONVIF, because that is the only thing it could have meant before the provider
// column existed.
func TestStartStreamDefaultsToONVIF(t *testing.T) {
	m, l := testManager(t)
	defer l.Close()
	defer m.Shutdown()

	info, err := m.StartStream("legacy-token", "rtsp://10.0.0.9:554/live")
	if err != nil {
		t.Fatal(err)
	}
	if info.Provider != models.ProviderONVIF {
		t.Fatalf("provider = %q, want onvif", info.Provider)
	}
	configs, err := l.ListStreamConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 1 || configs[0].Provider != "onvif" {
		t.Fatalf("persisted configs = %#v, want provider onvif", configs)
	}
}

// A Tuya stream must report and persist as Tuya. This is what makes a restart
// restore it as Tuya instead of silently downgrading it to ONVIF.
func TestStartStreamForProviderTagsAndPersists(t *testing.T) {
	m, l := testManager(t)
	defer l.Close()
	defer m.Shutdown()

	info, err := m.StartStreamForProvider("tuya:eb9f1d6e677b1b39f222ag", "rtsp://127.0.0.1:8591/tuya_eb9f1d6e677b1b39f222ag", models.ProviderTuya)
	if err != nil {
		t.Fatal(err)
	}
	if info.Provider != models.ProviderTuya {
		t.Fatalf("provider = %q, want tuya", info.Provider)
	}

	// The manager's own record -- what /api/stream/list serves -- must carry the
	// provider too, not just the returned copy.
	listed := m.ListStreams()
	if len(listed) != 1 || listed[0].Provider != models.ProviderTuya {
		t.Fatalf("ListStreams() = %#v, want one stream with provider tuya", listed)
	}

	configs, err := l.ListStreamConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 1 || configs[0].Provider != "tuya" {
		t.Fatalf("persisted configs = %#v, want provider tuya", configs)
	}
}

// An empty provider must never be persisted or reported as blank.
func TestStartStreamForProviderNormalisesEmptyProvider(t *testing.T) {
	m, l := testManager(t)
	defer l.Close()
	defer m.Shutdown()

	info, err := m.StartStreamForProvider("blank-token", "rtsp://10.0.0.9:554/live", models.ProviderKind(""))
	if err != nil {
		t.Fatal(err)
	}
	if info.Provider != models.ProviderONVIF {
		t.Fatalf("provider = %q, want onvif", info.Provider)
	}
	configs, _ := l.ListStreamConfigs()
	if len(configs) != 1 || configs[0].Provider != "onvif" {
		t.Fatalf("persisted configs = %#v, want provider onvif", configs)
	}
}
