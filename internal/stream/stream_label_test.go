package stream

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/models"
)

// --- M12: the stream carries a non-secret CAMERA label -----------------------
//
// The card title used to be the internal stream id. The browser cannot derive a
// camera name for itself (the only address-bearing field, RtspURL, is `json:"-"`
// because an RTSP URL can carry credentials), so the server publishes a
// display-only label. These tests pin the two properties that make that safe and
// useful: the label names the camera, and it NEVER carries userinfo.

// newLabelTestManager builds a manager whose ffmpeg is a stub, so a stream can be
// created for real without an encoder or a network.
func newLabelTestManager(t *testing.T) *Manager {
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

// TestONVIFStreamLabelIsTheCameraHostWithNoUserinfo is the headline assertion:
// feed the manager an RTSP URL that CARRIES credentials and prove the label the
// browser would receive is the host alone.
func TestONVIFStreamLabelIsTheCameraHostWithNoUserinfo(t *testing.T) {
	m := newLabelTestManager(t)

	info, err := m.StartStream("live-channel0", "rtsp://admin:hunter2@10.2.56.194:5543/19efe2cb88c09c4db24478f5f39db29d/live/channel0")
	if err != nil {
		t.Fatalf("StartStream: %v", err)
	}
	if info.StreamLabel != "10.2.56.194" {
		t.Fatalf("StreamLabel = %q, want the bare host 10.2.56.194", info.StreamLabel)
	}
	for _, leaked := range []string{"admin", "hunter2", "5543", "@", "rtsp"} {
		if strings.Contains(info.StreamLabel, leaked) {
			t.Errorf("StreamLabel %q leaked %q", info.StreamLabel, leaked)
		}
	}
	// The URL itself is still on the in-process record - ffmpeg needs it - but
	// it must not survive the serialisation the browser sees.
	if info.RtspURL == "" {
		t.Fatal("the manager must keep the RTSP URL for its own ffmpeg")
	}
	encoded, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"rtsp", "rtspUrl", "RtspURL", "admin", "hunter2"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("the API JSON exposed %q: %s", forbidden, encoded)
		}
	}
	if !strings.Contains(string(encoded), `"streamLabel":"10.2.56.194"`) {
		t.Fatalf("the API JSON must carry the camera label: %s", encoded)
	}

	// The list endpoint (what the page actually polls) must agree.
	listed := m.ListStreams()
	if len(listed) != 1 || listed[0].StreamLabel != "10.2.56.194" {
		t.Fatalf("ListStreams must report the same label, got %+v", listed)
	}
}

// TestStreamLabelSurvivesTheStateBroadcastCredentialFree covers the OTHER path
// to the browser: the SSE state frames. Every one of them is re-derived, so a
// label that somehow became a URL still cannot reach a browser with credentials
// in it.
func TestStreamLabelSurvivesTheStateBroadcastCredentialFree(t *testing.T) {
	m := newLabelTestManager(t)

	entry := m.stateEntry(models.StreamInfo{
		ID:          "stream_1",
		RtspURL:     "rtsp://admin:hunter2@10.2.56.194:5543/live",
		StreamLabel: "rtsp://admin:hunter2@10.2.56.194:5543/live/channel0",
	}, "connected to rtsp://admin:hunter2@10.2.56.194:5543/live")
	if entry.State == nil {
		t.Fatal("the state entry must carry the stream state")
	}
	if entry.State.RtspURL != "" {
		t.Error("a broadcast state frame must never carry the RTSP URL")
	}
	if entry.State.StreamLabel != "10.2.56.194" {
		t.Errorf("a URL-shaped label must be reduced to its host before broadcast, got %q", entry.State.StreamLabel)
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"hunter2", "admin:", "user:pass"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("the SSE frame exposed %q: %s", forbidden, encoded)
		}
	}
}

// TestTuyaStreamLabelIsTheCameraNameFromTheRegisteredSeam covers the Tuya half:
// the provider knows the camera NAME and hands it over at start time, and the
// manager consumes it instead of falling back to an id.
func TestTuyaStreamLabelIsTheCameraNameFromTheRegisteredSeam(t *testing.T) {
	m := newLabelTestManager(t)

	m.SetPendingStreamLabel("tuya:eb9f1d6e677b1b39f222ag", "Security Camera")
	info, err := m.StartStreamForProvider("tuya:eb9f1d6e677b1b39f222ag", "rtsp://127.0.0.1:41441/tuya_eb9f1d6e677b1b39f222ag", models.ProviderTuya)
	if err != nil {
		t.Fatalf("StartStreamForProvider: %v", err)
	}
	if info.StreamLabel != "Security Camera" {
		t.Fatalf("StreamLabel = %q, want the camera NAME the provider registered", info.StreamLabel)
	}
	// Consumed, not sticky: a second stream for the same token must not inherit
	// the label of the first, or one camera's name ends up on another's card.
	if got := m.takePendingStreamLabel("tuya:eb9f1d6e677b1b39f222ag"); got != "" {
		t.Errorf("the registered label must be consumed at stream creation, got %q still pending", got)
	}
}

// TestTuyaStreamLabelFallsBackToAShortDeviceId guards the honest-degradation
// case: a Tuya stream must NEVER be labelled from its URL, because that URL
// points at THIS process's own loopback engine and its host names nothing about
// the camera.
func TestTuyaStreamLabelFallsBackToAShortDeviceId(t *testing.T) {
	m := newLabelTestManager(t)

	info, err := m.StartStreamForProvider("tuya:eb9f1d6e677b1b39f222ag", "rtsp://127.0.0.1:41441/tuya_eb9f1d6e677b1b39f222ag", models.ProviderTuya)
	if err != nil {
		t.Fatalf("StartStreamForProvider: %v", err)
	}
	if info.StreamLabel == "127.0.0.1" {
		t.Fatal("a Tuya card must never be titled with this process's own loopback host")
	}
	if info.StreamLabel != "…39f222ag" {
		t.Fatalf("StreamLabel = %q, want the short device id tail", info.StreamLabel)
	}
}

// TestStreamLabelResolverReattachesTheCameraToARestoredStream covers the restore
// path: a stream created from a stored row has no provider-supplied label, so the
// installed resolver names it instead.
func TestStreamLabelResolverReattachesTheCameraToARestoredStream(t *testing.T) {
	m := newLabelTestManager(t)
	m.SetStreamLabelResolver(func(profileToken, rtspURL string) string {
		if profileToken == "tuya:eb9f1d6e677b1b39f222ag" {
			return "Security Camera"
		}
		return ""
	})

	info, err := m.StartStreamForProvider("tuya:eb9f1d6e677b1b39f222ag", "rtsp://127.0.0.1:41441/tuya_eb9f1d6e677b1b39f222ag", models.ProviderTuya)
	if err != nil {
		t.Fatalf("StartStreamForProvider: %v", err)
	}
	if info.StreamLabel != "Security Camera" {
		t.Fatalf("StreamLabel = %q, want the resolver's camera name", info.StreamLabel)
	}

	// A resolver that cannot name the camera must not invent one, and must not
	// hand a URL through either.
	m.SetStreamLabelResolver(func(profileToken, rtspURL string) string {
		return "rtsp://user:pass@10.9.9.9:554/live"
	})
	info2, err := m.StartStreamForProvider("tuya:aaaaaaaaaaaaaaaaaaaaaa", "rtsp://127.0.0.1:41441/tuya_aaaaaaaaaaaaaaaaaaaaaa", models.ProviderTuya)
	if err != nil {
		t.Fatalf("StartStreamForProvider: %v", err)
	}
	if info2.StreamLabel != "10.9.9.9" {
		t.Fatalf("a URL-shaped resolver answer must be reduced to its host, got %q", info2.StreamLabel)
	}
}

// TestONVIFStreamLabelIsEmptyWithoutAUsableHostFreeForm documents the empty case:
// a caller that hands over something that is not an RTSP URL gets no label at
// all rather than a fabricated one, and the UI then falls back to a short id.
func TestONVIFStreamLabelIsEmptyWithoutAUsableHostFreeForm(t *testing.T) {
	m := newLabelTestManager(t)

	info, err := m.StartStream("legacy", "ch0")
	if err != nil {
		t.Fatalf("StartStream: %v", err)
	}
	if info.StreamLabel != "" {
		t.Fatalf("StreamLabel = %q, want empty so the UI falls back to a shortened id", info.StreamLabel)
	}
}
