package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/recording"
	"dengan.dev/camera-streamer/internal/recording/storage/local"
	"dengan.dev/camera-streamer/internal/secrets"
)

const (
	statusRoute   = "/api/recordings/status"
	summaryRoute  = "/api/recordings/summary?camera=onvif:cam&from=2026-10-04T11:00:00Z&to=2026-10-04T13:00:00Z&buckets=60"
	settingsRoute = "/api/recordings/settings"
)

// fakeCredential is the configured S3 secret the redaction test hunts for in
// every serialized response. It is deliberately a value that could never appear
// by coincidence.
const fakeCredential = "FAKE-S3-SECRET-2f4b1e7a-NEVER-SERIALIZE"
const fakeSession = "FAKE-SESSION-9c8d3a-NEVER-SERIALIZE"

func wiredRecordingHandler(t *testing.T) (http.Handler, *recording.Recorder) {
	t.Helper()
	root := t.TempDir()
	db, e := logger.NewLogger(filepath.Join(root, "app.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	store, e := local.New(filepath.Join(root, "objects"))
	if e != nil {
		t.Fatal(e)
	}
	rec, e := recording.New(db.DB(), filepath.Join(root, "spool"), store, recording.Config{QuotaBytes: 1 << 20, RetentionDays: 7})
	if e != nil {
		t.Fatal(e)
	}
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))
	cipher, e := secrets.New(key)
	if e != nil {
		t.Fatal(e)
	}
	env := recording.StorageEnv{
		Driver:        recording.DriverS3,
		S3Endpoint:    "https://s3.example.invalid",
		S3Bucket:      "footage",
		S3Region:      "eu-central-1",
		S3AccessKey:   "operator",
		S3Secret:      fakeCredential,
		S3Session:     fakeSession,
		QuotaBytes:    1 << 20,
		ReserveBytes:  4096,
		RetentionDays: 7,
	}
	settings, _, e := recording.ResolveStorageSettings(db.DB(), env, cipher)
	if e != nil {
		t.Fatal(e)
	}
	// The wiring applies the resolved limits to the recorder at boot, exactly as
	// recording_setup.go does, so the reported capacity reflects the config row.
	if e := rec.ApplyLimits(settings.QuotaBytes, settings.ReserveBytes, settings.RetentionDays); e != nil {
		t.Fatal(e)
	}
	// Seed one camera and one synthetic segment so the routes have real state.
	if e := rec.SetEnabled("onvif:cam", true); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(root, "live")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "stream0.ts"), []byte("123456"), 0600)
	os.WriteFile(filepath.Join(dir, "stream.m3u8"), []byte("#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:1\n#EXTINF:2,\nstream0.ts\n"), 0600)
	if e := rec.IngestPlaylist("onvif:cam", "run", dir, time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)); e != nil {
		t.Fatal(e)
	}
	if e := rec.SetStoreDescription(recording.StoreDescription{
		Driver:    recording.DriverS3,
		S3Endpoint: "https://s3.example.invalid",
		S3Bucket:  "footage",
		S3Region:  "eu-central-1",
		Available: true,
		AppKey:    true,
	}); e != nil {
		t.Fatal(e)
	}
	return RecordingRoutes(rec, "secret", WithStorageSettings(settings)), rec
}

func authedRequest(method, target string, body []byte) *http.Request {
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, bytes.NewReader(body))
	}
	r.Header.Set("Authorization", "Bearer secret")
	return r
}

func TestNewRecordingRoutesRequireCredentialForEveryMethod(t *testing.T) {
	h, _ := wiredRecordingHandler(t)
	for _, route := range []string{statusRoute, summaryRoute, settingsRoute} {
		for _, method := range []string{"GET", "HEAD", "POST"} {
			req := httptest.NewRequest(method, route, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s %s = %d, want 401 without a credential", method, route, w.Code)
			}
			if w.Body.Len() > 0 && strings.Contains(w.Body.String(), "footage") {
				t.Errorf("%s %s leaked configuration on the unauthenticated path", method, route)
			}
		}
		// A wrong token is still unauthenticated.
		req := httptest.NewRequest("GET", route, nil)
		req.Header.Set("Authorization", "Bearer wrong")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("GET %s with a wrong token = %d, want 401", route, w.Code)
		}
	}
}

func TestStatusRouteShapeAndRedaction(t *testing.T) {
	h, _ := wiredRecordingHandler(t)
	req := authedRequest("GET", statusRoute, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d %q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	var decoded struct {
		Driver   string `json:"driver"`
		Location struct {
			Kind     string `json:"kind"`
			Endpoint string `json:"endpoint"`
			Bucket   string `json:"bucket"`
			Region   string `json:"region"`
		} `json:"location"`
		Capacity struct {
			QuotaBytes int64 `json:"quotaBytes"`
		} `json:"capacity"`
		Backlog struct {
			PendingUploads int `json:"pendingUploads"`
		} `json:"backlog"`
		Cameras []struct {
			Camera  string `json:"camera"`
			Enabled bool   `json:"enabled"`
		} `json:"cameras"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &decoded); e != nil {
		t.Fatal(e)
	}
	if decoded.Driver != "s3" || decoded.Location.Endpoint != "https://s3.example.invalid" || decoded.Location.Bucket != "footage" || decoded.Location.Region != "eu-central-1" {
		t.Fatalf("status location %+v", decoded)
	}
	if decoded.Capacity.QuotaBytes != 1<<20 {
		t.Fatalf("status capacity %+v", decoded.Capacity)
	}
	if decoded.Backlog.PendingUploads != 1 {
		t.Fatalf("status backlog %+v", decoded.Backlog)
	}
	if len(decoded.Cameras) != 1 || decoded.Cameras[0].Camera != "onvif:cam" {
		t.Fatalf("status cameras %+v", decoded.Cameras)
	}
	assertNoSecrets(t, body)
}

func TestSummaryRouteShapeAndRedaction(t *testing.T) {
	h, _ := wiredRecordingHandler(t)
	req := authedRequest("GET", summaryRoute, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("summary = %d %q", w.Code, w.Body.String())
	}
	var decoded struct {
		Buckets []struct {
			Start           time.Time `json:"start"`
			End             time.Time `json:"end"`
			RecordedSeconds float64   `json:"recordedSeconds"`
			GapSeconds      float64   `json:"gapSeconds"`
			Segments        int       `json:"segments"`
		} `json:"buckets"`
		Truncated bool `json:"truncated"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &decoded); e != nil {
		t.Fatal(e)
	}
	if len(decoded.Buckets) == 0 || len(decoded.Buckets) > recording.MaxSummaryBuckets {
		t.Fatalf("summary bucket count %d", len(decoded.Buckets))
	}
	var gap float64
	for _, b := range decoded.Buckets {
		gap += b.GapSeconds
	}
	if gap <= 0 {
		t.Fatalf("the seeded prefix gap did not reach the summary: %+v", decoded.Buckets)
	}
	assertNoSecrets(t, w.Body.String())
}

func TestSummaryRouteRejectsMalformedRanges(t *testing.T) {
	h, _ := wiredRecordingHandler(t)
	for _, target := range []string{
		"/api/recordings/summary?camera=onvif:cam&from=not-a-time&to=2026-10-04T13:00:00Z",
		"/api/recordings/summary?camera=onvif:cam&from=2026-10-04T11:00:00Z",
		"/api/recordings/summary?camera=&from=2026-10-04T11:00:00Z&to=2026-10-04T13:00:00Z",
		"/api/recordings/summary?camera=onvif:cam&from=2026-10-04T13:00:00Z&to=2026-10-04T11:00:00Z",
		"/api/recordings/summary?camera=onvif:cam&from=2026-10-04T11:00:00Z&to=2026-10-04T13:00:00Z&buckets=lots",
		"/api/recordings/summary?camera=onvif:cam&from=2026-10-04T11:00:00Z&to=2026-10-04T13:00:00Z&buckets=-5",
	} {
		req := authedRequest("GET", target, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400", target, w.Code)
		}
	}
}

func TestSettingsRouteReadsEffectiveConfiguration(t *testing.T) {
	h, _ := wiredRecordingHandler(t)
	req := authedRequest("GET", settingsRoute, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("settings = %d %q", w.Code, w.Body.String())
	}
	var decoded struct {
		Driver        string `json:"driver"`
		RetentionDays int    `json:"retentionDays"`
		QuotaBytes    int64  `json:"quotaBytes"`
		ReserveBytes  uint64 `json:"reserveBytes"`
		Cameras       []struct {
			Camera  string `json:"camera"`
			Enabled bool   `json:"enabled"`
		} `json:"cameras"`
		DriverSwitchAllowed bool `json:"driverSwitchAllowed"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &decoded); e != nil {
		t.Fatal(e)
	}
	if decoded.Driver != "s3" || decoded.RetentionDays != 7 || decoded.QuotaBytes != 1<<20 || decoded.ReserveBytes != 4096 {
		t.Fatalf("settings %+v", decoded)
	}
	if len(decoded.Cameras) != 1 || !decoded.Cameras[0].Enabled {
		t.Fatalf("settings cameras %+v", decoded.Cameras)
	}
	// The catalog holds a segment, so a driver switch must be refused.
	if decoded.DriverSwitchAllowed {
		t.Fatal("a populated catalog offered a driver switch")
	}
	assertNoSecrets(t, w.Body.String())
}

func TestSettingsRouteWritesCameraAndLimitsAtRuntime(t *testing.T) {
	h, rec := wiredRecordingHandler(t)
	payload := []byte(`{"camera":"onvif:cam","enabled":false,"retentionDays":3,"quotaBytes":2097152,"reserveBytes":8192}`)
	req := authedRequest("POST", settingsRoute, payload)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST settings = %d %q", w.Code, w.Body.String())
	}
	assertNoSecrets(t, w.Body.String())

	// The saved values must read back immediately, with no restart.
	st, e := rec.Status()
	if e != nil {
		t.Fatal(e)
	}
	if st.RetentionDays != 3 || st.Capacity.QuotaBytes != 2097152 || st.Capacity.ReserveBytes != 8192 {
		t.Fatalf("limits did not take effect: %+v", st)
	}
	if len(st.Cameras) != 1 || st.Cameras[0].Enabled {
		t.Fatalf("camera enablement was not saved: %+v", st.Cameras)
	}

	// And they must survive a re-read of the effective settings row.
	req = authedRequest("GET", settingsRoute, nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var decoded struct {
		RetentionDays int   `json:"retentionDays"`
		QuotaBytes    int64 `json:"quotaBytes"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &decoded); e != nil {
		t.Fatal(e)
	}
	if decoded.RetentionDays != 3 || decoded.QuotaBytes != 2097152 {
		t.Fatalf("settings did not read back the saved limits: %+v", decoded)
	}
}

func TestSettingsRouteRejectsBadPayloads(t *testing.T) {
	h, _ := wiredRecordingHandler(t)
	for _, tc := range []struct{ name, body string }{
		{"unknown field", `{"driver":"local"}`},
		{"empty body", ``},
		{"no editable field", `{}`},
		{"negative quota", `{"quotaBytes":-1}`},
		{"zero retention", `{"retentionDays":0}`},
		{"invalid camera", `{"camera":"bad\ncamera","enabled":true}`},
		{"not json", `not json at all`},
	} {
		req := authedRequest("POST", settingsRoute, []byte(tc.body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: POST settings = %d, want 400 (%q)", tc.name, w.Code, w.Body.String())
		}
	}
}

func TestSettingsRouteRejectsGetBodyAndUnsupportedMethods(t *testing.T) {
	h, _ := wiredRecordingHandler(t)
	req := authedRequest("PUT", settingsRoute, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT settings = %d, want 405", w.Code)
	}
	req = authedRequest("POST", statusRoute, []byte(`{}`))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", w.Code)
	}
}

func TestRecordingRoutesAnswerUndefinedSubPathWith404(t *testing.T) {
	h, _ := wiredRecordingHandler(t)
	req := authedRequest("GET", "/api/recordings/nonsense", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown sub-path = %d, want 404", w.Code)
	}
}

// assertNoSecrets is the single redaction gate every response passes through.
func assertNoSecrets(t *testing.T, body string) {
	t.Helper()
	for _, forbidden := range []string{
		fakeCredential,
		fakeSession,
		"sha256",
		"SHA256",
		"spool",
		"Spool",
		"SecretKey",
		"secretKey",
		"sessionToken",
		"SessionToken",
		"accessKey",
		"AccessKey",
		"s3_secret_cipher",
		"s3_session_cipher",
		"cipher",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("response leaked %q: %s", forbidden, body)
		}
	}
}

func TestRecordingRoutesRequireCredentialOnHeadWithoutBody(t *testing.T) {
	h, _ := wiredRecordingHandler(t)
	for _, route := range []string{statusRoute, settingsRoute} {
		req := httptest.NewRequest("HEAD", route, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("HEAD %s = %d, want 401", route, w.Code)
		}
	}
}
