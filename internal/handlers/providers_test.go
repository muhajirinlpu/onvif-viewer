package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/models"
	"dengan.dev/camera-streamer/internal/onvif"
	"dengan.dev/camera-streamer/internal/provider"
	"dengan.dev/camera-streamer/internal/stream"
	"dengan.dev/camera-streamer/internal/tuyaengine"
	"dengan.dev/camera-streamer/internal/tuyaqr"
)

type testEnv struct {
	handler *Handler
	manager *stream.Manager
}

func testHandler(t *testing.T) *testEnv {
	t.Helper()
	l, err := logger.NewLogger(filepath.Join(t.TempDir(), "handler.db"))
	if err != nil {
		t.Fatal(err)
	}
	m := stream.NewManager(t.TempDir(), l)
	// Shut the manager down BEFORE closing the database: the monitor goroutines
	// write log lines, and closing the DB first makes every one of them noisy.
	t.Cleanup(func() {
		m.Shutdown()
		l.Close()
	})
	return &testEnv{handler: New(m, onvif.NewClient(), l), manager: m}
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, rec.Body.String())
	}
	return out
}

// An install with no provider wiring must answer clearly rather than 404 or
// panic. This is the shape of an ONVIF-only deployment.
func TestProviderEndpointsWithoutWiringAnswer503(t *testing.T) {
	env := testHandler(t)
	h := env.handler
	for _, tc := range []struct {
		name string
		call func(w http.ResponseWriter, r *http.Request)
		meth string
	}{
		{"cameras", h.ProviderCameras, http.MethodGet},
		{"tuya begin", h.TuyaLoginBegin, http.MethodPost},
		{"tuya poll", h.TuyaLoginPoll, http.MethodGet},
		{"tuya session", h.TuyaSession, http.MethodGet},
	} {
		rec := httptest.NewRecorder()
		tc.call(rec, httptest.NewRequest(tc.meth, "/x", nil))
		// TuyaSession answers 200 with configured:false by design: the UI polls
		// it unconditionally and needs a shape it can read, not an error.
		if tc.name == "tuya session" {
			if rec.Code != http.StatusOK {
				t.Errorf("%s: status = %d, want 200", tc.name, rec.Code)
			}
			if body := decodeBody(t, rec); body["configured"] != false || body["valid"] != false {
				t.Errorf("%s: body = %#v, want configured=false valid=false", tc.name, body)
			}
			continue
		}
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: status = %d, want 503", tc.name, rec.Code)
		}
	}
}

// GET /api/providers/cameras?provider=onvif must list nothing and say why,
// without being an error: the ONVIF form legitimately asks for this while a
// camera is being configured.
func TestProviderCamerasONVIFIsEmptyWithAnExplanation(t *testing.T) {
	env := testHandler(t)
	h := env.handler
	h.SetProviders(provider.NewSet(provider.NewONVIF(env.handler.onvifClient)), nil, nil, nil)

	rec := httptest.NewRecorder()
	h.ProviderCameras(rec, httptest.NewRequest(http.MethodGet, "/api/providers/cameras?provider=onvif", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := decodeBody(t, rec)
	cams, ok := body["cameras"].([]any)
	if !ok || len(cams) != 0 {
		t.Fatalf("cameras = %#v, want an empty list", body["cameras"])
	}
	if detail, _ := body["detail"].(string); !strings.Contains(detail, "POST") {
		t.Fatalf("detail = %q, want guidance pointing at the POST form", detail)
	}
}

func TestProviderCamerasRejectsUnknownProvider(t *testing.T) {
	env := testHandler(t)
	h := env.handler
	h.SetProviders(provider.NewSet(provider.NewONVIF(env.handler.onvifClient)), nil, nil, nil)

	rec := httptest.NewRecorder()
	h.ProviderCameras(rec, httptest.NewRequest(http.MethodGet, "/api/providers/cameras?provider=nope", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// POST /api/providers/cameras is the credential-bearing ONVIF listing: it must
// validate the body and never echo credentials back.
func TestProviderCamerasPostRequiresAnAddressAndHidesCredentials(t *testing.T) {
	env := testHandler(t)
	h := env.handler
	h.SetProviders(provider.NewSet(provider.NewONVIF(env.handler.onvifClient)), nil, nil, nil)

	rec := httptest.NewRecorder()
	h.ProviderCameras(rec, httptest.NewRequest(http.MethodPost, "/api/providers/cameras",
		strings.NewReader(`{"provider":"onvif"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a missing cameraIp", rec.Code)
	}

	// A non-ONVIF provider in the POST body must be refused rather than
	// silently treated as ONVIF.
	rec = httptest.NewRecorder()
	h.ProviderCameras(rec, httptest.NewRequest(http.MethodPost, "/api/providers/cameras",
		strings.NewReader(`{"provider":"tuya","cameraIp":"10.0.0.1"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for provider=tuya on the POST form", rec.Code)
	}

	// No reachable camera: the failure must be a clean 502 with a generic
	// message, never the upstream error text (which can name the camera).
	rec = httptest.NewRecorder()
	h.ProviderCameras(rec, httptest.NewRequest(http.MethodPost, "/api/providers/cameras",
		strings.NewReader(`{"provider":"onvif","cameraIp":"127.0.0.1","cameraPort":"1","username":"admin","password":"hunter2"}`)))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for an unreachable camera", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatalf("password leaked into the response: %s", rec.Body.String())
	}
}

// The Tuya-shaped start request must reach the Tuya path, and a Tuya request
// with no deviceId must fail clearly instead of being mistaken for ONVIF.
func TestStartStreamRoutesTuyaWithoutBreakingONVIF(t *testing.T) {
	env := testHandler(t)
	h := env.handler

	// provider=tuya with no Tuya provider wired: an explicit, honest failure.
	rec := httptest.NewRecorder()
	h.StartStream(rec, httptest.NewRequest(http.MethodPost, "/api/stream/start",
		strings.NewReader(`{"provider":"tuya","deviceId":"eb9f1d6e677b1b39f222ag"}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when Tuya is not configured (%s)", rec.Code, rec.Body.String())
	}

	// provider=tuya with an empty deviceId.
	rec = httptest.NewRecorder()
	h.StartStream(rec, httptest.NewRequest(http.MethodPost, "/api/stream/start",
		strings.NewReader(`{"provider":"tuya"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a missing deviceId", rec.Code)
	}

	// The unchanged ONVIF contract still works and still reports onvif.
	rec = httptest.NewRecorder()
	h.StartStream(rec, httptest.NewRequest(http.MethodPost, "/api/stream/start",
		strings.NewReader(`{"profileToken":"legacy","rtspUrl":"rtsp://10.0.0.9:554/live"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("ONVIF start status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["provider"] != "onvif" {
		t.Fatalf("provider = %#v, want onvif", body["provider"])
	}
	if body["profileToken"] != "legacy" {
		t.Fatalf("profileToken = %#v, want legacy (the ONVIF contract must not change)", body["profileToken"])
	}
}

// A malformed JSON body must be a 400, not a panic or a silent success.
func TestStartStreamRejectsMalformedBody(t *testing.T) {
	env := testHandler(t)
	h := env.handler
	rec := httptest.NewRecorder()
	h.StartStream(rec, httptest.NewRequest(http.MethodPost, "/api/stream/start", strings.NewReader(`{not json`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// --- M6: session lifecycle HTTP surface -------------------------------------

// TestTuyaSessionWithoutWiringStaysReadable keeps the pre-provider shape: the UI
// polls this unconditionally and needs fields it can read.
func TestTuyaSessionWithoutWiringStaysReadable(t *testing.T) {
	env := testHandler(t)
	rec := httptest.NewRecorder()
	env.handler.TuyaSession(rec, httptest.NewRequest(http.MethodGet, "/api/tuya/session", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := decodeBody(t, rec)
	if body["configured"] != false {
		t.Errorf("configured = %#v, want false", body["configured"])
	}
	// The honesty fields must exist even in the unconfigured case, so the UI
	// never has to guess what a missing field means.
	for _, field := range []string{"configured", "filePresent", "cloudVerified", "valid", "expiryKnown", "expirySource", "reloginRequired"} {
		if _, ok := body[field]; !ok {
			t.Errorf("response is missing the honesty field %q: %s", field, rec.Body.String())
		}
	}
	if body["expiresAt"] != nil {
		t.Errorf("expiresAt = %#v, want null", body["expiresAt"])
	}
}

// TestTuyaSessionRejectsNonGET keeps the method contract explicit.
func TestTuyaSessionRejectsNonGET(t *testing.T) {
	env := testHandler(t)
	rec := httptest.NewRecorder()
	env.handler.TuyaSession(rec, httptest.NewRequest(http.MethodPost, "/api/tuya/session", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// TestTuyaLogoutWithoutWiringAnswers503 mirrors every other Tuya endpoint.
func TestTuyaLogoutWithoutWiringAnswers503(t *testing.T) {
	env := testHandler(t)
	rec := httptest.NewRecorder()
	env.handler.TuyaLogout(rec, httptest.NewRequest(http.MethodPost, "/api/tuya/logout", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestTuyaLogoutRejectsGET: a GET must never be able to delete a credential.
func TestTuyaLogoutRejectsGET(t *testing.T) {
	env := testHandler(t)
	rec := httptest.NewRecorder()
	env.handler.TuyaLogout(rec, httptest.NewRequest(http.MethodGet, "/api/tuya/logout", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405 (a GET must not be able to delete a credential)", rec.Code)
	}
}

// TestTuyaLogoutIsHonestAboutNoServerSideLogout: the response must not imply the
// cloud revoked anything.
func TestTuyaLogoutIsHonestAboutNoServerSideLogout(t *testing.T) {
	env := testHandler(t)
	h := env.handler
	dir := t.TempDir()
	path := filepath.Join(dir, "session.json")
	if err := writeTestSessionFile(path); err != nil {
		t.Fatal(err)
	}
	h.SetProviders(provider.NewSet(provider.NewONVIF(env.handler.onvifClient)), newTestLoginManager(path), nil, nil)

	rec := httptest.NewRecorder()
	h.TuyaLogout(rec, httptest.NewRequest(http.MethodPost, "/api/tuya/logout", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["removed"] != true {
		t.Errorf("removed = %#v, want true", body["removed"])
	}
	if body["serverSideLogout"] != false {
		t.Errorf("serverSideLogout = %#v, want false: Tuya has no server-side logout", body["serverSideLogout"])
	}
	if detail, _ := body["detail"].(string); !strings.Contains(detail, "no server-side logout") {
		t.Errorf("detail = %q, want it to say there is no server-side logout", detail)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the session file still exists after a logout: %v", err)
	}
	if strings.Contains(rec.Body.String(), "fast-sid=") || strings.Contains(rec.Body.String(), "s-sid=") {
		t.Fatalf("a cookie value leaked into the logout response: %s", rec.Body.String())
	}
}

// TestTuyaResumeWithoutWiringAnswers503.
func TestTuyaResumeWithoutWiringAnswers503(t *testing.T) {
	env := testHandler(t)
	rec := httptest.NewRecorder()
	env.handler.TuyaResume(rec, httptest.NewRequest(http.MethodPost, "/api/tuya/resume", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestTuyaResumeRejectsGET.
func TestTuyaResumeRejectsGET(t *testing.T) {
	env := testHandler(t)
	rec := httptest.NewRecorder()
	env.handler.TuyaResume(rec, httptest.NewRequest(http.MethodGet, "/api/tuya/resume", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// deadTuyaBridge is a TuyaStreaming double whose engine cannot connect, which is
// what the real engine does when the session file it is handed is dead.
type deadTuyaBridge struct{}

func (deadTuyaBridge) StartStream(tuyaengine.DeviceSpec) (*models.StreamInfo, error) {
	return nil, errors.New("tuyaengine: engine cannot connect")
}

func (deadTuyaBridge) Resolve(string) (string, error) {
	return "", errors.New("tuyaengine: engine is not running")
}

// writeUnusableSessionFile writes a session file with a loginResult (so it
// parses) but WITHOUT the fast-sid/s-sid pair, so building an authenticated
// client fails locally. That makes the "the session is dead" branch reachable
// without any network call.
func writeUnusableSessionFile(path string) error {
	return os.WriteFile(path, []byte(`{
  "region": "us-west",
  "email": "user@example.test",
  "userKey": "us-west_user_at_example_test",
  "lastRefresh": "2026-09-20T00:00:00Z",
  "sessionData": {
    "cookies": [{"name":"locale","value":"en"}],
    "loginResult": {"uid":"az1","email":"user@example.test"},
    "region": "us-west",
    "serverHost": "protect-us.ismartlife.me",
    "userEmail": "user@example.test"
  }
}`), 0o600)
}

// TestTuyaStartOnADeadSessionIsA401WithRelogin: the UI needs a distinguishable
// signal, not an opaque 502. The session here is unusable LOCALLY (no
// fast-sid/s-sid), so the outcome does not depend on the network.
func TestTuyaStartOnADeadSessionIsA401WithRelogin(t *testing.T) {
	env := testHandler(t)
	h := env.handler
	dir := t.TempDir()
	path := filepath.Join(dir, "session.json")
	if err := writeUnusableSessionFile(path); err != nil {
		t.Fatal(err)
	}
	tuyaProvider := provider.NewTuya(path,
		provider.WithTuyaBridge(deadTuyaBridge{}),
		provider.WithTuyaResolution("sd"))
	h.SetProviders(provider.NewSet(provider.NewONVIF(env.handler.onvifClient), tuyaProvider), nil, tuyaProvider, nil)

	rec := httptest.NewRecorder()
	h.StartStream(rec, httptest.NewRequest(http.MethodPost, "/api/stream/start",
		strings.NewReader(`{"provider":"tuya","deviceId":"eb9f1d6e677b1b39f222ag"}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (%s)", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["status"] != "session_expired" || body["reloginRequired"] != true {
		t.Errorf("body = %v, want status=session_expired reloginRequired=true", body)
	}
	if strings.Contains(rec.Body.String(), "s-sid=") {
		t.Fatalf("a cookie value leaked into the start response: %s", rec.Body.String())
	}
}

// TestTuyaSessionOnAnUnusableFileDistinguishesTheReason: an unusable file must
// not be reported as "the file is absent".
func TestTuyaSessionOnAnUnusableFileDistinguishesTheReason(t *testing.T) {
	env := testHandler(t)
	h := env.handler
	dir := t.TempDir()
	path := filepath.Join(dir, "session.json")
	if err := writeUnusableSessionFile(path); err != nil {
		t.Fatal(err)
	}
	tuyaProvider := provider.NewTuya(path)
	h.SetProviders(provider.NewSet(provider.NewONVIF(env.handler.onvifClient)), nil, tuyaProvider, nil)

	rec := httptest.NewRecorder()
	h.TuyaSession(rec, httptest.NewRequest(http.MethodGet, "/api/tuya/session", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := decodeBody(t, rec)
	if body["configured"] != true {
		t.Errorf("configured = %#v, want true (a path IS wired up)", body["configured"])
	}
	if body["filePresent"] != false {
		t.Errorf("filePresent = %#v, want false (the file cannot yield a usable session)", body["filePresent"])
	}
	if body["cloudVerified"] != false || body["valid"] != false {
		t.Errorf("body = %v, want cloudVerified=false valid=false", body)
	}
	if body["expiryKnown"] != false || body["expiresAt"] != nil {
		t.Errorf("body = %v, want expiryKnown=false expiresAt=null", body)
	}
	if body["reloginRequired"] != true {
		t.Errorf("reloginRequired = %#v, want true", body["reloginRequired"])
	}
}

// newTestLoginManager builds a LoginManager over a file path.
func newTestLoginManager(path string) *provider.LoginManager {
	return provider.NewLoginManager(provider.WithLoginSessionFile(path))
}

// writeTestSessionFile writes a session file with the cookie pair discovery
// needs, so path-based behaviour can be exercised without a real scan.
func writeTestSessionFile(path string) error {
	return tuyaqr.SaveSession(path, &tuyaqr.Session{
		Region: "us-west", Email: "user@example.test", UserKey: "us-west_user_at_example_test",
		LastRefresh: time.Now(),
		SessionData: tuyaqr.UserSession{
			LoginResult:   &tuyaqr.LoginResult{UID: "az1", Email: "user@example.test"},
			LastValidated: time.Now(),
			ServerHost:    tuyaqr.DefaultHost,
			Region:        "us-west",
			UserEmail:     "user@example.test",
			Cookies: []*tuyaqr.Cookie{
				{Name: "gTyPlatLang", Value: "en"},
				{Name: "locale", Value: "en"},
				{Name: "fast-sid", Value: strings.Repeat("a", 32)},
				{Name: "s-sid", Value: strings.Repeat("b", 82)},
			},
		},
	})
}
