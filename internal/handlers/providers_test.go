package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/onvif"
	"dengan.dev/camera-streamer/internal/provider"
	"dengan.dev/camera-streamer/internal/stream"
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
