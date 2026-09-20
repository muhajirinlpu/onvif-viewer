package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"dengan.dev/camera-streamer/internal/models"
	"dengan.dev/camera-streamer/internal/provider"
)

// SetProviders wires the provider registry and the QR login manager into the
// handler. It is optional: an ONVIF-only install never calls it and every
// provider endpoint then answers 503 with an explanatory detail instead of
// disappearing from the route table.
//
// tuya is the concrete Tuya provider used for the streaming path (nil when Tuya
// is not configured). onSessionCaptured runs after a successful QR scan so the
// provider reloads the new session file.
func (h *Handler) SetProviders(set *provider.Set, logins *provider.LoginManager, tuya *provider.Tuya, onSessionCaptured func()) {
	h.providers = set
	h.logins = logins
	h.tuyaProvider = tuya
	h.onTuyaSession = onSessionCaptured
}

// ProviderCameras serves GET /api/providers/cameras?provider=tuya|onvif and
// POST /api/providers/cameras.
//
// GET is the Tuya path and the all-providers path. POST exists because ONVIF
// discovery is credential-scoped: it needs cameraIp/username/password, and those
// must never travel in a URL (they would land in logs and browser history). So
// the ONVIF variant is POST-only with a JSON body.
//
// Response:
//
//	{
//	  "provider": "tuya",              // echoed when one was requested
//	  "providers": ["onvif","tuya"],   // registered providers
//	  "cameras": [ { "id":..., "name":..., "provider":"tuya", "detail":..., "online":true } ],
//	  "errors": ["tuya: ..."]          // per-provider failures, never secret-bearing
//	}
func (h *Handler) ProviderCameras(w http.ResponseWriter, r *http.Request) {
	if h.providers == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"detail": "no camera providers are configured in this process",
		})
		return
	}

	requested := strings.TrimSpace(r.URL.Query().Get("provider"))

	if r.Method == http.MethodPost {
		h.providerCamerasPost(w, r)
		return
	}

	if requested != "" {
		kind := provider.Kind(requested)
		if _, err := h.providers.Get(kind); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"detail": err.Error()})
			return
		}
		if kind == provider.KindONVIF {
			// Deliberately not an error: the UI legitimately asks for the ONVIF
			// list while a camera is configured in the form. ONVIF has no
			// account to enumerate, so the answer is "none listed here" plus
			// why, and the ONVIF form stays the way it always was.
			writeJSON(w, http.StatusOK, map[string]any{
				"provider":  string(kind),
				"providers": kindsToStrings(h.providers.Kinds()),
				"cameras":   []provider.Camera{},
				"detail":    "ONVIF cameras are listed per camera: POST /api/providers/cameras with cameraIp, cameraPort, username, password",
			})
			return
		}
		cams, err := h.providers.Cameras(r.Context(), kind)
		if err != nil {
			h.respondProviderError(w, kind, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"provider":  string(kind),
			"providers": kindsToStrings(h.providers.Kinds()),
			"cameras":   cams,
		})
		return
	}

	cams, errs := h.providers.CamerasFromAll(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"providers": kindsToStrings(h.providers.Kinds()),
		"cameras":   cams,
		"errors":    errorStrings(errs),
	})
}

// providerCamerasPost lists the media profiles of ONE ONVIF camera. Credentials
// travel in the body, are used for the SOAP call and are never persisted or
// echoed back.
func (h *Handler) providerCamerasPost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider string `json:"provider"`
		models.CameraRequest
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if want := strings.TrimSpace(req.Provider); want != "" && provider.Kind(want) != provider.KindONVIF {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "POST is only used for provider=onvif; use GET for other providers"})
		return
	}
	onvifProvider, ok := h.onvifProvider()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"detail": "the ONVIF provider is not configured in this process"})
		return
	}
	if req.CameraIp == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "cameraIp is required"})
		return
	}
	if req.CameraPort == "" {
		req.CameraPort = "8000"
	}
	cams, err := onvifProvider.CamerasFor(r.Context(), req.CameraRequest)
	if err != nil {
		h.logger.LogWarn("", "provider", fmt.Sprintf("ONVIF camera listing failed for %s:%s: %v", req.CameraIp, req.CameraPort, err))
		writeJSON(w, http.StatusBadGateway, map[string]any{"detail": "camera did not answer GetProfiles"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"provider":  string(provider.KindONVIF),
		"providers": kindsToStrings(h.providers.Kinds()),
		"cameras":   cams,
	})
}

// TuyaLoginBegin serves POST /api/tuya/login/begin.
//
// Response 200:
//
//	{
//	  "token": "...",                 // needed by the poll call
//	  "qrPng": "data:image/png;base64,...",
//	  "expiresAt": "2026-09-19T12:00:00Z",
//	  "remainingSeconds": 690,
//	  "ttlSeconds": 720,
//	  "host": "protect-us.ismartlife.me"
//	}
func (h *Handler) TuyaLoginBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.logins == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"detail": "Tuya login is not configured in this process"})
		return
	}
	ticket, err := h.logins.Begin(r.Context())
	if err != nil {
		h.logger.LogWarn("", "tuya", fmt.Sprintf("QR login could not start: %v", err))
		writeJSON(w, http.StatusBadGateway, map[string]any{"detail": "could not start Tuya QR login"})
		return
	}
	// Token length only: the token itself must never reach the logs.
	h.logger.LogInfo("", "tuya", fmt.Sprintf("QR login started (token length %d, %d s remaining)", len(ticket.Token), ticket.RemainingSeconds))
	writeJSON(w, http.StatusOK, ticket)
}

// TuyaLoginPoll serves GET /api/tuya/login/poll?token=...
//
// Responses 200:
//
//	{"status":"pending","remainingSeconds":511}
//	{"status":"expired"}
//	{"status":"done","session":{"email":"...","region":"us-west","cookieNames":[...],"cookieCount":4,"savedTo":"..."}}
//
// 410 means the token is unknown to this process (expired or a restart); the UI
// must request a new QR.
func (h *Handler) TuyaLoginPoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.logins == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"detail": "Tuya login is not configured in this process"})
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "token is required"})
		return
	}
	result, err := h.logins.Poll(r.Context(), token)
	if err != nil {
		if errors.Is(err, provider.ErrLoginUnknown) {
			writeJSON(w, http.StatusGone, map[string]any{"status": string(provider.StatusExpired), "detail": "this QR token is no longer known; request a new one"})
			return
		}
		h.logger.LogWarn("", "tuya", fmt.Sprintf("QR poll failed: %v", err))
		writeJSON(w, http.StatusBadGateway, map[string]any{"detail": "Tuya poll failed"})
		return
	}
	if result.Status == provider.StatusDone {
		h.logger.LogInfo("", "tuya", "QR login completed; session captured")
		// A fresh session must be picked up without a restart.
		if h.onTuyaSession != nil && h.tuyaProvider != nil {
			h.onTuyaSession()
		}
	}
	writeJSON(w, http.StatusOK, result)
}

// TuyaSession serves GET /api/tuya/session.
//
// Response 200 (never contains a cookie value or an sid):
//
//	{"configured":true,"valid":true,"expiresAt":null,"remainingSeconds":0,
//	 "lastRefresh":"...","cookieNames":["gTyPlatLang","locale","fast-sid","s-sid"],
//	 "detail":"accepted by the cloud; the stored cookies declare no expiry"}
func (h *Handler) TuyaSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.tuyaProvider == nil {
		writeJSON(w, http.StatusOK, &provider.SessionStatus{Configured: false, Valid: false, Detail: "Tuya is not configured in this process"})
		return
	}
	status, err := h.tuyaProvider.Session(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"configured": true, "valid": false, "detail": "session check failed"})
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// respondProviderError maps a discovery failure onto a status the UI can act on:
// 401 when the stored session is dead (scan a new QR), 502 otherwise.
func (h *Handler) respondProviderError(w http.ResponseWriter, kind provider.Kind, err error) {
	if provider.SessionExpired(err) {
		h.logger.LogWarn("", string(kind), "stored Tuya session was rejected; a new QR scan is required")
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"detail":  "the stored Tuya session is no longer valid; scan a new QR code",
			"status":  "session_expired",
			"cameras": []provider.Camera{},
		})
		return
	}
	h.logger.LogWarn("", string(kind), fmt.Sprintf("camera discovery failed: %v", err))
	writeJSON(w, http.StatusBadGateway, map[string]any{
		"detail":  "camera discovery failed",
		"cameras": []provider.Camera{},
	})
}

func (h *Handler) onvifProvider() (*provider.ONVIF, bool) {
	if h.providers == nil {
		return nil, false
	}
	p, err := h.providers.Get(provider.KindONVIF)
	if err != nil {
		return nil, false
	}
	o, ok := p.(*provider.ONVIF)
	return o, ok
}

func kindsToStrings(kinds []provider.Kind) []string {
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, string(k))
	}
	return out
}

func errorStrings(errs []error) []string {
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		if e != nil {
			out = append(out, e.Error())
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
