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
// provider reloads the credential from its session store. With the session in
// the project database that is a re-read of the stored row, not a file watch.
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
		// ...and the cameras that were stood down when the old session died
		// must come back WITHOUT the user re-selecting them. This is the
		// one-click recovery: the same scan that fixes the credential also
		// restarts the same streams, because their profile tokens were kept.
		if h.tuyaProvider != nil {
			resumed, failures, err := h.tuyaProvider.ResumeStreams(r.Context())
			result.ResumedStreams = resumed
			result.ResumeFailures = failures
			if resumed > 0 {
				h.logger.LogInfo("", "tuya", fmt.Sprintf("resumed %d Tuya stream(s) after the re-login; no device was re-selected", resumed))
			}
			if err != nil {
				h.logger.LogWarn("", "tuya", fmt.Sprintf("some Tuya streams could not be resumed: %v", err))
			}
		}
	}
	writeJSON(w, http.StatusOK, result)
}

// TuyaSession serves GET /api/tuya/session.
//
// The response answers FOUR independent questions instead of collapsing them
// into one misleading "valid" flag:
//
//	configured      - is a Tuya session store wired up in this process?
//	filePresent     - does a stored session load and carry fast-sid/s-sid?
//	cloudVerified   - did an ACTUAL authenticated call to the cloud succeed?
//	expiryKnown     - did the cloud ever state when the cookies expire?
//
// `filePresent` keeps its exact meaning now that the session may live in the
// project database: it is "a stored credential loads and carries the auth
// cookie pair", which is what it always meant, and it must NOT be renamed to
// something database-shaped without an equivalent, because that would quietly
// change an answer the UI gates on. `storeKind`/`storeLocation`/`storeReason`
// are ADDED so the response still says, unambiguously, WHERE the credential is.
//
// `expiryKnown:false` is an honest answer, not a failure: MEASURED, the user's
// stored session has a ZERO expiry on all four cookies, so no truthful
// countdown exists for it. `expiresAt` is then null, `remainingSeconds` is 0 and
// `expirySource` is "unknown". A countdown is only ever shown for a value the
// cloud itself reported (`expirySource: "cookie:fast-sid"`).
//
// Response 200 (valid, expiry known):
//
//	{"configured":true,"filePresent":true,"cloudVerified":true,"valid":true,
//	 "storeKind":"sqlite","storeLocation":"onvif_logs.db",
//	 "expiresAt":"2026-09-22T12:56:20Z","remainingSeconds":214000,"expiryKnown":true,
//	 "expirySource":"cookie:fast-sid","cookiesWithExpiry":3,"cookieCount":4,
//	 "checkedSecondsAgo":0,"cacheTtlSeconds":30,"reloginRequired":false,"detail":"..."}
//
// Response 200 (valid, expiry UNKNOWN — the honest case today):
//
//	{"configured":true,"filePresent":true,"cloudVerified":true,"valid":true,
//	 "storeKind":"sqlite","storeLocation":"onvif_logs.db",
//	 "expiresAt":null,"remainingSeconds":0,"expiryKnown":false,
//	 "expirySource":"unknown","cookiesWithExpiry":0,"cookieCount":4,
//	 "detail":"accepted by the cloud; the stored cookies declare no expiry, so no countdown can be shown"}
//
// Response 200 (session dead — cloud-verified, not merely absent):
//
//	{"configured":true,"filePresent":true,"cloudVerified":false,"valid":false,
//	 "reloginRequired":true,"expiredStreamsStopped":1,
//	 "detail":"the stored Tuya session was rejected by the cloud; scan a new QR code"}
func (h *Handler) TuyaSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.tuyaProvider == nil {
		writeJSON(w, http.StatusOK, &provider.SessionStatus{Configured: false, Detail: "Tuya is not configured in this process"})
		return
	}
	status, err := h.tuyaProvider.Session(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"configured": true, "valid": false, "detail": "session check failed"})
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// TuyaLogout serves POST /api/tuya/logout.
//
// It removes the stored session from this host — the database row when the
// session lives in the project store, the file when a legacy file store is
// configured. HONESTY: Tuya exposes NO server-side logout endpoint for these
// cookies, so this is local credential removal — the cookies would still be
// accepted by the cloud until they expire. Removing them is nevertheless the
// right local action: it is what makes the UI stop using a credential the user
// asked to be rid of, and it is what forces the one-click QR flow.
//
// Response 200:
//
//	{"removed":true,"sessionStore":"sqlite","storeLocation":"onvif_logs.db",
//	 "serverSideLogout":false,
//	 "detail":"the stored Tuya session was removed from this host; Tuya has no server-side logout, so the cookies remain valid at the cloud until they expire"}
type TuyaLogoutResponse struct {
	Removed bool `json:"removed"`
	// SessionFile is kept for compatibility: it names the file when the store
	// is file-backed, and the database when it is not. SessionStore is the
	// unambiguous answer.
	SessionFile string `json:"sessionFile,omitempty"`
	// SessionStore is the kind of store the credential was deleted from
	// (file|sqlite) and StoreLocation is where that store is. Neither is a
	// secret.
	SessionStore     string `json:"sessionStore,omitempty"`
	StoreLocation    string `json:"storeLocation,omitempty"`
	ServerSideLogout bool   `json:"serverSideLogout"`
	ReloginRequired  bool   `json:"reloginRequired"`
	StreamsStopped   int    `json:"streamsStopped"`
	Detail           string `json:"detail"`
}

func (h *Handler) TuyaLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.logins == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"detail": "Tuya login is not configured in this process"})
		return
	}
	removed, err := h.logins.Logout()
	if err != nil {
		h.logger.LogError("", "tuya", fmt.Sprintf("Tuya logout could not remove the stored session: %v", err))
		writeJSON(w, http.StatusInternalServerError, map[string]any{"detail": "the stored Tuya session could not be removed"})
		return
	}

	// A logout invalidates the credentials this process holds. The streams
	// cannot survive it, and stopping them here is the same "stop the bleed"
	// rule as a cloud rejection: after a deliberate logout the user IS going to
	// re-login, so the streams keep their place and can be resumed.
	stopped := 0
	if h.tuyaProvider != nil {
		h.tuyaProvider.Invalidate()
		if n, err := h.tuyaProvider.SuspendStreams(); err != nil {
			h.logger.LogWarn("", "tuya", fmt.Sprintf("logout: standing down Tuya streams: %v", err))
			stopped = n
		} else {
			stopped = n
		}
	}
	storeKind := h.logins.StoreKind()
	storeLocation := h.logins.SessionFilePath()
	h.logger.LogWarn("", "tuya", fmt.Sprintf(
		"stored Tuya session removed from the %s store (%s) — no server-side logout exists; a new QR scan is required",
		storeKind, storeLocation))

	writeJSON(w, http.StatusOK, &TuyaLogoutResponse{
		Removed:          removed,
		SessionFile:      storeLocation,
		SessionStore:     storeKind,
		StoreLocation:    storeLocation,
		ServerSideLogout: false,
		ReloginRequired:  true,
		StreamsStopped:   stopped,
		Detail: "the stored Tuya session was removed from this host; Tuya has no server-side logout, " +
			"so the cookies remain valid at the cloud until they expire",
	})
}

// TuyaResume serves POST /api/tuya/resume.
//
// It restarts the Tuya streams that were stood down when the session died (or
// when the user logged out), using whatever session file is on disk now. It is
// the second half of the one-click re-login: the UI calls this right after a
// successful scan, and the SAME cameras come back without the user re-picking
// anything, because the suspended streams kept their profile tokens.
//
// It is safe to call when nothing is suspended: it then reports resumed=0.
//
// Response 200:
//
//	{"resumed":1,"failures":[],"detail":"1 Tuya stream resumed without re-selecting a device"}
func (h *Handler) TuyaResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.tuyaProvider == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"detail": "Tuya streaming is not configured in this process"})
		return
	}
	resumed, failures, err := h.tuyaProvider.ResumeStreams(r.Context())
	if err != nil && resumed == 0 && len(failures) == 0 {
		writeJSON(w, http.StatusBadGateway, map[string]any{"detail": err.Error(), "resumed": 0})
		return
	}
	detail := fmt.Sprintf("%d Tuya stream(s) resumed without re-selecting a device", resumed)
	if len(failures) > 0 {
		detail = fmt.Sprintf("%d resumed, %d could not be resumed", resumed, len(failures))
	}
	if err != nil {
		h.logger.LogWarn("", "tuya", fmt.Sprintf("Tuya resume: %v (failures: %s)", err, strings.Join(failures, "; ")))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"resumed":  resumed,
		"failures": failures,
		"detail":   detail,
	})
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
