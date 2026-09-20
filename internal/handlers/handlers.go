package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/models"
	"dengan.dev/camera-streamer/internal/onvif"
	"dengan.dev/camera-streamer/internal/provider"
	"dengan.dev/camera-streamer/internal/stream"
	"dengan.dev/camera-streamer/internal/tuyaengine"
)

// Handler contains all the HTTP handlers and their dependencies
type Handler struct {
	streamManager *stream.Manager
	onvifClient   *onvif.Client
	logger        *logger.Logger

	// Provider seam. Optional: nil means "ONVIF only", which is exactly the
	// pre-milestone behaviour. Wire them with SetProviders.
	providers    *provider.Set
	logins       *provider.LoginManager
	tuyaProvider *provider.Tuya
	// onTuyaSession is invoked when a new Tuya session has been captured, so
	// the discovery provider drops any cached session without a restart.
	onTuyaSession func()
}

// New creates a new Handler instance
func New(streamManager *stream.Manager, onvifClient *onvif.Client, logger *logger.Logger) *Handler {
	return &Handler{
		streamManager: streamManager,
		onvifClient:   onvifClient,
		logger:        logger,
	}
}

// StartStream handles stream start requests.
//
// The ONVIF contract is unchanged: {profileToken, rtspUrl} starts the URL
// directly, exactly as before. The additive fields are OPTIONAL and only used
// for the Tuya path:
//
//	{"provider":"tuya","deviceId":"eb9f1d6e677b1b39f222ag"}
//	{"provider":"tuya","deviceId":"...","resolution":"hd"}
//
// A Tuya request carries no rtspUrl on purpose: the RTSP endpoint is allocated
// by the in-process engine and must not be spoofed by the browser.
//
// `resolution` is the only field that changes what the pipeline emits. Omitting
// it means "the resolution already stored for this camera", so the existing UI
// call above keeps producing SD and nothing changes for a user who does not opt
// in.
func (h *Handler) StartStream(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProfileToken string `json:"profileToken"`
		RtspURL      string `json:"rtspUrl"`
		Provider     string `json:"provider"`
		DeviceID     string `json:"deviceId"`
		Resolution   string `json:"resolution"`
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.LogError("", "http", fmt.Sprintf("Failed to decode start stream request: %v", err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Tuya path: only taken when the caller actually says provider=tuya (or
	// names a deviceId without an rtspUrl), so ONVIF requests cannot regress.
	if models.ProviderKind(req.Provider).OrDefault() == models.ProviderTuya || (req.DeviceID != "" && req.RtspURL == "") {
		h.startTuyaStream(w, r, req.DeviceID, req.Resolution)
		return
	}

	h.logger.LogInfo("", "http", fmt.Sprintf("Starting stream for profile %s", req.ProfileToken))

	streamInfo, err := h.streamManager.StartStream(req.ProfileToken, req.RtspURL)
	if err != nil {
		h.logger.LogError("", "http", fmt.Sprintf("Failed to start stream: %v", err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(streamInfo); err != nil {
		h.logger.LogError(streamInfo.ID, "http", fmt.Sprintf("Failed to encode response: %v", err))
	}
}

// startTuyaStream routes a Tuya device through the in-process bridge. The
// response body is the same models.StreamInfo shape the ONVIF path returns, with
// provider="tuya".
//
// A Tuya stream that cannot start because the stored session is dead answers 401
// with `reloginRequired:true` rather than an opaque 502, because the only way out
// is a fresh QR scan and the UI must be able to say so.
//
// An unparseable resolution is a 400 and NOTHING is started: silently falling
// back to SD would make a typo look like a successful switch to HD.
func (h *Handler) startTuyaStream(w http.ResponseWriter, r *http.Request, deviceID string, resolution string) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "deviceId is required for provider=tuya"})
		return
	}
	if h.tuyaProvider == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"detail": "Tuya streaming is not configured in this process"})
		return
	}
	if err := logger.ValidateResolution(resolution); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": err.Error()})
		return
	}
	info, err := h.tuyaProvider.StartStreamAt(deviceID, resolution)
	if err != nil {
		if errors.Is(err, provider.ErrSessionReloginRequired) {
			// The cloud rejected the stored session: any Tuya stream already
			// running has just been stood down for the same reason.
			h.logger.LogWarn("", "tuya", "Tuya stream start refused: the stored session is dead; a new QR scan is required")
			stopped := 0
			// The cached status is populated by the degradation above, so this
			// is a cache read rather than a second cloud call.
			if status, serr := h.tuyaProvider.Session(r.Context()); serr == nil && status != nil {
				stopped = status.ExpiredStreamsStopped
			}
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"detail":          "the stored Tuya session is no longer valid; scan a new QR code",
				"status":          "session_expired",
				"reloginRequired": true,
				"streamsStopped":  stopped,
			})
			return
		}
		h.logger.LogError("", "tuya", fmt.Sprintf("Failed to start Tuya stream: %v", err))
		writeJSON(w, http.StatusBadGateway, map[string]any{"detail": "could not start the Tuya stream"})
		return
	}
	h.logger.LogInfo(info.ID, "tuya", fmt.Sprintf("Tuya stream started through the shared HLS pipeline (resolution=%s)", info.Resolution))
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(info); err != nil {
		h.logger.LogError(info.ID, "http", fmt.Sprintf("Failed to encode response: %v", err))
	}
}

// SetTuyaResolution serves POST /api/tuya/resolution.
//
// Body: {"deviceId":"eb9f1d6e677b1b39f222ag","resolution":"hd"}
//
// It records the per-camera choice WITHOUT starting or restarting anything, so
// the UI can persist a preference and say honestly that it applies to the next
// start. Switching a RUNNING stream's resolution is deliberately not done here:
// that is a stop+start, which the UI performs explicitly so the user sees the
// stream drop rather than a silent restart.
//
// Response 200:
//
//	{"deviceId":"...","resolution":"hd","appliesTo":"the next start of this camera",
//	 "cpuCost":"...","restartRequired":true}
func (h *Handler) SetTuyaResolution(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.tuyaProvider == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"detail": "Tuya streaming is not configured in this process"})
		return
	}
	var req struct {
		DeviceID   string `json:"deviceId"`
		Resolution string `json:"resolution"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "invalid request"})
		return
	}
	resolved, err := h.tuyaProvider.SetResolution(req.DeviceID, req.Resolution)
	if err != nil {
		h.logger.LogWarn("", "tuya", fmt.Sprintf("resolution change rejected: %v", err))
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": err.Error()})
		return
	}
	// Say whether this needs a restart, and report the CPU cost truthfully
	// rather than describing HD as free.
	//
	// "Restart required" means a Tuya stream for this camera is ALREADY running
	// at a different resolution: the persisted choice cannot take effect on a
	// live ffmpeg, because switching the output path means replacing the process.
	// Saying so is the difference between a preference and a silent no-op.
	restartRequired := false
	token, tokenErr := tuyaengine.ProfileTokenFor(req.DeviceID)
	if tokenErr == nil {
		for _, s := range h.streamManager.ListStreams() {
			if s.ProfileToken == token && s.Resolution != resolved {
				restartRequired = true
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"deviceId":        req.DeviceID,
		"resolution":      resolved,
		"profileToken":    token,
		"appliesTo":       "the next start of this camera",
		"restartRequired": restartRequired,
		"cpuCost":         hdCPUWarning(resolved),
	})
}

// hdCPUWarning is the honest cost statement attached to a resolution, in the
// same words the UI shows. HD is a SOFTWARE libx264 transcode of a 1440p HEVC
// source on a 4-core host; it is not free and it competes with every other
// stream for the same cores, so it is described as such rather than as
// "higher quality".
func hdCPUWarning(resolution string) string {
	if logger.NormalizeResolution(resolution) == "hd" {
		return "HD re-encodes 2560x1440 HEVC to H.264 1280x720 in SOFTWARE (the video decoder " +
			"is not available to this user). It will use a large share of this 4-core host's CPU " +
			"and can affect other streams. 1440p is NOT offered because it does not keep up."
	}
	return "SD copies the camera's H.264 stream without re-encoding: no transcoding CPU cost."
}

// Snapshot returns one current JPEG frame from an active HLS stream.
func (h *Handler) Snapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	streamID := r.URL.Query().Get("id")
	if streamID == "" {
		http.Error(w, "missing stream ID", http.StatusBadRequest)
		return
	}

	jpeg, err := h.streamManager.Snapshot(streamID)
	if err != nil {
		h.logger.LogError(streamID, "snapshot", fmt.Sprintf("Failed to capture snapshot: %v", err))
		http.Error(w, "snapshot unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(jpeg)))
	_, _ = w.Write(jpeg)
}

// StopStream handles stream stop requests
func (h *Handler) StopStream(w http.ResponseWriter, r *http.Request) {
	streamID := r.URL.Query().Get("id")
	if streamID == "" {
		http.Error(w, "Missing stream ID", http.StatusBadRequest)
		return
	}

	h.logger.LogInfo(streamID, "http", "Stopping stream via HTTP request")

	if err := h.streamManager.StopStream(streamID); err != nil {
		h.logger.LogError(streamID, "http", fmt.Sprintf("Failed to stop stream: %v", err))
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ListStreams handles stream listing requests
func (h *Handler) ListStreams(w http.ResponseWriter, r *http.Request) {
	streams := h.streamManager.ListStreams()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(streams); err != nil {
		h.logger.LogError("", "http", fmt.Sprintf("Failed to encode streams list: %v", err))
	}
}

// DiagnoseStream runs non-destructive network and service reachability checks.
func (h *Handler) DiagnoseStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	detail, err := h.streamManager.DiagnoseStream(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": detail})
}

// ReconnectStream requests a controlled FFmpeg/RTSP reconnect.
func (h *Handler) ReconnectStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := h.streamManager.ReconnectStream(r.URL.Query().Get("id")); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// SynchronizeStream asks ONVIF Media to inject a synchronization point/I-frame.
func (h *Handler) SynchronizeStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		models.GetStreamUriRequest
		StreamID string `json:"streamId"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.CameraPort == "" {
		req.CameraPort = "8000"
	}
	if req.CameraIp == "" || req.Username == "" || req.Password == "" || req.ProfileToken == "" || req.StreamID == "" {
		http.Error(w, "stream, camera address, credentials, and profile token are required", http.StatusBadRequest)
		return
	}
	if err := h.streamManager.ValidateCameraForStream(req.StreamID, req.CameraIp, req.ProfileToken); err != nil {
		http.Error(w, "camera does not match selected stream", http.StatusConflict)
		return
	}
	if err := h.onvifClient.SetSynchronizationPoint(req.CameraRequest, req.ProfileToken); err != nil {
		h.logger.LogError("", "onvif", fmt.Sprintf("Synchronization request failed: %v", err))
		http.Error(w, "camera synchronization request failed", http.StatusBadGateway)
		return
	}
	h.logger.LogInfo("", "onvif", "Synchronization point requested")
	w.WriteHeader(http.StatusAccepted)
}

// GetStreamUri handles ONVIF GetStreamUri requests
func (h *Handler) GetStreamUri(w http.ResponseWriter, r *http.Request) {
	var req models.GetStreamUriRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.LogError("", "http", fmt.Sprintf("Failed to decode GetStreamUri request: %v", err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Set default port if not provided
	if req.CameraPort == "" {
		req.CameraPort = "8000"
	}

	h.logger.LogInfo("", "onvif", fmt.Sprintf("GetStreamUri request for camera %s:%s", req.CameraIp, req.CameraPort))

	// First get profiles if no token provided
	if req.ProfileToken == "" {
		profilesResponse, err := h.onvifClient.GetProfiles(req.CameraRequest)
		if err != nil {
			h.logger.LogError("", "onvif", fmt.Sprintf("Failed to get profiles: %v", err))
			http.Error(w, fmt.Sprintf("Failed to get profiles: %v", err), http.StatusInternalServerError)
			return
		}

		token, err := onvif.ExtractProfileToken(profilesResponse)
		if err != nil {
			h.logger.LogError("", "onvif", "No profile token found in response")
			http.Error(w, "No profile token found", http.StatusInternalServerError)
			return
		}
		req.ProfileToken = token
		h.logger.LogInfo("", "onvif", fmt.Sprintf("Extracted profile token: %s", token))
	}

	// Get stream URI with profile token
	streamUriResponse, err := h.onvifClient.GetStreamUri(req.CameraRequest, req.ProfileToken)
	if err != nil {
		h.logger.LogError("", "onvif", fmt.Sprintf("Failed to get stream URI: %v", err))
		http.Error(w, fmt.Sprintf("Failed to get stream URI: %v", err), http.StatusInternalServerError)
		return
	}

	// Prepare response
	url := fmt.Sprintf("http://%s:%s/%s", req.CameraIp, req.CameraPort, onvif.GetStreamUri.URI())
	envelope := onvif.GetStreamUri.Envelope(req.CameraRequest, req.ProfileToken)

	response := map[string]interface{}{
		"url":         url,
		"envelope":    envelope,
		"rawResponse": streamUriResponse,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.LogError("", "http", fmt.Sprintf("Failed to encode GetStreamUri response: %v", err))
	}
}

// GetSystemDateAndTime handles ONVIF GetSystemDateAndTime requests
func (h *Handler) GetSystemDateAndTime(w http.ResponseWriter, r *http.Request) {
	var req models.CameraRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.LogError("", "http", fmt.Sprintf("Failed to decode GetSystemDateAndTime request: %v", err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Set default port if not provided
	if req.CameraPort == "" {
		req.CameraPort = "8000"
	}

	h.logger.LogInfo("", "onvif", fmt.Sprintf("GetSystemDateAndTime request for camera %s:%s", req.CameraIp, req.CameraPort))

	// Get system date and time
	systemDateAndTimeResponse, err := h.onvifClient.GetSystemDateAndTime(req)
	if err != nil {
		h.logger.LogError("", "onvif", fmt.Sprintf("Failed to get system date and time: %v", err))
		http.Error(w, fmt.Sprintf("Failed to get system date and time: %v", err), http.StatusInternalServerError)
		return
	}

	// Prepare response
	url := fmt.Sprintf("http://%s:%s/%s", req.CameraIp, req.CameraPort, onvif.GetSystemDateAndTime.URI())
	envelope := onvif.GetSystemDateAndTime.Envelope(req)

	response := map[string]interface{}{
		"url":         url,
		"envelope":    envelope,
		"rawResponse": systemDateAndTimeResponse,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.LogError("", "http", fmt.Sprintf("Failed to encode GetSystemDateAndTime response: %v", err))
	}
}

// FuncTest handles ONVIF function testing requests
func (h *Handler) FuncTest(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.LogError("", "http", "Failed to read request body")
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req map[string]interface{}
	if err := json.Unmarshal(body, &req); err != nil {
		h.logger.LogError("", "http", "Invalid JSON payload")
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	var camReq models.CameraRequest
	if err := json.Unmarshal(body, &camReq); err != nil {
		h.logger.LogError("", "http", "Invalid camera request JSON")
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Set default port
	if camReq.CameraPort == "" {
		camReq.CameraPort = "8000"
	}

	funcName, ok := req["func"].(string)
	if !ok {
		http.Error(w, "Missing or invalid 'func' field", http.StatusBadRequest)
		return
	}

	h.logger.LogInfo("", "onvif", fmt.Sprintf("Testing function %s for camera %s:%s", funcName, camReq.CameraIp, camReq.CameraPort))

	cameraFunction := onvif.ToCameraFunction(funcName)
	if cameraFunction == "" {
		h.logger.LogError("", "onvif", fmt.Sprintf("Unknown function: %s", funcName))
		http.Error(w, "Unknown function", http.StatusBadRequest)
		return
	}

	resp, err := h.onvifClient.SendRequest(camReq, cameraFunction, "")
	if err != nil {
		h.logger.LogError("", "onvif", fmt.Sprintf("Failed to send SOAP request: %v", err))
		http.Error(w, fmt.Sprintf("Failed to send SOAP request: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	soapResponse, err := io.ReadAll(resp.Body)
	if err != nil {
		h.logger.LogError("", "onvif", "Failed to read SOAP response")
		http.Error(w, "Failed to read SOAP response", http.StatusInternalServerError)
		return
	}

	// Prepare response
	url := fmt.Sprintf("http://%s:%s/%s", camReq.CameraIp, camReq.CameraPort, cameraFunction.URI())
	envelope := cameraFunction.Envelope(camReq)

	response := map[string]interface{}{
		"url":         url,
		"envelope":    envelope,
		"rawResponse": string(soapResponse),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.LogError("", "http", fmt.Sprintf("Failed to encode response: %v", err))
	}
}

// LogEvents handles SSE connections for streaming logs
func (h *Handler) LogEvents(w http.ResponseWriter, r *http.Request) {
	// Set headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("X-Accel-Buffering", "no") // Prevent Nginx from buffering SSE streams and stalling the connection

	// Create a client channel with a much larger buffer for FFmpeg burst logs
	clientChan := make(chan models.LogEntry, 500)
	clientID := fmt.Sprintf("client-%d", time.Now().UnixNano())

	// Add this client to the active SSE clients
	client := &models.ClientConnection{
		Channel:    clientChan,
		LastActive: time.Now(),
	}
	h.streamManager.AddSSEClient(clientID, client)

	// Remove client when connection closes
	defer func() {
		h.streamManager.RemoveSSEClient(clientID)
		h.logger.LogInfo("", "sse", fmt.Sprintf("SSE client %s disconnected", clientID))
	}()

	// Flush the response writer to send the headers
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}
	flusher.Flush()

	h.logger.LogInfo("", "sse", fmt.Sprintf("New SSE client connected: %s", clientID))

	// AddSSEClient queued distinct current-state snapshots. Historical FFmpeg
	// logs are intentionally not replayed because they are stale and noisy.

	// Create a heartbeat ticker
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	// Keep connection open and stream logs
	for {
		select {
		case entry, ok := <-clientChan:
			if !ok {
				// Channel safely closed, exit to prevent 100% CPU infinite spinning
				return
			}

			// Marshal the log entry
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}

			// Write the SSE data
			if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
				return // Client connection naturally severed
			}
			flusher.Flush()

		case <-heartbeat.C:
			// Send heartbeat and update last active time
			h.streamManager.UpdateClientActivity(clientID)

			// Send a comment as heartbeat
			if _, err := fmt.Fprintf(w, ": heartbeat %s\n\n", time.Now().Format(time.RFC3339)); err != nil {
				return // Client connection naturally severed
			}
			flusher.Flush()

		case <-r.Context().Done():
			// Client disconnected
			return
		}
	}
}

// GetLogs handles requests for historical logs
func (h *Handler) GetLogs(w http.ResponseWriter, r *http.Request) {
	streamID := r.URL.Query().Get("streamId")
	limitStr := r.URL.Query().Get("limit")

	limit := 100 // default
	if limitStr != "" {
		if parsed, err := fmt.Sscanf(limitStr, "%d", &limit); err != nil || parsed != 1 {
			limit = 100
		}
	}

	var logs []logger.StreamLog
	var err error

	if streamID != "" {
		logs, err = h.logger.GetStreamLogs(streamID, limit)
	} else {
		logs, err = h.logger.GetRecentLogs(limit)
	}

	if err != nil {
		h.logger.LogError("", "http", fmt.Sprintf("Failed to get logs: %v", err))
		http.Error(w, fmt.Sprintf("Failed to get logs: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(logs); err != nil {
		h.logger.LogError("", "http", fmt.Sprintf("Failed to encode logs response: %v", err))
	}
}
