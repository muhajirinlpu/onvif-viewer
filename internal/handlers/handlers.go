package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/models"
	"dengan.dev/camera-streamer/internal/onvif"
	"dengan.dev/camera-streamer/internal/stream"
)

// Handler contains all the HTTP handlers and their dependencies
type Handler struct {
	streamManager *stream.Manager
	onvifClient   *onvif.Client
	logger        *logger.Logger
}

// New creates a new Handler instance
func New(streamManager *stream.Manager, onvifClient *onvif.Client, logger *logger.Logger) *Handler {
	return &Handler{
		streamManager: streamManager,
		onvifClient:   onvifClient,
		logger:        logger,
	}
}

// StartStream handles stream start requests
func (h *Handler) StartStream(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProfileToken string `json:"profileToken"`
		RtspURL      string `json:"rtspUrl"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.LogError("", "http", fmt.Sprintf("Failed to decode start stream request: %v", err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.logger.LogInfo("", "http", fmt.Sprintf("Starting stream for profile %s with URL %s", req.ProfileToken, req.RtspURL))

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

	// Create a client channel
	clientChan := make(chan models.LogEntry, 10)
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

	// Send recent logs from database
	recentLogs, err := h.logger.GetRecentLogs(500)
	if err != nil {
		h.logger.LogError("", "sse", fmt.Sprintf("Failed to get recent logs: %v", err))
	} else {
		// Convert database logs to SSE format and send them
		for i := len(recentLogs) - 1; i >= 0; i-- {
			dbLog := recentLogs[i]
			entry := models.LogEntry{
				StreamID: dbLog.StreamID,
				Message:  fmt.Sprintf("[%s] %s", dbLog.Source, dbLog.Message),
				Time:     dbLog.Timestamp.Format(time.RFC3339),
			}
			data, _ := json.Marshal(entry)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}

	// Create a heartbeat ticker
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	// Keep connection open and stream logs
	for {
		select {
		case entry := <-clientChan:
			// Update last active time
			h.streamManager.UpdateClientActivity(clientID)

			// Marshal the log entry
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}

			// Write the SSE data
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()

		case <-heartbeat.C:
			// Send heartbeat and update last active time
			h.streamManager.UpdateClientActivity(clientID)

			// Send a comment as heartbeat
			fmt.Fprintf(w, ": heartbeat %s\n\n", time.Now().Format(time.RFC3339))
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