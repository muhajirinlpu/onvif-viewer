package models

import "time"

// CameraRequest holds the credentials and address of an ONVIF camera.
type CameraRequest struct {
	CameraIp   string `json:"cameraIp"`
	CameraPort string `json:"cameraPort"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}

// GetStreamUriRequest is used for GetStreamUri requests, embedding CameraRequest.
type GetStreamUriRequest struct {
	CameraRequest
	ProfileToken string `json:"profileToken"`
}

// StreamInfo contains information about an active FFmpeg stream.
type StreamInfo struct {
	ID           string    `json:"id"`
	ProfileToken string    `json:"profileToken"`
	RtspURL      string    `json:"rtspUrl"`
	HlsURL       string    `json:"hlsUrl"`
	StartedAt    time.Time `json:"startedAt"`
	Status       string    `json:"status"`
}

// ClientConnection represents a connection for a Server-Sent Events (SSE) client.
type ClientConnection struct {
	Channel    chan LogEntry
	LastActive time.Time
}

// LogEntry represents a single log message for SSE.
type LogEntry struct {
	StreamID string `json:"streamId"`
	Message  string `json:"message"`
	Time     string `json:"time"`
}
