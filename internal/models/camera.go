package models

import (
	"encoding/json"
	"time"
)

// ProviderKind identifies the subsystem a camera stream comes from. It lives
// here (rather than in internal/provider) because StreamInfo carries it, and
// models must stay a leaf package: internal/provider aliases it, so callers can
// import either name.
type ProviderKind string

// The providers a stream can belong to.
const (
	// ProviderONVIF is the default and the only provider that existed before
	// the multi-provider milestone. Every legacy row and every request that
	// does not name a provider is treated as ONVIF.
	ProviderONVIF ProviderKind = "onvif"
	// ProviderTuya is a Tuya/Smart Life camera fed through the in-process
	// Tuya->RTSP engine.
	ProviderTuya ProviderKind = "tuya"
)

// OrDefault returns the provider itself, or ONVIF when unset. Use it wherever an
// absent value must not be allowed to mean "unknown".
func (k ProviderKind) OrDefault() ProviderKind {
	if k == "" {
		return ProviderONVIF
	}
	return k
}

// MarshalJSON always emits a concrete provider: a stream that predates the
// provider column, or one created by a legacy code path, is reported as
// "onvif" rather than as an empty string.
func (k ProviderKind) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(k.OrDefault()))
}

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
	ID             string       `json:"id"`
	ProfileToken   string       `json:"profileToken"`
	Provider       ProviderKind `json:"provider"`
	RtspURL        string       `json:"-"`
	HlsURL         string       `json:"hlsUrl"`
	StartedAt      time.Time    `json:"startedAt"`
	Status         string       `json:"status"`
	ReconnectCount int          `json:"reconnectCount"`
	ReconnectDelay string       `json:"reconnectDelay,omitempty"`
	LastHLSAdvance *time.Time   `json:"lastHlsAdvance,omitempty"`
	Detail         string       `json:"detail,omitempty"`
}

// ClientConnection represents a connection for a Server-Sent Events (SSE) client.
type ClientConnection struct {
	Channel    chan LogEntry
	LastActive time.Time
}

// LogEntry represents a single log message for SSE.
type LogEntry struct {
	Type     string      `json:"type,omitempty"`
	StreamID string      `json:"streamId"`
	Message  string      `json:"message"`
	Time     string      `json:"time"`
	State    *StreamInfo `json:"state,omitempty"`
}
