package models

import (
	"encoding/json"
	"net/url"
	"strings"
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
	ID           string       `json:"id"`
	ProfileToken string       `json:"profileToken"`
	Provider     ProviderKind `json:"provider"`
	Resolution   string       `json:"resolution"`
	RtspURL      string       `json:"-"`
	HlsURL       string       `json:"hlsUrl"`
	StartedAt    time.Time    `json:"startedAt"`
	Status       string       `json:"status"`
	// StreamLabel is the DISPLAY-ONLY, non-secret name of the CAMERA behind
	// this stream. It exists because the card title used to be `stream.id`
	// ("stream_1789961119825723855"), which is unreadable when several cameras
	// are on screen, and because the browser CANNOT derive a better name: the
	// only field that carries a camera address, RtspURL, is deliberately
	// `json:"-"` (an RTSP URL can carry credentials).
	//
	// It consequently carries NO credential material by construction:
	//   - ONVIF: the HOST of the RTSP URL only (no userinfo, no path, no port
	//     userinfo), built by CameraLabelFromRTSPURL;
	//   - Tuya: the cloud device name ("Security Camera"), which the provider
	//     caches from its own device listing, or a short device id.
	//
	// Empty means "the server could not name this camera", and the UI then
	// falls back to its own shortened id.
	StreamLabel string `json:"streamLabel,omitempty"`
	// ReconnectCount is how many reconnect attempts this stream has made.
	ReconnectCount int `json:"reconnectCount"`
	// ReconnectDelay is the pending backoff before the next attempt.
	ReconnectDelay string `json:"reconnectDelay,omitempty"`
	// LastHLSAdvance is when the HLS playlist last moved forward.
	LastHLSAdvance *time.Time `json:"lastHlsAdvance,omitempty"`
	// Detail is a secret-free explanation of the stream's current condition.
	Detail string `json:"detail,omitempty"`
	// Output reports which video output path this stream's ffmpeg is on:
	// "copy_mpegts" (the original, only path for ONVIF and Tuya SD) or
	// "transcode_h264" (Tuya HD). It is reported so the UI can say what is
	// actually running rather than what was requested.
	Output string `json:"output,omitempty"`
	// InputTimestamps reports how this stream's ffmpeg decides the time base of
	// the input: "camera" (it trusts the camera's own RTP timestamps, which is
	// every ONVIF stream and Tuya HD) or "wallclock" (it re-stamps the input by
	// arrival with -use_wallclock_as_timestamps 1, which is Tuya SD).
	//
	// It exists because Output CANNOT carry this distinction honestly: the Tuya
	// SD path and the ONVIF/SD path genuinely share the same container and
	// encoder ("copy_mpegts"), so a stream where the camera's RTP clock runs
	// ahead of what it delivers — and therefore stutters — would otherwise be
	// indistinguishable from a healthy one in /api/stream/list and in the logs.
	InputTimestamps string `json:"inputTimestamps,omitempty"`
	// Transcoding is true when this stream is re-encoding video in software.
	// HD is the only case today, and it costs real CPU on this 4-core host, so
	// the fact is reported explicitly instead of being inferred from the
	// resolution by every consumer.
	Transcoding bool `json:"transcoding"`
	// Suspended is true when the stream was deliberately stood down and can be
	// resumed by a re-login (Tuya session loss). A suspended stream is still
	// listed so its card stays visible and explains itself.
	Suspended bool `json:"suspended,omitempty"`
	// SuspendedReason is a secret-free explanation of why it was suspended.
	SuspendedReason string `json:"suspendedReason,omitempty"`
}

// CameraLabelFromRTSPURL returns the HOST of an RTSP URL, for display on a
// stream card, and NEVER any credential material.
//
// This is the fix for the unreadable card title. The browser cannot derive the
// camera's address itself: models.StreamInfo.RtspURL is `json:"-"` because an
// RTSP URL can be `rtsp://user:pass@host/...`, so the host has to be published
// as its own field - and it must be stripped here, at the one place that reads
// the URL, rather than trusted to a template.
//
// url.Parse puts userinfo in URL.User, so reading URL.Hostname() (and NOT
// URL.Host, which KEEPS the userinfo) is what makes the stripping structural
// rather than a string filter. An unparseable URL that still looks like an RTSP
// URL is salvaged by hand, and the salvaged form is userinfo-stripped too; a
// value that is not an RTSP URL at all yields "" so the caller falls back to a
// shortened id rather than showing garbage.
func CameraLabelFromRTSPURL(rawURL string) string {
	raw := strings.TrimSpace(rawURL)
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Scheme != "" {
		if host := parsed.Hostname(); host != "" {
			return host
		}
	}
	// Salvage an unparseable value ("rtsp://user:pass@10.0.0.4:554/..." with
	// something url.Parse rejects). Everything before the first "/" after the
	// scheme is authority; the userinfo, if any, ends at the LAST "@" in it.
	rest := raw
	if idx := strings.Index(rest, "://"); idx >= 0 {
		rest = rest[idx+3:]
	} else {
		return ""
	}
	if idx := strings.IndexAny(rest, "/?#"); idx >= 0 {
		rest = rest[:idx]
	}
	if idx := strings.LastIndex(rest, "@"); idx >= 0 {
		rest = rest[idx+1:]
	}
	// Strip the port, keeping bracketed IPv6 literals intact.
	if strings.HasPrefix(rest, "[") {
		if end := strings.Index(rest, "]"); end >= 0 {
			return rest[1:end]
		}
		return ""
	}
	if idx := strings.LastIndex(rest, ":"); idx >= 0 {
		rest = rest[:idx]
	}
	return strings.TrimSpace(rest)
}

// CameraLabelOrLabel is the LAST-LINE defence applied to any string that is
// about to be published as a card title.
//
// The normal path builds the label from the RTSP host (CameraLabelFromRTSPURL)
// or from a Tuya device name, both already credential-free. This function
// exists so that the safety of the browser-facing field does not depend on
// every future caller remembering that: a label that is actually a URL is
// reduced to its host, and a scheme-less "user:pass@host" loses its userinfo.
// A plain name - "Security Camera" - is returned unchanged, so it can never
// mangle a real camera name.
func CameraLabelOrLabel(label string) string {
	trimmed := strings.TrimSpace(label)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "://") {
		return CameraLabelFromRTSPURL(trimmed)
	}
	if idx := strings.LastIndex(trimmed, "@"); idx >= 0 && strings.Contains(trimmed[:idx], ":") {
		// "user:pass@host" with no scheme: the credentials end at the LAST "@",
		// and the colon before it is what makes this userinfo rather than a
		// device name that happens to contain an "@".
		return strings.TrimSpace(trimmed[idx+1:])
	}
	return trimmed
}

// ShortStreamID reduces an internal stream id or a profile token to a short,
// non-secret tail for display, so a card whose camera could not be named shows
// something compact instead of the whole `stream_1789961119825723855`.
//
// The tail is returned, not the head: a stream id's distinguishing part is its
// nanosecond timestamp, and a Tuya profile token's is its device id tail.
func ShortStreamID(id string) string {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return ""
	}
	const keep = 8
	runes := []rune(trimmed)
	if len(runes) <= keep {
		return trimmed
	}
	return "…" + string(runes[len(runes)-keep:])
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
