package tuyaengine

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ProfileTokenPrefix namespaces Tuya streams so they can never collide with an
// ONVIF profile token inside the shared stream manager.
const ProfileTokenPrefix = "tuya:"

// StreamNamePrefix namespaces the stream names used by the engine itself.
const StreamNamePrefix = "tuya_"

// ResolutionSD / ResolutionHD are the accepted engine stream resolutions.
const (
	ResolutionSD = "sd"
	ResolutionHD = "hd"
)

var (
	deviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	hostPattern     = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
)

// DeviceSpec identifies one Tuya camera stream for the engine.
type DeviceSpec struct {
	// DeviceID is the Tuya device id (alphanumeric, e.g. eb9f1d6e677b1b39f222ag).
	DeviceID string
	// SessionFile is the read-only saved Tuya session (QR login) file.
	SessionFile string
	// Resolution is "sd" (proven) or "hd" (unproven on this camera).
	Resolution string
	// Host is the Tuya region host, e.g. protect-us.ismartlife.me.
	Host string
}

// Normalize applies defaults and validates the spec.
func (s DeviceSpec) Normalize(def DeviceSpec) (DeviceSpec, error) {
	out := s
	if out.SessionFile == "" {
		out.SessionFile = def.SessionFile
	}
	if out.Host == "" {
		out.Host = def.Host
	}
	if out.Host == "" {
		out.Host = DefaultTuyaHost
	}
	if out.Resolution == "" {
		out.Resolution = def.Resolution
	}
	if out.Resolution == "" {
		out.Resolution = DefaultResolution
	}
	out.SessionFile = strings.TrimSpace(out.SessionFile)
	out.DeviceID = strings.TrimSpace(out.DeviceID)
	out.Host = strings.TrimSpace(out.Host)
	out.Resolution = strings.ToLower(strings.TrimSpace(out.Resolution))
	if err := out.Validate(); err != nil {
		return DeviceSpec{}, err
	}
	return out, nil
}

// Validate reports every way a spec can be unsafe or unusable.
func (s DeviceSpec) Validate() error {
	if !deviceIDPattern.MatchString(s.DeviceID) {
		return fmt.Errorf("tuyaengine: invalid device id %q (expected 1-64 chars of [A-Za-z0-9_-])", s.DeviceID)
	}
	if s.SessionFile == "" {
		return fmt.Errorf("tuyaengine: session file is required (set %s)", EnvSessionFile)
	}
	if strings.ContainsAny(s.SessionFile, "\r\n\x00") {
		return fmt.Errorf("tuyaengine: session file path contains control characters")
	}
	if !filepath.IsAbs(s.SessionFile) {
		return fmt.Errorf("tuyaengine: session file path must be absolute")
	}
	info, err := os.Stat(s.SessionFile)
	if err != nil {
		return fmt.Errorf("tuyaengine: session file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("tuyaengine: session file %s is a directory", s.SessionFile)
	}
	// The session file is a read-only credential store. Refuse to build a bridge
	// on top of one others can read.
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("tuyaengine: session file %s is group/world accessible (%04o); expected 0600", s.SessionFile, perm)
	}
	if !hostPattern.MatchString(s.Host) {
		return fmt.Errorf("tuyaengine: invalid tuya host %q", s.Host)
	}
	switch s.Resolution {
	case ResolutionSD, ResolutionHD:
	default:
		return fmt.Errorf("tuyaengine: invalid resolution %q (want %s or %s)", s.Resolution, ResolutionSD, ResolutionHD)
	}
	return nil
}

// StreamName returns the engine-side stream name for this device.
func (s DeviceSpec) StreamName() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	return StreamNamePrefix + s.DeviceID, nil
}

// ProfileToken returns the namespaced token used with the stream manager.
func (s DeviceSpec) ProfileToken() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	return ProfileTokenFor(s.DeviceID)
}

// EngineURL returns the tuya:// source URL the engine consumes.
func (s DeviceSpec) EngineURL() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	query := url.Values{}
	query.Set("device_id", s.DeviceID)
	query.Set("session_file", s.SessionFile)
	query.Set("resolution", s.Resolution)
	return "tuya://" + s.Host + "?" + query.Encode(), nil
}

// ProfileTokenFor builds the namespaced profile token for a device id.
func ProfileTokenFor(deviceID string) (string, error) {
	if !deviceIDPattern.MatchString(deviceID) {
		return "", fmt.Errorf("tuyaengine: invalid device id %q", deviceID)
	}
	return ProfileTokenPrefix + deviceID, nil
}

// IsTuyaProfileToken reports whether a profile token belongs to a Tuya stream.
func IsTuyaProfileToken(token string) bool {
	return strings.HasPrefix(token, ProfileTokenPrefix)
}

// RTSPURL builds the RTSP URL the viewer's ffmpeg should consume.
func RTSPURL(host string, port int, streamName string) string {
	if host == "" {
		host = DefaultRTSPHost
	}
	return fmt.Sprintf("rtsp://%s:%d/%s", host, port, url.PathEscape(streamName))
}
