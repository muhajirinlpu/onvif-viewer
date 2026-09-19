package tuyaengine

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// normalizedSpec is the supported way to build a usable spec: raw fields go
// through Normalize, which applies the host/resolution defaults and validates.
func normalizedSpec(t *testing.T, deviceID string) DeviceSpec {
	t.Helper()
	spec, err := DeviceSpec{DeviceID: deviceID, SessionFile: sessionFile(t)}.Normalize(DeviceSpec{})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	return spec
}

func TestEngineURLIsConstructedFromSpec(t *testing.T) {
	path := sessionFile(t)
	spec := DeviceSpec{DeviceID: "eb9f1d6e677b1b39f222ag", SessionFile: path, Resolution: ResolutionSD, Host: "protect-us.ismartlife.me"}
	got, err := spec.EngineURL()
	if err != nil {
		t.Fatalf("EngineURL: %v", err)
	}
	want := "tuya://protect-us.ismartlife.me?device_id=eb9f1d6e677b1b39f222ag&resolution=sd&session_file=" +
		url.QueryEscape(path)
	if got != want {
		t.Fatalf("EngineURL mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestEngineURLDefaultsHostAndResolution(t *testing.T) {
	path := sessionFile(t)
	normalized, err := DeviceSpec{DeviceID: "abc123", SessionFile: path}.Normalize(DeviceSpec{})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if normalized.Host != DefaultTuyaHost {
		t.Fatalf("host = %q, want %q", normalized.Host, DefaultTuyaHost)
	}
	if normalized.Resolution != ResolutionSD {
		t.Fatalf("resolution = %q, want %q", normalized.Resolution, ResolutionSD)
	}
}

func TestProfileTokenIsNamespaced(t *testing.T) {
	spec := normalizedSpec(t, "cam1")
	token, err := spec.ProfileToken()
	if err != nil {
		t.Fatalf("ProfileToken: %v", err)
	}
	if token != "tuya:cam1" {
		t.Fatalf("token = %q, want tuya:cam1", token)
	}
	if !IsTuyaProfileToken(token) {
		t.Fatal("IsTuyaProfileToken(token) = false")
	}
	// An ONVIF profile token must never be mistaken for a Tuya one.
	if IsTuyaProfileToken("Profile_1") || IsTuyaProfileToken("") {
		t.Fatal("ONVIF profile token classified as Tuya")
	}
}

func TestStreamNameIsNamespaced(t *testing.T) {
	spec := normalizedSpec(t, "cam1")
	name, err := spec.StreamName()
	if err != nil {
		t.Fatalf("StreamName: %v", err)
	}
	if name != "tuya_cam1" {
		t.Fatalf("stream name = %q, want tuya_cam1", name)
	}
}

func TestRTSPURL(t *testing.T) {
	if got := RTSPURL("127.0.0.1", 34567, "tuya_cam1"); got != "rtsp://127.0.0.1:34567/tuya_cam1" {
		t.Fatalf("RTSPURL = %q", got)
	}
	// An empty host falls back to loopback rather than producing a malformed URL.
	if got := RTSPURL("", 1, "s"); got != "rtsp://127.0.0.1:1/s" {
		t.Fatalf("RTSPURL default host = %q", got)
	}
}

func TestSpecValidationRejectsUnsafeInput(t *testing.T) {
	good := sessionFile(t)

	cases := []struct {
		name    string
		spec    DeviceSpec
		wantSub string
	}{
		{"empty device id", DeviceSpec{SessionFile: good, Resolution: ResolutionSD, Host: DefaultTuyaHost}, "invalid device id"},
		{"device id with yaml injection", DeviceSpec{DeviceID: "a\"\n  evil: 1", SessionFile: good, Resolution: ResolutionSD, Host: DefaultTuyaHost}, "invalid device id"},
		{"device id with slash", DeviceSpec{DeviceID: "a/b", SessionFile: good, Resolution: ResolutionSD, Host: DefaultTuyaHost}, "invalid device id"},
		{"missing session file", DeviceSpec{DeviceID: "cam1", SessionFile: filepath.Join(t.TempDir(), "absent.json"), Resolution: ResolutionSD, Host: DefaultTuyaHost}, "session file"},
		{"relative session file", DeviceSpec{DeviceID: "cam1", SessionFile: "relative.json", Resolution: ResolutionSD, Host: DefaultTuyaHost}, "absolute"},
		{"session file with newline", DeviceSpec{DeviceID: "cam1", SessionFile: "/tmp/a\nb", Resolution: ResolutionSD, Host: DefaultTuyaHost}, "control characters"},
		{"bad resolution", DeviceSpec{DeviceID: "cam1", SessionFile: good, Resolution: "4k", Host: DefaultTuyaHost}, "invalid resolution"},
		{"bad host", DeviceSpec{DeviceID: "cam1", SessionFile: good, Resolution: ResolutionSD, Host: "evil host/x"}, "invalid tuya host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.spec.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("Validate() = %v, want substring %q", err, tc.wantSub)
			}
		})
	}
}

func TestSpecRejectsGroupReadableSessionFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := DeviceSpec{DeviceID: "cam1", SessionFile: path, Resolution: ResolutionSD, Host: DefaultTuyaHost}.Validate()
	if err == nil || !strings.Contains(err.Error(), "group/world accessible") {
		t.Fatalf("Validate() = %v, want a permission refusal", err)
	}
}

func TestSpecAcceptsProvenConfiguration(t *testing.T) {
	path := sessionFile(t)
	spec := DeviceSpec{DeviceID: "eb9f1d6e677b1b39f222ag", SessionFile: path, Resolution: ResolutionSD, Host: "protect-us.ismartlife.me"}
	if err := spec.Validate(); err != nil {
		t.Fatalf("Validate() of the proven configuration = %v", err)
	}
}
