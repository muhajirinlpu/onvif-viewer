package provider

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"dengan.dev/camera-streamer/internal/tuyaengine"
	"dengan.dev/camera-streamer/internal/tuyaqr"
)

// --- M9: re-registering a PERSISTED Tuya camera with the engine ---------------
//
// The lifecycle defect this file guards: a Tuya stream's RTSP URL is a loopback
// address on our OWN in-process engine, on a port allocated fresh every start, so
// the stored row carries an EMPTY url and stream.Manager.RestoreStreams asks the
// engine for the live one. Nothing used to put the device back INTO the engine at
// boot, so restore asked about a device the engine had never heard of and
// correctly skipped it -- MEASURED live: 1 stream before a restart, 0 after.
//
// These tests pin the missing step, and in particular its two safety properties:
// it must not start a stream (that would be a SECOND ffmpeg) and it must not
// write a config row (the row already exists).

// fakeRegistrar is the engine-registration double. It records every spec it was
// given, so a test can prove the device id, session path and resolution reached
// the engine, and it can be made to fail like an offline camera or a dead engine.
type fakeRegistrar struct {
	specs []tuyaengine.DeviceSpec
	url   string
	err   error
	// failFor, when non-empty, makes RegisterStream fail only for that device.
	failFor string
}

func (f *fakeRegistrar) RegisterStream(spec tuyaengine.DeviceSpec) (string, string, error) {
	f.specs = append(f.specs, spec)
	if f.err != nil {
		return "", "", f.err
	}
	if f.failFor != "" && f.failFor == spec.DeviceID {
		return "", "", errors.New("tuyaengine: engine is not reachable for this camera")
	}
	url := f.url
	if url == "" {
		url = "rtsp://127.0.0.1:45011/tuya_" + spec.DeviceID
	}
	token, err := tuyaengine.ProfileTokenFor(spec.DeviceID)
	if err != nil {
		return "", "", err
	}
	return url, token, nil
}

// registrarProvider builds a provider with a real session store, a live session,
// a resolution store, and the supplied registrar.
func registrarProvider(t *testing.T, r TuyaStreamRegistrar, opts ...TuyaOption) (*Tuya, *tuyaqr.MemorySessionStore, *loggerResolutionStore) {
	t.Helper()
	store := tuyaqr.NewMemorySessionStore()
	if err := store.Save(testSessionForStore("m9@example.test")); err != nil {
		t.Fatalf("save session: %v", err)
	}
	res := newLoggerResolutionStore()
	base := []TuyaOption{
		WithTuyaStore(store),
		WithTuyaStreamRegistrar(r),
		WithTuyaResolutionStore(res),
		// A live cloud verdict, so the session gate is not what is under test.
		withTuyaLister(&fakeLister{}, nil),
	}
	return NewTuya("", append(base, opts...)...), store, res
}

// loggerResolutionStore is the minimal TuyaResolutionStore double: it keeps the
// per-camera choice in a map and records every WRITE, which is how the
// "registration must not persist" property is proven.
type loggerResolutionStore struct {
	values map[string]string
	writes []string
}

func newLoggerResolutionStore() *loggerResolutionStore {
	return &loggerResolutionStore{values: map[string]string{}}
}

func (s *loggerResolutionStore) StreamResolution(profileToken string) (string, error) {
	if v, ok := s.values[profileToken]; ok {
		return v, nil
	}
	return "sd", nil
}

func (s *loggerResolutionStore) SetStreamResolution(profileToken, resolution string) error {
	s.values[profileToken] = resolution
	s.writes = append(s.writes, profileToken+"="+resolution)
	return nil
}

// TestRegisterStoredDeviceRegistersWithoutStartingAStream is the core M9
// assertion, and it pins BOTH safety properties at once:
//
//   - the device DID reach the engine, with the session path and the stored
//     resolution, so a restore that follows can resolve a live URL;
//   - the stream was NOT started (the bridge's StartStream is a different call
//     and is not wired here at all -- a nil bridge proves nothing tried) and
//     nothing was persisted (zero resolution writes).
func TestRegisterStoredDeviceRegistersWithoutStartingAStream(t *testing.T) {
	reg := &fakeRegistrar{}
	// Deliberately NO WithTuyaBridge: if the registration path called
	// StartStream it would fail with "tuya streaming is not configured", which
	// is exactly the assertion.
	p, _, resolutions := registrarProvider(t, reg)

	const deviceID = "eb9f1d6e677b1b39f222ag"
	if _, err := p.SetResolution(deviceID, "hd"); err != nil {
		t.Fatalf("seed resolution: %v", err)
	}
	writesBefore := len(resolutions.writes)

	outcome := p.RegisterStoredDeviceForProfile(tuyaengine.ProfileTokenPrefix + deviceID)

	if !outcome.Registered {
		t.Fatalf("outcome = %+v, want Registered (reason: %s)", outcome, outcome.SkippedReason)
	}
	if outcome.DeviceID != deviceID {
		t.Errorf("device id = %q, want %q (it must be recovered from the profile token alone)", outcome.DeviceID, deviceID)
	}
	if outcome.ProfileToken != tuyaengine.ProfileTokenPrefix+deviceID {
		t.Errorf("profile token = %q, want the stored token back", outcome.ProfileToken)
	}
	if !strings.HasPrefix(outcome.RTSPURL, "rtsp://127.0.0.1:") {
		t.Errorf("rtsp url = %q, want the engine's loopback URL", outcome.RTSPURL)
	}
	if len(reg.specs) != 1 {
		t.Fatalf("registrar was called %d time(s), want exactly 1", len(reg.specs))
	}
	spec := reg.specs[0]
	if spec.DeviceID != deviceID {
		t.Errorf("spec device id = %q, want %q", spec.DeviceID, deviceID)
	}
	if !filepath.IsAbs(spec.SessionFile) {
		t.Errorf("spec session file = %q, want an absolute path (the engine validates this)", spec.SessionFile)
	}
	// The resolution already stored for the camera must be what the engine is
	// asked for, so a restore replays the user's own choice.
	if outcome.Resolution != "hd" || spec.Resolution != "hd" {
		t.Errorf("resolution = %q / spec %q, want the stored hd", outcome.Resolution, spec.Resolution)
	}
	// Reading the stored resolution must not have written anything new.
	if len(resolutions.writes) != writesBefore {
		t.Errorf("registration persisted a resolution (%v); it must only read, or a restart would re-write rows restore owns", resolutions.writes[writesBefore:])
	}
}

// TestRegisterStoredDeviceSkipsOnAnOfflineCamera proves an offline camera cannot
// take the viewer down: the failure is reported, never returned as an error, and
// nothing panics.
func TestRegisterStoredDeviceSkipsOnAnOfflineCamera(t *testing.T) {
	reg := &fakeRegistrar{err: errors.New("tuyaengine: camera is offline")}
	p, _, _ := registrarProvider(t, reg)

	outcome := p.RegisterStoredDeviceForProfile("tuya:eb9f1d6e677b1b39f222ag")
	if outcome.Registered {
		t.Fatalf("outcome = %+v, want not registered", outcome)
	}
	if strings.TrimSpace(outcome.SkippedReason) == "" {
		t.Fatal("an unregistered camera must carry a non-empty reason, or the operator has no way to tell why it is not coming back")
	}
	if !strings.Contains(outcome.SkippedReason, "offline") {
		t.Errorf("reason = %q, want it to carry the engine's own words", outcome.SkippedReason)
	}
}

// TestRegisterStoredDeviceSkipsWhenNoSessionIsStored is the "no QR scan yet"
// case: it must skip CLEANLY (a reason, not an error) and must not touch the
// engine at all.
func TestRegisterStoredDeviceSkipsWhenNoSessionIsStored(t *testing.T) {
	reg := &fakeRegistrar{}
	empty := tuyaqr.NewMemorySessionStore()
	p := NewTuya("", WithTuyaStore(empty), WithTuyaStreamRegistrar(reg), WithTuyaResolutionStore(newLoggerResolutionStore()))

	outcome := p.RegisterStoredDeviceForProfile("tuya:eb9f1d6e677b1b39f222ag")
	if outcome.Registered {
		t.Fatalf("outcome = %+v, want a skip when no session is stored", outcome)
	}
	if !strings.Contains(outcome.SkippedReason, "session") {
		t.Errorf("reason = %q, want it to name the missing session", outcome.SkippedReason)
	}
	if len(reg.specs) != 0 {
		t.Errorf("the engine was asked to register %d camera(s) with no session; it must not be touched at all", len(reg.specs))
	}
}

// TestRegisterStoredDeviceReportsADisabledRegistrar covers the honest-nil case:
// Tuya streaming is off in this process, so the reason must SAY that rather than
// leaving the camera silently unrestored.
func TestRegisterStoredDeviceReportsADisabledRegistrar(t *testing.T) {
	p, _, _ := registrarProvider(t, nil)

	outcome := p.RegisterStoredDeviceForProfile("tuya:eb9f1d6e677b1b39f222ag")
	if outcome.Registered {
		t.Fatalf("outcome = %+v, want a skip", outcome)
	}
	if !strings.Contains(outcome.SkippedReason, "not configured in this process") {
		t.Errorf("reason = %q, want the disabled-bridge explanation", outcome.SkippedReason)
	}
}

// TestRegisterStoredDeviceIgnoresONVIFTokens keeps the sweep safe: the start-up
// loop is profile-token driven and will hand it ONVIF tokens too.
func TestRegisterStoredDeviceIgnoresONVIFTokens(t *testing.T) {
	reg := &fakeRegistrar{}
	p, _, _ := registrarProvider(t, reg)

	for _, token := range []string{"defaultToken", "onvif-194", "", "tuya:"} {
		outcome := p.RegisterStoredDeviceForProfile(token)
		if outcome.Registered {
			t.Fatalf("token %q was registered with the Tuya engine: %+v", token, outcome)
		}
		if strings.TrimSpace(outcome.SkippedReason) == "" {
			t.Errorf("token %q produced an empty reason", token)
		}
	}
	if len(reg.specs) != 0 {
		t.Errorf("the engine was asked about %d non-Tuya token(s)", len(reg.specs))
	}
}
