package main

import (
	"strings"
	"testing"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/provider"
	"dengan.dev/camera-streamer/internal/tuyaengine"
	"dengan.dev/camera-streamer/internal/tuyaqr"
)

// --- M9: the start-up ORDER, and the boot report ----------------------------
//
// These two are the parts of the lifecycle fix that live in main.go, and both
// are here for the same reason: the defect they guard shipped while the suite was
// green, because nothing asserted the ORDER of start-up or the fact that a
// disabled Tuya said so out loud.

// sequenceRecorder records the order in which the start-up steps ran, so
// "registration happens before restore" is an assertion rather than a comment.
type sequenceRecorder struct {
	steps []string
}

func (s *sequenceRecorder) record(step string) { s.steps = append(s.steps, step) }

// fakeRestorer is the streamRestorer double: it records that restore was asked
// for, at the point it was asked for.
type fakeRestorer struct{ log *sequenceRecorder }

func (f fakeRestorer) RestoreStreams() { f.log.record("restore") }

// fakeBootRegistrar records a registration and hands back a registered outcome.
type fakeBootRegistrar struct {
	log    *sequenceRecorder
	tokens []string
	// skipWhen makes the registrar report a skip for a given token, standing in
	// for an offline camera.
	skipWhen string
}

func (f *fakeBootRegistrar) RegisterStoredDeviceForProfile(profileToken string) provider.TuyaRegistrationOutcome {
	f.log.record("register:" + profileToken)
	f.tokens = append(f.tokens, profileToken)
	if profileToken == f.skipWhen {
		return provider.TuyaRegistrationOutcome{
			ProfileToken:  profileToken,
			SkippedReason: "the Tuya engine would not accept this camera: camera is offline",
		}
	}
	return provider.TuyaRegistrationOutcome{
		ProfileToken: profileToken,
		DeviceID:     strings.TrimPrefix(profileToken, tuyaengine.ProfileTokenPrefix),
		RTSPURL:      "rtsp://127.0.0.1:45011/tuya_" + strings.TrimPrefix(profileToken, tuyaengine.ProfileTokenPrefix),
		Resolution:   logger.DefaultResolution,
		Registered:   true,
	}
}

// TestStartupRegistersTuyaCamerasBeforeRestore is the ordering assertion. It is
// the whole fix in one test: if restore is asked before the engine knows the
// device, restore correctly skips the camera and the stream is silently lost
// after a restart.
func TestStartupRegistersTuyaCamerasBeforeRestore(t *testing.T) {
	seq := &sequenceRecorder{}
	registrar := &fakeBootRegistrar{log: seq}
	configs := []logger.StreamConfig{
		// Sorted, as the store returns them, so the ONVIF row comes first and
		// the sweep has to skip past it.
		{ProfileToken: "defaultToken", RTSPURL: "rtsp://10.2.56.194:5543/x/live/channel0", Provider: string(provider.KindONVIF)},
		{ProfileToken: "tuya:eb9f1d6e677b1b39f222ag", Provider: string(provider.KindTuya)},
	}

	registered, skipped := restoreStoredStreamsAtStartup(fakeRestorer{log: seq}, configs, registrar, func(provider.TuyaRegistrationOutcome) {})

	if registered != 1 {
		t.Errorf("registered = %d, want 1", registered)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}
	want := []string{"register:tuya:eb9f1d6e677b1b39f222ag", "restore"}
	if len(seq.steps) != len(want) {
		t.Fatalf("start-up steps = %v, want %v", seq.steps, want)
	}
	for i := range want {
		if seq.steps[i] != want[i] {
			t.Fatalf("start-up steps = %v, want %v (registration MUST run before restore)", seq.steps, want)
		}
	}
	// The ONVIF row must not be handed to the Tuya engine.
	for _, token := range registrar.tokens {
		if !strings.HasPrefix(token, tuyaengine.ProfileTokenPrefix) {
			t.Errorf("the Tuya sweep asked about the non-Tuya token %q", token)
		}
	}
}

// TestStartupSkipsAnOfflineCameraAndStillRestores is the "must not break
// start-up" half: a camera the engine refuses (offline) is logged and skipped,
// the remaining cameras are still registered, and restore still runs.
func TestStartupSkipsAnOfflineCameraAndStillRestores(t *testing.T) {
	seq := &sequenceRecorder{}
	registrar := &fakeBootRegistrar{log: seq, skipWhen: "tuya:offline-camera"}
	configs := []logger.StreamConfig{
		{ProfileToken: "tuya:offline-camera", Provider: string(provider.KindTuya)},
		{ProfileToken: "tuya:online-camera", Provider: string(provider.KindTuya)},
	}

	var reported []provider.TuyaRegistrationOutcome
	registered, skipped := restoreStoredStreamsAtStartup(fakeRestorer{log: seq}, configs, registrar,
		func(o provider.TuyaRegistrationOutcome) { reported = append(reported, o) })

	if registered != 1 || skipped != 1 {
		t.Fatalf("registered/skipped = %d/%d, want 1/1", registered, skipped)
	}
	if len(reported) != 2 {
		t.Fatalf("reported %d outcome(s), want 2 (every camera must be reported, skipped or not)", len(reported))
	}
	if len(seq.steps) == 0 || seq.steps[len(seq.steps)-1] != "restore" {
		t.Fatalf("start-up steps = %v, want restore to run last even after a skip", seq.steps)
	}
	var skipReason string
	for _, o := range reported {
		if o.ProfileToken == "tuya:offline-camera" {
			skipReason = o.SkippedReason
		}
	}
	if !strings.Contains(skipReason, "offline") {
		t.Errorf("skip reason = %q, want the refusal recorded", skipReason)
	}
}

// TestStartupSweepSurvivesANilProviderToken drives the degenerate row that made
// the sweep worth guarding: a row with no provider at all is ONVIF by definition
// and must not be handed to the Tuya engine.
func TestStartupSweepSurvivesANilProviderToken(t *testing.T) {
	seq := &sequenceRecorder{}
	registrar := &fakeBootRegistrar{log: seq}
	configs := []logger.StreamConfig{
		{ProfileToken: "legacy-onvif", RTSPURL: "rtsp://10.0.0.9:554/live"},
		{ProfileToken: "", Provider: string(provider.KindTuya)},
	}
	registered, skipped := restoreStoredStreamsAtStartup(fakeRestorer{log: seq}, configs, registrar, func(provider.TuyaRegistrationOutcome) {})
	if registered != 0 {
		t.Errorf("registered = %d, want 0", registered)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 (the empty Tuya row is still reported)", skipped)
	}
	if len(registrar.tokens) != 1 || registrar.tokens[0] != "" {
		t.Fatalf("registrar tokens = %v, want just the empty Tuya token", registrar.tokens)
	}
}

// stubSessionStore is a SessionStore whose Accounts() can be made to fail or to
// hold accounts, so the boot message can be exercised for every case without a
// database.
type stubSessionStore struct {
	kind     string
	location string
	accounts []tuyaqr.StoredSession
	err      error
}

func (s stubSessionStore) Load(tuyaqr.Account) (*tuyaqr.Session, error) { return nil, tuyaqr.ErrNoSession }
func (s stubSessionStore) Save(*tuyaqr.Session) error                   { return nil }
func (s stubSessionStore) Delete(tuyaqr.Account) error                  { return nil }
func (s stubSessionStore) Accounts() ([]tuyaqr.StoredSession, error) {
	return s.accounts, s.err
}
func (s stubSessionStore) Kind() string     { return s.kind }
func (s stubSessionStore) Location() string { return s.location }
func (s stubSessionStore) Materialize(*tuyaqr.Session) (string, error) {
	return "", tuyaqr.ErrNoSession
}

// TestBootSaysLoudlyWhenNoTuyaSessionIsStored is the Bug 3a guard. The state
// that used to be reported by SILENCE (a nil bridge for the process's lifetime,
// and an opaque error only when a stream was started) must now be stated at boot,
// naming what is missing and what to do about it.
//
// It also pins the claim that must NOT be made: this build makes the bridge
// available when a session later appears, so the message must not tell the
// operator that a restart is needed.
func TestBootSaysLoudlyWhenNoTuyaSessionIsStored(t *testing.T) {
	store := stubSessionStore{kind: tuyaqr.StoreKindSQLite, location: "onvif_logs.db"}

	available, message := tuyaBootSessionMessage(store, "")

	if available {
		t.Error("available = true with no stored account and no legacy file")
	}
	if !strings.HasPrefix(message, "WARNING: NO Tuya session is stored at start-up") {
		t.Errorf("message does not open with a loud warning: %q", message)
	}
	for _, want := range []string{
		tuyaqr.StoreKindSQLite, // where it looked
		"onvif_logs.db",        // the exact location
		"fast-sid/s-sid",       // what is actually missing
		"QR scan",              // how it gets fixed
		"NOT disabled",         // the bridge is up regardless
	} {
		if !strings.Contains(message, want) {
			t.Errorf("message %q does not mention %q", message, want)
		}
	}
	if strings.Contains(strings.ToLower(message), "restart the") {
		t.Errorf("message tells the operator a restart is needed, which is no longer true: %q", message)
	}
}

// TestBootReportsASessionThatIsActuallyStored is the control: the normal state
// must be reported as available, not as a warning, or the loud case becomes
// noise nobody reads.
func TestBootReportsASessionThatIsActuallyStored(t *testing.T) {
	store := stubSessionStore{
		kind:     tuyaqr.StoreKindSQLite,
		location: "onvif_logs.db",
		accounts: []tuyaqr.StoredSession{{Account: tuyaqr.Account{Region: "us-west", Email: "user@example.test"}}},
	}
	available, message := tuyaBootSessionMessage(store, "")
	if !available {
		t.Errorf("available = false although an account is stored: %q", message)
	}
	if strings.Contains(message, "WARNING") {
		t.Errorf("message warns although a session is stored: %q", message)
	}
	// The account label is not a secret, but a credential must never be there.
	if strings.Contains(message, "fast-sid=") || strings.Contains(strings.ToLower(message), "cookie=") {
		t.Errorf("message leaks credential material: %q", message)
	}
}

// TestBootWarnsWhenTheStoreCannotBeListed covers the failing-store case: it must
// still say Tuya is not disabled, because the caller's registration path will
// skip and the operator needs to know which of the two situations they are in.
func TestBootWarnsWhenTheStoreCannotBeListed(t *testing.T) {
	store := stubSessionStore{kind: tuyaqr.StoreKindSQLite, location: "onvif_logs.db", err: errStubList}
	available, message := tuyaBootSessionMessage(store, "")
	if available {
		t.Error("available = true although Accounts() failed")
	}
	if !strings.Contains(message, "could not be listed") || !strings.Contains(message, "NOT disabled") {
		t.Errorf("message = %q, want the listing failure and the not-disabled clarification", message)
	}
}

// TestBootNamesTheLegacyFileWhenItIsTheSource keeps the import-source case
// distinct: a configured legacy file IS a session, even before the import runs.
func TestBootNamesTheLegacyFileWhenItIsTheSource(t *testing.T) {
	store := stubSessionStore{kind: tuyaqr.StoreKindSQLite, location: "onvif_logs.db"}
	available, message := tuyaBootSessionMessage(store, "/home/user/user_us-west_x.json")
	if !available {
		t.Errorf("available = false although a legacy session file is configured: %q", message)
	}
	if !strings.Contains(message, "/home/user/user_us-west_x.json") {
		t.Errorf("message = %q, want the legacy path named", message)
	}
}

type stubListError string

func (e stubListError) Error() string { return string(e) }

var errStubList = stubListError("database is locked")
