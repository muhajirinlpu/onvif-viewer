package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/models"
	"dengan.dev/camera-streamer/internal/tuyaengine"
	"dengan.dev/camera-streamer/internal/tuyaqr"
)

// --- fakes ------------------------------------------------------------------

type fakeProvider struct {
	kind Kind
	cams []Camera
	err  error
}

func (f *fakeProvider) Kind() Kind { return f.kind }
func (f *fakeProvider) Cameras(context.Context) ([]Camera, error) {
	return f.cams, f.err
}

// fakeLister is a discovery double: it returns a fixed device list, including
// non-camera devices, and can be made to fail like an expired session.
type fakeLister struct {
	devices []tuyaqr.Device
	err     error
	calls   int
	// probeErr is the verdict RefreshExpiry reports; it defaults to err so a
	// test can make discovery fail while the liveness probe still succeeds
	// (and vice versa).
	probeErr    error
	probeErrSet bool
	// reportedExpiry, when non-zero, is folded into the session by
	// RefreshExpiry — standing in for the cloud's Set-Cookie expiry.
	reportedExpiry time.Time
	expiryOnCookie string
	refreshCalls   int
	validateCalls  int
}

func (f *fakeLister) Cameras(context.Context) ([]tuyaqr.Device, error) {
	f.calls++
	return f.devices, f.err
}

func (f *fakeLister) Validate(context.Context) error {
	f.validateCalls++
	return f.err
}

// probeCalls reports how many times the pre-start liveness gate asked.
func (f *fakeLister) probeCalls() int { return f.validateCalls }

// RefreshExpiry mirrors *tuyaqr.Client.RefreshExpiry for tests: it reports the
// configured liveness verdict without a network round trip, and applies any
// expiry the fake "cloud" reported, exactly as the real one does.
func (f *fakeLister) RefreshExpiry(_ context.Context, s *tuyaqr.Session) (err error) {
	f.refreshCalls++
	if f.probeErrSet {
		err = f.probeErr
	} else {
		err = f.err
	}
	if err == nil && s != nil && !f.reportedExpiry.IsZero() {
		name := f.expiryOnCookie
		if name == "" {
			name = "fast-sid"
		}
		for _, c := range s.SessionData.Cookies {
			if c != nil && c.Name == name {
				c.Expires = f.reportedExpiry
			}
		}
	}
	return err
}

// fakeStopper records the suspend/resume lifecycle without a stream manager.
type fakeStopper struct {
	suspended   []models.StreamInfo
	suspendCall int
	resumeCalls int
	suspendErr  error
	resumedIDs  []string
}

func (f *fakeStopper) SuspendStreamsForProvider(_ models.ProviderKind, _ string) (int, error) {
	f.suspendCall++
	if f.suspendErr != nil {
		return 0, f.suspendErr
	}
	return len(f.suspended), nil
}

func (f *fakeStopper) SuspendedStreams(models.ProviderKind) []models.StreamInfo {
	return f.suspended
}

func (f *fakeStopper) ResumeSuspended(streamID, _ string, _ models.ProviderKind) (*models.StreamInfo, error) {
	f.resumeCalls++
	f.resumedIDs = append(f.resumedIDs, streamID)
	return &models.StreamInfo{ID: streamID, Provider: KindTuya}, nil
}

type fakeBridge struct {
	lastSpec tuyaengine.DeviceSpec
	info     *models.StreamInfo
	err      error
	// resolved records the device ids Resolve was asked for, so a resume can be
	// proven to target the SAME cameras without re-selection.
	resolved []string
}

func (f *fakeBridge) StartStream(spec tuyaengine.DeviceSpec) (*models.StreamInfo, error) {
	f.lastSpec = spec
	if f.err != nil {
		return nil, f.err
	}
	if f.info == nil {
		f.info = &models.StreamInfo{}
	}
	return f.info, nil
}

func (f *fakeBridge) Resolve(deviceID string) (string, error) {
	f.resolved = append(f.resolved, deviceID)
	if f.err != nil {
		return "", f.err
	}
	return "rtsp://127.0.0.1:8554/tuya_" + deviceID, nil
}

// fakeLoginClient drives the QR state machine with no network.
type fakeLoginClient struct {
	beginErr error
	pollSeq  []pollStep
	polls    int
	session  *tuyaqr.Session
}

type pollStep struct {
	done bool
	err  error
}

func (f *fakeLoginClient) BeginLoginSession(context.Context) (*tuyaqr.Login, error) {
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	now := time.Now()
	return &tuyaqr.Login{
		Token:     "TESTTOKEN-0001",
		Payload:   tuyaqr.QRBindingPrefix + "TESTTOKEN-0001",
		Host:      tuyaqr.DefaultHost,
		IssuedAt:  now,
		ExpiresAt: now.Add(tuyaqr.TokenTTL - 30*time.Second),
	}, nil
}

func (f *fakeLoginClient) PollLogin(context.Context, *tuyaqr.Login) (*tuyaqr.Session, bool, error) {
	step := pollStep{}
	if f.polls < len(f.pollSeq) {
		step = f.pollSeq[f.polls]
	} else if len(f.pollSeq) > 0 {
		step = f.pollSeq[len(f.pollSeq)-1]
	}
	f.polls++
	if step.err != nil {
		return nil, false, step.err
	}
	if !step.done {
		return nil, false, nil
	}
	s := f.session
	if s == nil {
		s = testSession()
	}
	return s, true, nil
}

// testSession builds an in-memory session with the cookie pair discovery needs.
func testSession() *tuyaqr.Session {
	now := time.Now()
	return &tuyaqr.Session{
		Region:      tuyaqr.DefaultRegion,
		Email:       "user@example.test",
		UserKey:     "us-west_user_at_example_test",
		LastRefresh: now,
		SessionData: tuyaqr.UserSession{
			LoginResult:   &tuyaqr.LoginResult{UID: "az1", Email: "user@example.test"},
			LastValidated: now,
			ServerHost:    tuyaqr.DefaultHost,
			Region:        tuyaqr.DefaultRegion,
			UserEmail:     "user@example.test",
			Cookies: []*tuyaqr.Cookie{
				{Name: "gTyPlatLang", Value: "en"},
				{Name: "locale", Value: "en"},
				{Name: "fast-sid", Value: "0123456789012345678901234567890a"},
				{Name: "s-sid", Value: strings.Repeat("a", 82)},
			},
		},
	}
}

// --- Set --------------------------------------------------------------------

func TestSetDefaultsToONVIFWhenKindIsEmpty(t *testing.T) {
	onvif := &fakeProvider{kind: KindONVIF, cams: []Camera{{ID: "onvif-1"}}}
	tuya := &fakeProvider{kind: KindTuya, cams: []Camera{{ID: "tuya-1"}}}
	set := NewSet(onvif, tuya)

	got, err := set.Get("")
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind() != KindONVIF {
		t.Fatalf("empty kind resolved to %q, want onvif", got.Kind())
	}
}

func TestSetRejectsUnknownProvider(t *testing.T) {
	set := NewSet(&fakeProvider{kind: KindONVIF})
	if _, err := set.Get(Kind("rtsp-unicorn")); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("err = %v, want ErrUnknownProvider", err)
	}
}

func TestSetListsKindsInRegistrationOrder(t *testing.T) {
	set := NewSet(&fakeProvider{kind: KindONVIF}, &fakeProvider{kind: KindTuya})
	kinds := set.Kinds()
	if len(kinds) != 2 || kinds[0] != KindONVIF || kinds[1] != KindTuya {
		t.Fatalf("kinds = %v, want [onvif tuya]", kinds)
	}
}

func TestSetStampsProviderOnEveryCamera(t *testing.T) {
	// A provider that returns a camera with a blank provider must not be able to
	// put an unlabelled camera in front of the UI.
	set := NewSet(&fakeProvider{kind: KindTuya, cams: []Camera{{ID: "d1", Name: "Plug"}}})
	cams, err := set.Cameras(context.Background(), KindTuya)
	if err != nil {
		t.Fatal(err)
	}
	if len(cams) != 1 || cams[0].Provider != KindTuya {
		t.Fatalf("cams = %#v, want provider stamped tuya", cams)
	}
}

func TestSetCamerasFromAllSurvivesOneFailingProvider(t *testing.T) {
	ok := &fakeProvider{kind: KindONVIF, cams: []Camera{{ID: "onvif-1"}}}
	bad := &fakeProvider{kind: KindTuya, err: errors.New("cloud said no")}
	set := NewSet(ok, bad)

	cams, errs := set.CamerasFromAll(context.Background())
	if len(cams) != 1 || cams[0].ID != "onvif-1" {
		t.Fatalf("cams = %#v, want the ONVIF camera", cams)
	}
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want exactly one reported failure", errs)
	}
}

func TestSetIsEmptySafe(t *testing.T) {
	var set *Set
	if _, err := set.Get(""); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("err = %v, want ErrUnknownProvider", err)
	}
	if got := set.Kinds(); got != nil {
		t.Fatalf("Kinds() = %v, want nil", got)
	}
}

// --- Tuya discovery filtering ----------------------------------------------

// measuredAccount mirrors the real account: 5 devices, one camera (sp) and four
// cz switches/meters. The provider must serve exactly one camera.
func measuredAccount() []tuyaqr.Device {
	return []tuyaqr.Device{
		{Category: "sp", DeviceID: "eb9f1d6e677b1b39f222ag", DeviceName: "Security Camera", Online: true, ProductID: "p1"},
		{Category: "cz", DeviceID: "cz0000000000000001", DeviceName: "Switch 1", Online: true},
		{Category: "cz", DeviceID: "cz0000000000000002", DeviceName: "Meter 1", Online: false},
		{Category: "cz", DeviceID: "cz0000000000000003", DeviceName: "Switch 2", Online: true},
		{Category: "cz", DeviceID: "cz0000000000000004", DeviceName: "Switch 3", Online: true},
	}
}

func TestTuyaCamerasFiltersOutNonCameraDevices(t *testing.T) {
	lister := &fakeLister{devices: measuredAccount()}
	p := NewTuya("/dev/null/session.json", withTuyaLister(lister, testSession()))

	cams, err := p.Cameras(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cams) != 1 {
		t.Fatalf("got %d cameras, want 1 (the 4 cz devices must be filtered): %#v", len(cams), cams)
	}
	if cams[0].ID != "eb9f1d6e677b1b39f222ag" || cams[0].Name != "Security Camera" {
		t.Fatalf("unexpected camera: %#v", cams[0])
	}
	if cams[0].Provider != KindTuya {
		t.Fatalf("provider = %q, want tuya", cams[0].Provider)
	}
	for _, c := range cams {
		if strings.Contains(c.Detail, "cz") {
			t.Fatalf("non-camera device leaked into detail: %#v", c)
		}
	}
}

func TestTuyaCamerasNeverExposeSecretMaterial(t *testing.T) {
	dev := tuyaqr.Device{
		Category: "sp", DeviceID: "eb9f1d6e677b1b39f222ag", DeviceName: "Security Camera",
		Config: &tuyaqr.DeviceConfig{
			Auth:     "p2p-auth-secret",
			LocalKey: "local-key-secret",
			P2PConfig: tuyaqr.P2PConfig{
				Auth: "p2p-config-auth-secret",
				Ices: []tuyaqr.ICESrv{{URLs: "turn:x", Credential: "ice-cred-secret", Username: "ice-user"}},
			},
		},
	}
	lister := &fakeLister{devices: []tuyaqr.Device{dev}}
	p := NewTuya("/dev/null/session.json", withTuyaLister(lister, testSession()))

	cams, err := p.Cameras(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blob := ""
	for _, c := range cams {
		blob += c.ID + c.Name + c.Detail + string(c.Provider)
	}
	for _, secret := range []string{"p2p-auth-secret", "local-key-secret", "p2p-config-auth-secret", "ice-cred-secret", "ice-user"} {
		if strings.Contains(blob, secret) {
			t.Fatalf("secret %q leaked into the camera list: %s", secret, blob)
		}
	}
}

func TestTuyaStartStreamTagsProviderAndPassesDeviceID(t *testing.T) {
	bridge := &fakeBridge{}
	// A LIVE session: the pre-start liveness gate must let a healthy start
	// through to the bridge, which is what this test is about.
	lister := &fakeLister{}
	p := NewTuya("/tmp/session.json", WithTuyaBridge(bridge), withTuyaLister(lister, testSession()))

	info, err := p.StartStream("eb9f1d6e677b1b39f222ag")
	if err != nil {
		t.Fatal(err)
	}
	if bridge.lastSpec.DeviceID != "eb9f1d6e677b1b39f222ag" {
		t.Fatalf("device id passed to the bridge = %q", bridge.lastSpec.DeviceID)
	}
	if bridge.lastSpec.SessionFile != "/tmp/session.json" {
		t.Fatalf("session file passed to the bridge = %q", bridge.lastSpec.SessionFile)
	}
	if bridge.lastSpec.Resolution != "sd" {
		t.Fatalf("resolution = %q, want the proven sd default", bridge.lastSpec.Resolution)
	}
	if info == nil || info.Provider != KindTuya {
		t.Fatalf("stream info = %#v, want provider tuya", info)
	}
}

func TestTuyaStartStreamWithoutBridgeIsAClearError(t *testing.T) {
	p := NewTuya("/tmp/session.json")
	if _, err := p.StartStream("eb9f1d6e677b1b39f222ag"); err == nil {
		t.Fatal("expected an error when Tuya streaming is unconfigured")
	}
}

func TestTuyaSessionReportsCloudVerdictWithoutSecrets(t *testing.T) {
	lister := &fakeLister{}
	p := NewTuya("/tmp/session.json", withTuyaLister(lister, testSession()))

	status, err := p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.Configured || !status.Valid {
		t.Fatalf("status = %#v, want configured+valid", status)
	}
	// The stored cookies declare no expiry, so inventing one would be a lie.
	if status.ExpiresAt != nil {
		t.Fatalf("expiresAt = %v, want nil (the stored cookies carry no expiry)", status.ExpiresAt)
	}
	if status.RemainingSeconds != 0 {
		t.Fatalf("remainingSeconds = %d, want 0 with no declared expiry", status.RemainingSeconds)
	}
	if len(status.CookieNames) != 4 {
		t.Fatalf("cookieNames = %v, want 4 names", status.CookieNames)
	}
	blob := strings.Join(status.CookieNames, ",")
	if strings.Contains(blob, "AAAA") || strings.Contains(blob, "a5") {
		t.Fatalf("a cookie value leaked into cookieNames: %s", blob)
	}
}

func TestTuyaSessionRequiresANewScanWhenTheCloudRejects(t *testing.T) {
	lister := &fakeLister{err: &tuyaqr.SessionExpiredError{StatusCode: 401, ErrorCode: "USER_SESSION_LOSS"}}
	p := NewTuya("/tmp/session.json", withTuyaLister(lister, testSession()))

	status, err := p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Valid {
		t.Fatalf("status = %#v, want invalid", status)
	}
	if !strings.Contains(status.Detail, "QR") {
		t.Fatalf("detail = %q, want an instruction to scan a new QR", status.Detail)
	}
}

func TestServerSessionExpiryIsClassified(t *testing.T) {
	if !SessionExpired(&tuyaqr.SessionExpiredError{StatusCode: 401, ErrorCode: "USER_SESSION_LOSS"}) {
		t.Error("SessionExpiredError must be recognised")
	}
	if !SessionExpired(tuyaqr.ErrNoSession) {
		t.Error("ErrNoSession must be recognised")
	}
	if SessionExpired(errors.New("some other failure")) {
		t.Error("an unrelated error must not be treated as an expired session")
	}
}

// --- M6: truthful session lifecycle -----------------------------------------

// TestSessionReportsTheFourHonestAxes pins the distinction the whole milestone
// is about: "a file is present" is NOT "the cloud accepted it", and "the cloud
// accepted it" is NOT "we know when it expires".
func TestSessionReportsTheFourHonestAxes(t *testing.T) {
	lister := &fakeLister{}
	p := NewTuya("/tmp/session.json", withTuyaLister(lister, testSession()))

	status, err := p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.Configured || !status.FilePresent || !status.CloudVerified || !status.Valid {
		t.Fatalf("status = %+v, want configured+filePresent+cloudVerified+valid", status)
	}
	if status.ExpiryKnown {
		t.Error("expiryKnown must be false: the stored cookies declare no expiry")
	}
	if status.ExpiresAt != nil || status.RemainingSeconds != 0 {
		t.Errorf("expiresAt=%v remainingSeconds=%d, want null/0 — inventing a countdown is a lie", status.ExpiresAt, status.RemainingSeconds)
	}
	if status.ExpirySource != "unknown" {
		t.Errorf("expirySource = %q, want \"unknown\"", status.ExpirySource)
	}
	if status.ReloginRequired {
		t.Error("reloginRequired must be false for a live session")
	}
	if status.CacheTTLSeconds <= 0 {
		t.Errorf("cacheTtlSeconds = %d, want > 0 so a polling UI cannot hammer the cloud", status.CacheTTLSeconds)
	}
	if status.CookieCount != 4 || status.CookiesWithExpiry != 0 {
		t.Errorf("cookieCount=%d cookiesWithExpiry=%d, want 4/0", status.CookieCount, status.CookiesWithExpiry)
	}
	if !strings.Contains(status.Detail, "no countdown") {
		t.Errorf("detail = %q, want it to say no countdown can be shown", status.Detail)
	}
}

// TestSessionReportsARealExpiryWhenTheCloudStatesOne is the other half: once the
// cloud tells us, the API must report a real deadline and name its source.
func TestSessionReportsARealExpiryWhenTheCloudStatesOne(t *testing.T) {
	expiry := time.Now().Add(60 * time.Hour).UTC().Truncate(time.Second)
	lister := &fakeLister{reportedExpiry: expiry, expiryOnCookie: "fast-sid"}
	p := NewTuya("/tmp/session.json", withTuyaLister(lister, testSession()))

	status, err := p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.Valid || !status.ExpiryKnown {
		t.Fatalf("status = %+v, want valid with a known expiry", status)
	}
	if status.ExpiresAt == nil || !status.ExpiresAt.Equal(expiry) {
		t.Fatalf("expiresAt = %v, want the cloud-reported %v", status.ExpiresAt, expiry)
	}
	if status.RemainingSeconds < 59*3600 || status.RemainingSeconds > 61*3600 {
		t.Errorf("remainingSeconds = %d, want ~60h", status.RemainingSeconds)
	}
	if status.ExpirySource != "cookie:fast-sid" {
		t.Errorf("expirySource = %q, want cookie:fast-sid (attributable)", status.ExpirySource)
	}
	if status.CookiesWithExpiry != 1 || status.CookieCount != 4 {
		t.Errorf("cookiesWithExpiry = %d/%d, want 1/4", status.CookiesWithExpiry, status.CookieCount)
	}
}

// TestSessionReportsFilePresentButCloudRejected is the dishonest-looking state
// the old code could not express: the file is there, and the cloud says no.
func TestSessionReportsFilePresentButCloudRejected(t *testing.T) {
	lister := &fakeLister{err: &tuyaqr.SessionExpiredError{StatusCode: 401, ErrorCode: "USER_SESSION_LOSS"}}
	p := NewTuya("/tmp/session.json", withTuyaLister(lister, testSession()))

	status, err := p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.FilePresent {
		t.Error("filePresent must be true: the file loads fine")
	}
	if status.CloudVerified || status.Valid {
		t.Fatalf("status = %+v, want cloudVerified=false valid=false", status)
	}
	if !status.ReloginRequired {
		t.Error("reloginRequired must be true: only a new QR scan can fix this")
	}
	if status.ExpiryKnown {
		t.Error("expiryKnown must stay false on a rejected session")
	}
}

// TestSessionMissingFileIsHonestAboutIt: no file must not be reported as a cloud
// rejection, and must not claim an expiry either.
func TestSessionMissingFileIsHonestAboutIt(t *testing.T) {
	p := NewTuya("/nonexistent/dir/session.json")
	status, err := p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.Configured {
		t.Error("configured must be true: a path is wired up")
	}
	if status.FilePresent || status.CloudVerified || status.Valid {
		t.Fatalf("status = %+v, want filePresent=false cloudVerified=false valid=false", status)
	}
	if status.ExpiryKnown || status.ExpiresAt != nil {
		t.Error("a missing session must not report an expiry")
	}
	if !status.ReloginRequired {
		t.Error("reloginRequired must be true with no usable session")
	}
}

// TestSessionStandsDownStreamsWhenTheCloudRejects is delivery item 3 at the
// provider layer: the liveness verdict must actually stop the bleed.
func TestSessionStandsDownStreamsWhenTheCloudRejects(t *testing.T) {
	stopper := &fakeStopper{suspended: []models.StreamInfo{
		{ID: "stream_1", ProfileToken: "tuya:eb9f1d6e677b1b39f222ag", Provider: KindTuya},
	}}
	lister := &fakeLister{err: &tuyaqr.SessionExpiredError{StatusCode: 401, ErrorCode: "USER_SESSION_LOSS"}}
	p := NewTuya("/tmp/session.json", withTuyaLister(lister, testSession()), WithTuyaStreamStopper(stopper))

	status, err := p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stopper.suspendCall != 1 {
		t.Fatalf("SuspendStreamsForProvider calls = %d, want exactly 1", stopper.suspendCall)
	}
	if status.ExpiredStreamsStopped != 1 {
		t.Errorf("expiredStreamsStopped = %d, want 1 (the API must be able to report it)", status.ExpiredStreamsStopped)
	}
}

// TestSessionDoesNotTouchStreamsWhenTheSessionIsFine guards against a false
// positive stopping healthy streams.
func TestSessionDoesNotTouchStreamsWhenTheSessionIsFine(t *testing.T) {
	stopper := &fakeStopper{suspended: []models.StreamInfo{{ID: "stream_1", Provider: KindTuya}}}
	lister := &fakeLister{}
	p := NewTuya("/tmp/session.json", withTuyaLister(lister, testSession()), WithTuyaStreamStopper(stopper))

	if _, err := p.Session(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stopper.suspendCall != 0 {
		t.Fatalf("a healthy session stood down %d stream(s)", stopper.suspendCall)
	}
}

// TestSessionCachesTheCloudVerdict proves the UI polling cannot hammer the cloud:
// consecutive calls within the TTL must not issue a second probe.
func TestSessionCachesTheCloudVerdict(t *testing.T) {
	lister := &fakeLister{}
	p := NewTuya("/tmp/session.json", withTuyaLister(lister, testSession()), withTuyaValidateTTL(time.Minute))

	for i := 0; i < 5; i++ {
		if _, err := p.Session(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if lister.refreshCalls != 1 {
		t.Fatalf("probe calls = %d, want 1 across 5 polls (the verdict must be cached)", lister.refreshCalls)
	}
}

// TestStartStreamOnADeadSessionAsksForAReloginAndStopsTheBleed is delivery items
// 3 and 4 at the start-stream checkpoint.
func TestStartStreamOnADeadSessionAsksForAReloginAndStopsTheBleed(t *testing.T) {
	stopper := &fakeStopper{suspended: []models.StreamInfo{{ID: "stream_1", ProfileToken: "tuya:eb9f1d6e677b1b39f222ag", Provider: KindTuya}}}
	bridge := &fakeBridge{err: errors.New("tuyaengine: engine cannot connect: session rejected")}
	lister := &fakeLister{err: &tuyaqr.SessionExpiredError{StatusCode: 401, ErrorCode: "USER_SESSION_LOSS"}}
	p := NewTuya("/tmp/session.json",
		WithTuyaBridge(bridge), WithTuyaStreamStopper(stopper), withTuyaLister(lister, testSession()))

	_, err := p.StartStream("eb9f1d6e677b1b39f222ag")
	if !errors.Is(err, ErrSessionReloginRequired) {
		t.Fatalf("err = %v, want ErrSessionReloginRequired", err)
	}
	if stopper.suspendCall != 1 {
		t.Fatalf("suspend calls = %d, want 1 (the other Tuya streams must not be left to hot-loop)", stopper.suspendCall)
	}
}

// TestStartStreamDoesNotBlameTheSessionForACameraFailure: only a typed
// ErrSessionExpired may trigger the degradation, so a legitimately offline camera
// cannot cause a mass stand-down.
func TestStartStreamDoesNotBlameTheSessionForACameraFailure(t *testing.T) {
	stopper := &fakeStopper{}
	bridge := &fakeBridge{err: errors.New("tuyaengine: camera offline")}
	lister := &fakeLister{err: &tuyaqr.APIError{StatusCode: 500, ErrorCode: "SERVER_ERROR"}}
	p := NewTuya("/tmp/session.json",
		WithTuyaBridge(bridge), WithTuyaStreamStopper(stopper), withTuyaLister(lister, testSession()))

	_, err := p.StartStream("eb9f1d6e677b1b39f222ag")
	if errors.Is(err, ErrSessionReloginRequired) {
		t.Fatal("a non-session failure was reported as a dead session")
	}
	if stopper.suspendCall != 0 {
		t.Fatalf("suspend calls = %d, want 0 for a camera failure", stopper.suspendCall)
	}
}

// TestResumeStreamsRestartsTheSameCamerasWithoutReSelecting is the core of
// delivery item 4 at the provider layer: the profile tokens were kept, so the
// devices come back on their own.
func TestResumeStreamsRestartsTheSameCamerasWithoutReSelecting(t *testing.T) {
	stopper := &fakeStopper{suspended: []models.StreamInfo{
		{ID: "stream_1", ProfileToken: "tuya:eb9f1d6e677b1b39f222ag", Provider: KindTuya},
		{ID: "stream_2", ProfileToken: "tuya:aaaaaaaaaaaaaaaaaaaaaa", Provider: KindTuya},
	}}
	bridge := &fakeBridge{}
	p := NewTuya("/tmp/session.json", WithTuyaBridge(bridge), WithTuyaStreamStopper(stopper))
	// Nothing may be selected by the caller: that is the whole point.
	resumed, failures, err := p.ResumeStreams(context.Background())
	if err != nil {
		t.Fatalf("ResumeStreams: %v (failures=%v)", err, failures)
	}
	if resumed != 2 {
		t.Fatalf("resumed = %d, want 2", resumed)
	}
	if stopper.resumeCalls != 2 {
		t.Fatalf("ResumeSuspended calls = %d, want 2", stopper.resumeCalls)
	}
	want := []string{"stream_1", "stream_2"}
	for i, id := range want {
		if stopper.resumedIDs[i] != id {
			t.Errorf("resumed[%d] = %q, want %q", i, stopper.resumedIDs[i], id)
		}
	}
	if len(bridge.resolved) != 2 || bridge.resolved[1] != "aaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("the engine was asked to resolve %v, want both suspended devices in order", bridge.resolved)
	}
}

// TestResumeStreamsIsANoOpWhenNothingIsSuspended keeps a post-login call safe.
func TestResumeStreamsIsANoOpWhenNothingIsSuspended(t *testing.T) {
	stopper := &fakeStopper{}
	p := NewTuya("/tmp/session.json", WithTuyaBridge(&fakeBridge{}), WithTuyaStreamStopper(stopper))
	resumed, failures, err := p.ResumeStreams(context.Background())
	if err != nil || resumed != 0 || len(failures) != 0 {
		t.Fatalf("resumed=%d failures=%v err=%v, want 0/none/nil", resumed, failures, err)
	}
	if stopper.resumeCalls != 0 {
		t.Errorf("resume calls = %d, want 0", stopper.resumeCalls)
	}
}

// TestLogoutRemovesTheStoredSessionLocallyAndDropsHandshakes covers the file
// half of delivery item 5.
func TestLogoutRemovesTheStoredSessionLocallyAndDropsHandshakes(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/user_us-west.json"
	if err := tuyaqr.SaveSession(path, testSession()); err != nil {
		t.Fatal(err)
	}
	m := NewLoginManager(
		WithLoginClientFactory(func() LoginClient { return &fakeLoginClient{pollSeq: []pollStep{{}}} }),
		WithLoginSessionFile(path),
	)
	if _, err := m.Begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.Pending() != 1 {
		t.Fatalf("pending = %d, want 1 before logout", m.Pending())
	}

	removed, err := m.Logout()
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Error("removed = false, want true when a file was actually deleted")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("the session file still exists after logout: %v", statErr)
	}
	if m.Pending() != 0 {
		t.Errorf("pending = %d, want 0: an in-flight handshake must not resurrect the old account", m.Pending())
	}
	// A second logout is not an error: the desired state is already reached.
	removedAgain, err := m.Logout()
	if err != nil || removedAgain {
		t.Fatalf("second logout: removed=%t err=%v, want false/nil", removedAgain, err)
	}
}

// TestLogoutWithNoConfiguredFileIsSafe covers an install that never set a path.
func TestLogoutWithNoConfiguredFileIsSafe(t *testing.T) {
	m := NewLoginManager()
	removed, err := m.Logout()
	if err != nil || removed {
		t.Fatalf("removed=%t err=%v, want false/nil", removed, err)
	}
}

// TestStartStreamRefusesBeforeTheEngineStartsOnADeadSession is the fix for a gap
// measured live: the Tuya engine happily registers a stream whose session is dead
// and only fails on connect, so the HLS watchdog then restarts ffmpeg forever.
// The session must be probed BEFORE the bridge is called, and the bridge must not
// be touched at all.
func TestStartStreamRefusesBeforeTheEngineStartsOnADeadSession(t *testing.T) {
	stopper := &fakeStopper{}
	bridge := &fakeBridge{}
	lister := &fakeLister{err: &tuyaqr.SessionExpiredError{StatusCode: 401, ErrorCode: "USER_SESSION_LOSS"}}
	p := NewTuya("/tmp/session.json",
		WithTuyaBridge(bridge), WithTuyaStreamStopper(stopper), withTuyaLister(lister, testSession()))

	_, err := p.StartStream("eb9f1d6e677b1b39f222ag")
	if !errors.Is(err, ErrSessionReloginRequired) {
		t.Fatalf("err = %v, want ErrSessionReloginRequired", err)
	}
	if bridge.lastSpec.DeviceID != "" {
		t.Fatalf("the engine was asked to start %q; a dead session must be refused BEFORE any stream is registered",
			bridge.lastSpec.DeviceID)
	}
}

// TestStartStreamProbesBeforeStartingExactlyOnce keeps the gate from becoming a
// cloud-cost regression: a fresh verdict must be reused, not re-fetched.
func TestStartStreamProbesBeforeStartingOncePerVerdictWindow(t *testing.T) {
	bridge := &fakeBridge{}
	lister := &fakeLister{}
	p := NewTuya("/tmp/session.json",
		WithTuyaBridge(bridge), withTuyaLister(lister, testSession()), withTuyaValidateTTL(time.Minute))

	for i := 0; i < 4; i++ {
		if _, err := p.StartStream("eb9f1d6e677b1b39f222ag"); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
	}
	if lister.probeCalls() != 1 {
		t.Fatalf("probes = %d, want 1 across 4 starts (the verdict is cached)", lister.probeCalls())
	}
}

// TestStartStreamDoesNotBlameTheSessionForATransportFailure is the safety rule
// that keeps a flaky network from stopping every stream.
func TestStartStreamDoesNotBlameTheSessionForATransportFailure(t *testing.T) {
	stopper := &fakeStopper{}
	bridge := &fakeBridge{}
	// A transport error, NOT a typed rejection.
	lister := &fakeLister{probeErr: errors.New("dial tcp: connection reset"), probeErrSet: true}
	p := NewTuya("/tmp/session.json",
		WithTuyaBridge(bridge), WithTuyaStreamStopper(stopper), withTuyaLister(lister, testSession()))

	info, err := p.StartStream("eb9f1d6e677b1b39f222ag")
	if err != nil {
		t.Fatalf("a transport failure must not block a start: %v", err)
	}
	if info == nil {
		t.Fatal("no stream info returned")
	}
	if stopper.suspendCall != 0 {
		t.Fatalf("a transport failure stood down %d stream(s); only a typed rejection may", stopper.suspendCall)
	}
}

// --- QR login state machine -------------------------------------------------

func TestLoginBeginReturnsADataURLPNGAndAWindow(t *testing.T) {
	m := NewLoginManager(WithLoginClientFactory(func() LoginClient { return &fakeLoginClient{} }))

	ticket, err := m.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ticket.Token == "" {
		t.Fatal("empty token")
	}
	if ticket.TTLSeconds != int(tuyaqr.TokenTTL.Seconds()) {
		t.Fatalf("ttlSeconds = %d, want %d", ticket.TTLSeconds, int(tuyaqr.TokenTTL.Seconds()))
	}
	if ticket.RemainingSeconds <= 0 || ticket.RemainingSeconds > ticket.TTLSeconds {
		t.Fatalf("remainingSeconds = %d, want within (0, %d]", ticket.RemainingSeconds, ticket.TTLSeconds)
	}
	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(ticket.QRPNGDataURL, prefix) {
		t.Fatalf("qrPng does not start with %q", prefix)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ticket.QRPNGDataURL, prefix))
	if err != nil {
		t.Fatalf("qrPng is not valid base64: %v", err)
	}
	// PNG magic: 0x89 'P' 'N' 'G'. This is the token-bearing image, so it must
	// really be an image and not an error string.
	if len(raw) < 8 || raw[0] != 0x89 || string(raw[1:4]) != "PNG" {
		t.Fatalf("qrPng is not a PNG (first bytes %x)", raw[:min(8, len(raw))])
	}
	if m.Pending() != 1 {
		t.Fatalf("pending = %d, want 1", m.Pending())
	}
}

func TestLoginPollReportsPendingThenDoneAndPersists(t *testing.T) {
	client := &fakeLoginClient{pollSeq: []pollStep{{}, {}, {done: true}}}
	saved := ""
	m := NewLoginManager(
		WithLoginClientFactory(func() LoginClient { return client }),
		WithLoginSessionFile("/tmp/should-not-be-written.json"),
		WithLoginSaver(func(path string, s *tuyaqr.Session) error {
			saved = path
			return nil
		}),
	)
	ticket, err := m.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		result, err := m.Poll(context.Background(), ticket.Token)
		if err != nil {
			t.Fatal(err)
		}
		if result.Status != StatusPending {
			t.Fatalf("poll %d status = %q, want pending", i, result.Status)
		}
		if result.RemainingSeconds <= 0 {
			t.Fatalf("poll %d remainingSeconds = %d, want > 0 so the UI can count down", i, result.RemainingSeconds)
		}
	}

	result, err := m.Poll(context.Background(), ticket.Token)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusDone {
		t.Fatalf("status = %q, want done", result.Status)
	}
	if result.Session == nil || result.Session.CookieCount != 4 {
		t.Fatalf("session = %#v, want 4 cookies", result.Session)
	}
	if saved != "/tmp/should-not-be-written.json" {
		t.Fatalf("session was not persisted to the configured path (saved=%q)", saved)
	}
	// A completed token is single-use.
	if _, err := m.Poll(context.Background(), ticket.Token); !errors.Is(err, ErrLoginUnknown) {
		t.Fatalf("re-polling a completed token gave %v, want ErrLoginUnknown", err)
	}
	if m.Pending() != 0 {
		t.Fatalf("pending = %d, want 0 after a completed scan", m.Pending())
	}
}

func TestLoginPollReportsExpiredOnTheCloudVerdict(t *testing.T) {
	client := &fakeLoginClient{pollSeq: []pollStep{{err: &tuyaqr.QRExpiredError{ErrorCode: "USER_QR_LOGIN_TOKEN_EXPIRE"}}}}
	m := NewLoginManager(WithLoginClientFactory(func() LoginClient { return client }))
	ticket, err := m.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.Poll(context.Background(), ticket.Token)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusExpired {
		t.Fatalf("status = %q, want expired", result.Status)
	}
	if m.Pending() != 0 {
		t.Fatalf("pending = %d, want 0 so a dead token cannot leak", m.Pending())
	}
}

func TestLoginPollStopsOnTheLocalTTL(t *testing.T) {
	client := &fakeLoginClient{pollSeq: []pollStep{{}}}
	m := NewLoginManager(WithLoginClientFactory(func() LoginClient { return client }))
	ticket, err := m.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite the stored handshake so the local countdown has already elapsed.
	// This is the exact failure the UI must never miss: a stale QR that the
	// cloud would reject must be reported as expired by the countdown alone.
	m.mu.Lock()
	for _, entry := range m.pending {
		entry.login.ExpiresAt = time.Now().Add(-time.Second)
	}
	m.mu.Unlock()

	result, err := m.Poll(context.Background(), ticket.Token)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusExpired {
		t.Fatalf("status = %q, want expired once the local TTL elapsed", result.Status)
	}
	if client.polls != 0 {
		t.Fatalf("a poll was sent for a locally expired token (%d), wasting the cloud call", client.polls)
	}
}

func TestLoginPollUnknownTokenAsksForANewQR(t *testing.T) {
	m := NewLoginManager(WithLoginClientFactory(func() LoginClient { return &fakeLoginClient{} }))
	if _, err := m.Poll(context.Background(), "not-a-real-token"); !errors.Is(err, ErrLoginUnknown) {
		t.Fatalf("err = %v, want ErrLoginUnknown", err)
	}
}

func TestLoginNeverPersistsBeforeAScanCompletes(t *testing.T) {
	saves := 0
	m := NewLoginManager(
		WithLoginClientFactory(func() LoginClient { return &fakeLoginClient{pollSeq: []pollStep{{}}} }),
		WithLoginSessionFile("/tmp/never.json"),
		WithLoginSaver(func(string, *tuyaqr.Session) error { saves++; return nil }),
	)
	ticket, err := m.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Poll(context.Background(), ticket.Token); err != nil {
		t.Fatal(err)
	}
	if saves != 0 {
		t.Fatalf("session written %d times before any scan; opening the Tuya tab must not touch the stored session", saves)
	}
}

func TestLoginSurfaceHookFiresOnSuccess(t *testing.T) {
	fired := 0
	m := NewLoginManager(
		WithLoginClientFactory(func() LoginClient { return &fakeLoginClient{pollSeq: []pollStep{{done: true}}} }),
		WithLoginSessionSink(func(*tuyaqr.Session) { fired++ }),
	)
	ticket, err := m.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Poll(context.Background(), ticket.Token); err != nil {
		t.Fatal(err)
	}
	if fired != 1 {
		t.Fatalf("session sink fired %d times, want 1", fired)
	}
}

// min is a local helper: this repo builds with go1.23 and the builtin arrived
// in go1.21, but being explicit keeps the test readable at a glance.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
