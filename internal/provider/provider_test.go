package provider

import (
	"context"
	"encoding/base64"
	"errors"
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
}

func (f *fakeLister) Cameras(context.Context) ([]tuyaqr.Device, error) {
	f.calls++
	return f.devices, f.err
}

func (f *fakeLister) Validate(context.Context) error { return f.err }

type fakeBridge struct {
	lastSpec tuyaengine.DeviceSpec
	info     *models.StreamInfo
	err      error
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

func (f *fakeBridge) Resolve(string) (string, error) { return "rtsp://127.0.0.1:8554/x", nil }

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
	p := NewTuya("/tmp/session.json", WithTuyaBridge(bridge))

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
