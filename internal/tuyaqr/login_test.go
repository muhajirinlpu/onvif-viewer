package tuyaqr

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// withBase is the test-only hook that points a Client at an httptest server.
func withBase(u string) Option { return func(o *Options) { o.baseOverride = u } }

// fakeCloud is a scripted stand-in for the Tuya protect cloud.
type fakeCloud struct {
	mu sync.Mutex
	// pollScript is consumed one entry per /api/login/poll call. The last
	// entry repeats forever.
	pollScript []string
	polls      int
	qcTokens   int

	// onPollSuccess, when set, is invoked before the terminal success reply so
	// the handler can Set-Cookie like the real cloud does.
	headers http.Header
	origin  string

	// homeList is the authenticated probe the captured session must survive
	// before it is returned. These knobs let a test script it.
	homeListCalls        int
	homeListStatus       int  // non-zero makes every probe answer that status (401 -> USER_SESSION_LOSS)
	suppressExpiryHeader bool // simulate a cloud that reports no cookie Expires at all
}

const (
	fakeToken   = "AZ1789816670942V5AXLGJFW7TESTTESTTESTTESTTESTTESTTESTTESTTESTTEST"
	pendingBody = `{"result":true,"success":true,"status":"ok"}`
	expiredBody = `{"success":false,"errorCode":"USER_QR_LOGIN_TOKEN_EXPIRE","errorMsg":"登录二维码已失效"}`
	scannedBody = `{"success":false,"errorCode":"USER_QR_LOGIN_TOKEN_SCANED","errorMsg":"二维码已被扫描"}`
	scannedOK   = `{"success":true,"result":{"uid":"az1670113591347HF6E9","email":"user@example.test","nickname":"Tester","domain":{"mobileMqttsUrl":"m1.tuyaus.example","mqttsPort":8883,"regionCode":"AZ"},"sid":"sid-value-not-a-real-secret","attribute":1,"clientId":"cid","dataVersion":1,"ecode":"e","extras":{"homeId":"1","sceneType":"CUSTOMER"},"headPic":"","improveCompanyInfo":false,"partnerIdentity":"p1","phoneCode":"62","receiver":"user@example.test","regFrom":5,"snsNickname":"Tester","tempUnit":1,"timezone":"","timezoneId":"Asia/Jakarta","userType":1,"username":"u"}}`
)

func (f *fakeCloud) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if got := r.Header.Get("Content-Type"); got != "application/json; charset=utf-8" {
			t.Errorf("Content-Type = %q, want application/json; charset=utf-8", got)
		}
		if got := r.Header.Get("X-Requested-With"); got != "XMLHttpRequest" {
			t.Errorf("X-Requested-With = %q", got)
		}
		if got := r.Header.Get("Origin"); got != f.origin {
			t.Errorf("Origin = %q, want %q", got, f.origin)
		}
		if got := r.Header.Get("Referer"); !strings.HasPrefix(got, f.origin+"/") {
			t.Errorf("Referer = %q, want prefix %q", got, f.origin+"/")
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}

		switch r.URL.Path {
		case pathQCtoken:
			if r.ContentLength > 0 {
				var probe map[string]any
				if err := json.NewDecoder(r.Body).Decode(&probe); err == nil && len(probe) > 0 {
					t.Errorf("QCtoken body = %v, want empty", probe)
				}
			}
			f.qcTokens++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"result":"` + fakeToken + `","success":true}`))
		case pathPoll:
			// The token must be echoed back in the body.
			var req struct {
				Token string `json:"token"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Token != fakeToken {
				t.Errorf("poll token = %q, want the QCtoken value", req.Token)
			}
			body := pendingBody
			if f.polls < len(f.pollScript) {
				body = f.pollScript[f.polls]
			} else if len(f.pollScript) > 0 {
				body = f.pollScript[len(f.pollScript)-1]
			}
			f.polls++
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(body, "fast-sid") || body == "SUCCESS_WITH_COOKIES" {
				// Real cloud sets the session cookies on the poll that
				// completes the scan. Values here are fake, and MEASURED: the
				// cookies the poll sets are SESSION cookies with no Expires.
				w.Header().Add("Set-Cookie", "fast-sid=fakesidvalue; Path=/; Secure; HttpOnly")
				w.Header().Add("Set-Cookie", "s-sid=fakesidsessionvalue; Path=/; Secure; HttpOnly")
				w.Header().Add("Set-Cookie", "locale=en; Path=/; Secure")
				w.Header().Add("Set-Cookie", "gTyPlatLang=en; Path=/; Secure")
				_, _ = w.Write([]byte(scannedOK))
				return
			}
			_, _ = w.Write([]byte(body))
		case pathHomeList:
			// MEASURED on the real cloud: an authenticated call re-emits
			// fast-sid WITH its real expiry. This is the only place the expiry
			// is ever visible, so the Client folds it into the captured
			// session right after a scan completes.
			f.homeListCalls++
			if f.homeListStatus != 0 {
				w.WriteHeader(f.homeListStatus)
				_, _ = w.Write([]byte(`{"success":false,"errorCode":"USER_SESSION_LOSS"}`))
				return
			}
			if !f.suppressExpiryHeader {
				w.Header().Add("Set-Cookie", "fast-sid=fakesidvalue; Path=/; Expires="+
					time.Now().Add(48*time.Hour).UTC().Format(http.TimeFormat)+"; Secure; HttpOnly")
				w.Header().Add("Set-Cookie", "gTyPlatLang=en; Path=/; Expires="+
					time.Now().Add(1000*time.Hour).UTC().Format(http.TimeFormat)+"; Secure")
				w.Header().Add("Set-Cookie", "locale=en; Path=/; Secure")
				w.Header().Add("Set-Cookie", "s-sid=fakesidsessionvalue; Path=/; Secure; HttpOnly")
			}
			_, _ = w.Write([]byte(`{"result":[],"success":true,"status":"ok"}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func newFakeCloud(t *testing.T, script ...string) (*fakeCloud, *Client) {
	t.Helper()
	f := &fakeCloud{pollScript: script}
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	f.origin = srv.URL
	c := NewClient(WithHost(u.Host), WithHTTPClient(&http.Client{}), withBase(srv.URL))
	return f, c
}

// TestQRLoginStateMachine drives pending -> scanned -> session and asserts the
// session shape the HTTP layer will persist. This is the measured success path:
// result:true while unscanned, and a result object containing uid when scanned.
func TestQRLoginStateMachine(t *testing.T) {
	f, c := newFakeCloud(t, pendingBody, pendingBody, "SUCCESS_WITH_COOKIES")

	login, err := c.BeginLoginSession(context.Background())
	if err != nil {
		t.Fatalf("BeginLoginSession: %v", err)
	}
	if login.Token != fakeToken {
		t.Fatalf("token = %q, want %q", login.Token, fakeToken)
	}
	if want := "tuyaSmart--qrLogin?token=" + fakeToken; login.Payload != want {
		t.Fatalf("payload = %q, want %q", login.Payload, want)
	}
	if got := login.Remaining(); got <= 0 || got > TokenTTL {
		t.Fatalf("Remaining() = %v, want (0, %v]", got, TokenTTL)
	}

	// 1) pending
	sess, done, err := c.PollLogin(context.Background(), login)
	if err != nil || done || sess != nil {
		t.Fatalf("pending poll: sess=%v done=%v err=%v, want nil/false/nil", sess, done, err)
	}
	// 2) still pending
	sess, done, err = c.PollLogin(context.Background(), login)
	if err != nil || done || sess != nil {
		t.Fatalf("second pending poll: sess=%v done=%v err=%v", sess, done, err)
	}
	// 3) scanned -> session
	sess, done, err = c.PollLogin(context.Background(), login)
	if err != nil || !done || sess == nil {
		t.Fatalf("scanned poll: sess=%v done=%v err=%v, want session/true/nil", sess, done, err)
	}
	if f.qcTokens != 1 {
		t.Errorf("QCtoken calls = %d, want 1", f.qcTokens)
	}
	if f.polls != 3 {
		t.Errorf("poll calls = %d, want 3", f.polls)
	}
	if f.homeListCalls != 1 {
		t.Errorf("authenticated expiry probe calls = %d, want exactly 1", f.homeListCalls)
	}
	if sess.Email != "user@example.test" || sess.SessionData.LoginResult.UID != "az1670113591347HF6E9" {
		t.Errorf("session identity mismatch: email=%q uid=%q", sess.Email, sess.SessionData.LoginResult.UID)
	}
	if sess.SessionData.ServerHost == "" || sess.Region == "" {
		t.Errorf("session missing host/region: host=%q region=%q", sess.SessionData.ServerHost, sess.Region)
	}
	fast, sSID, n := sess.AuthCookieStatus()
	if !fast || !sSID {
		t.Fatalf("captured cookies lack fast-sid/s-sid (have %d: %s)", n, strings.Join(sess.CookieNames(), ","))
	}
	t.Logf("state machine: pending,pending -> scanned; cookies captured=%d names=%v",
		n, sess.CookieNames())

	// The captured session must itself be persistable and reloadable.
	path := t.TempDir() + "/session.json"
	if err := SaveSession(path, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	reloaded, err := LoadSession(path)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	if _, err := NewClientFromSession(reloaded, withBase(f.origin)); err != nil {
		t.Fatalf("NewClientFromSession(reloaded): %v", err)
	}
}

// TestQRLoginExpired covers the measured expiry signal: success:false with
// errorCode USER_QR_LOGIN_TOKEN_EXPIRE. The HTTP layer must be able to tell
// this apart from other failures.
func TestQRLoginExpired(t *testing.T) {
	_, c := newFakeCloud(t, pendingBody, expiredBody)

	login, err := c.BeginLoginSession(context.Background())
	if err != nil {
		t.Fatalf("BeginLoginSession: %v", err)
	}
	if _, _, err := c.PollLogin(context.Background(), login); err != nil {
		t.Fatalf("first poll should be pending, got %v", err)
	}
	sess, done, err := c.PollLogin(context.Background(), login)
	if !errors.Is(err, ErrQRExpired) {
		t.Fatalf("err = %v, want errors.Is(ErrQRExpired)", err)
	}
	if sess != nil || done {
		t.Fatalf("expired poll returned session=%v done=%v", sess, done)
	}
	var typed *QRExpiredError
	if !errors.As(err, &typed) || typed.ErrorCode != "USER_QR_LOGIN_TOKEN_EXPIRE" {
		t.Fatalf("typed error missing: %#v", err)
	}
	t.Logf("expiry: %v", err)
}

// TestQRLoginScannedElsewhere covers the second terminal server signal.
func TestQRLoginScannedElsewhere(t *testing.T) {
	_, c := newFakeCloud(t, scannedBody)
	login, err := c.BeginLoginSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = c.PollLogin(context.Background(), login)
	if !errors.Is(err, ErrQRScanned) {
		t.Fatalf("err = %v, want ErrQRScanned", err)
	}
	t.Logf("scanned-elsewhere: %v", err)
}

// TestPollStopsAtLocalTTL proves the client refuses to poll a token whose
// local countdown has run out (measured TTL ~12 min), without a network call.
func TestPollStopsAtLocalTTL(t *testing.T) {
	f, c := newFakeCloud(t, pendingBody)
	login := &Login{Token: fakeToken, Payload: QRBindingPrefix + fakeToken, Host: "example.test",
		IssuedAt: time.Now().Add(-13 * time.Minute), ExpiresAt: time.Now().Add(-time.Second)}

	_, _, err := c.PollLogin(context.Background(), login)
	if !errors.Is(err, ErrQRExpired) {
		t.Fatalf("err = %v, want ErrQRExpired", err)
	}
	if !login.Expired() || login.Remaining() != 0 {
		t.Fatalf("Expired()=%v Remaining()=%v, want true/0", login.Expired(), login.Remaining())
	}
	if f.polls != 0 {
		t.Fatalf("polled %d times on a locally-expired token, want 0", f.polls)
	}
}

// TestBeginLoginSessionExpiryWindow pins the advertised token lifetime to the
// measured TTL window (12 min minus the 30s refresh margin).
func TestBeginLoginSessionExpiryWindow(t *testing.T) {
	_, c := newFakeCloud(t)
	login, err := c.BeginLoginSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	window := login.ExpiresAt.Sub(login.IssuedAt)
	if window != TokenTTL-tokenSafetyMargin {
		t.Fatalf("window = %v, want %v", window, TokenTTL-tokenSafetyMargin)
	}
}

func TestBeginLoginRejectsRefusal(t *testing.T) {
	f := &fakeCloud{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":false,"errorCode":"SOME_ERROR","errorMsg":"nope"}`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	c := NewClient(WithHost(u.Host), WithHTTPClient(&http.Client{}), withBase(srv.URL))
	_ = f
	_, _, err := c.BeginLogin(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode != "SOME_ERROR" {
		t.Fatalf("err = %v, want *APIError with SOME_ERROR", err)
	}
}

// TestSessionExpiredIsTyped covers the post-login failure mode the HTTP layer
// must handle separately: the cloud rejecting the stored cookies.
func TestSessionExpiredIsTyped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"success":false,"errorCode":"USER_SESSION_LOSS","errorMsg":"Not login"}`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	c := newFakeAuthedClient(t, srv.URL, u.Host)

	err := c.Validate(context.Background())
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("err = %v, want ErrSessionExpired", err)
	}
	_, err = c.Cameras(context.Background())
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Cameras err = %v, want ErrSessionExpired", err)
	}
	t.Logf("session-expired: %v", err)
}

// newFakeAuthedClient builds a client backed by a hand-made session (no disk).
func newFakeAuthedClient(t *testing.T, base, host string) *Client {
	t.Helper()
	s := &Session{
		Region: "us-west", Email: "user@example.test", UserKey: "us-west_user_at_example_test",
		LastRefresh: time.Now(),
		SessionData: UserSession{
			LoginResult: &LoginResult{UID: "uid", Email: "user@example.test"},
			Cookies: []*Cookie{
				{Name: "fast-sid", Value: "fake", Path: "/"},
				{Name: "s-sid", Value: "fake", Path: "/"},
			},
			LastValidated: time.Now(), ServerHost: host, Region: "us-west", UserEmail: "user@example.test",
		},
	}
	c, err := NewClientFromSession(s, WithHTTPClient(&http.Client{}), withBase(base))
	if err != nil {
		t.Fatalf("NewClientFromSession: %v", err)
	}
	return c
}

// --- M6: real expiry capture and honest unknowns ----------------------------

// TestCapturedCookiesKeepsServerExpiry is the core of the M6 honesty fix: the
// Expires the cloud sends must survive into the stored Cookie, and a cookie the
// cloud sends WITHOUT an expiry must stay zero rather than gain a made-up one.
func TestCapturedCookiesKeepsServerExpiry(t *testing.T) {
	now := time.Now()
	future := now.Add(48 * time.Hour).UTC().Truncate(time.Second)
	past := now.Add(-time.Hour).UTC().Truncate(time.Second)

	got := capturedCookies([]string{
		"fast-sid=abc; Path=/; Expires=" + future.Format(http.TimeFormat) + "; Secure; HttpOnly",
		// A session cookie: no Expires attribute at all. This is what the real
		// QR-login poll sets, so it must NOT be given an expiry.
		"s-sid=def; Path=/; Secure; HttpOnly",
		// A cookie the cloud explicitly expired must never be persisted as a
		// live deadline.
		"locale=en; Path=/; Expires=" + past.Format(http.TimeFormat) + "; Secure",
		// Go represents "no Expires" internally as year 1 + Max-Age=0; that is
		// exactly how a real Set-Cookie with no attributes arrives, so it must
		// be treated as unknown too.
		"gTyPlatLang=en; Path=/; Secure",
	}, now)

	byName := map[string]*Cookie{}
	for _, c := range got {
		byName[c.Name] = c
	}
	if len(got) != 4 {
		t.Fatalf("captured %d cookies, want 4 (%v)", len(got), got)
	}
	if got := byName["fast-sid"]; got == nil || !got.Expires.Equal(future) {
		t.Fatalf("fast-sid expires = %v, want the server-reported %v", got, future)
	}
	if got := byName["s-sid"]; got == nil || !got.Expires.IsZero() {
		t.Fatalf("s-sid expires = %v, want ZERO (the cloud declared none)", got)
	}
	if got := byName["locale"]; got == nil || !got.Expires.IsZero() {
		t.Fatalf("locale expires = %v, want ZERO (a past expiry must not be stored as a deadline)", got)
	}
	if got := byName["gTyPlatLang"]; got == nil || !got.Expires.IsZero() {
		t.Fatalf("gTyPlatLang expires = %v, want ZERO", got)
	}
	// Credential attributes the cloud sends must survive too, or the cookie
	// would be replayed over the wrong transport.
	if f := byName["fast-sid"]; !f.Secure || !f.HttpOnly || f.Path != "/" {
		t.Errorf("fast-sid attributes lost: secure=%t httponly=%t path=%q", f.Secure, f.HttpOnly, f.Path)
	}
	t.Logf("server expiry captured for fast-sid; cookies with a declared expiry: %d/4 (a session cookie correctly stays unknown)", countWithExpiry(got))
}

func countWithExpiry(cookies []*Cookie) int {
	n := 0
	for _, c := range cookies {
		if c != nil && !c.Expires.IsZero() {
			n++
		}
	}
	return n
}

// TestApplyReportedExpiryOnlyEverAddsRealDeadlines pins the guard rails: a probe
// can move a cookie from "unknown" to the cloud's value, but it can never invent
// one for a cookie the cloud did not mention, and never a past deadline.
func TestApplyReportedExpiryOnlyEverAddsRealDeadlines(t *testing.T) {
	now := time.Now()
	real := now.Add(60 * time.Hour).UTC().Truncate(time.Second)
	s := &Session{SessionData: UserSession{Cookies: []*Cookie{
		{Name: "fast-sid", Value: "v"},
		{Name: "s-sid", Value: "v"},
		{Name: "locale", Value: "en"},
	}}}

	applied := s.applyReportedExpiry([]string{
		"fast-sid=v; Path=/; Expires=" + real.Format(http.TimeFormat),
		"locale=en; Path=/; Expires=" + now.Add(-2*time.Hour).UTC().Format(http.TimeFormat),
	}, now)
	if applied != 1 {
		t.Fatalf("applied = %d, want 1 (only fast-sid declared a usable expiry)", applied)
	}
	byName := map[string]*Cookie{}
	for _, c := range s.SessionData.Cookies {
		byName[c.Name] = c
	}
	if !byName["fast-sid"].Expires.Equal(real) {
		t.Errorf("fast-sid expires = %v, want %v", byName["fast-sid"].Expires, real)
	}
	if !byName["s-sid"].Expires.IsZero() {
		t.Errorf("s-sid gained an expiry the cloud never sent: %v", byName["s-sid"].Expires)
	}
	if !byName["locale"].Expires.IsZero() {
		t.Errorf("locale stored a PAST expiry as a deadline: %v", byName["locale"].Expires)
	}
}

// TestSessionExpiryIsUnknownWhenNoCookieDeclaresOne is the "never fabricate a
// countdown" guard at the data layer. This is the REAL shape of the user's
// stored session.
func TestSessionExpiryIsUnknownWhenNoCookieDeclaresOne(t *testing.T) {
	s := &Session{SessionData: UserSession{Cookies: []*Cookie{
		{Name: "fast-sid", Value: "v"},
		{Name: "s-sid", Value: "v"},
	}}}
	if _, _, ok := s.EarliestCookieExpiry(); ok {
		t.Fatal("EarliestCookieExpiry reported a deadline for a session that declares none")
	}
	with, total := s.CookiesWithExpiry()
	if with != 0 || total != 2 {
		t.Fatalf("cookiesWithExpiry = %d/%d, want 0/2", with, total)
	}
}

// TestSessionEarliestCookieExpiryNamesTheCookie keeps the reported deadline
// auditable: the API attributes it to a specific cookie.
func TestSessionEarliestCookieExpiryNamesTheCookie(t *testing.T) {
	soon := time.Now().Add(2 * time.Hour)
	later := time.Now().Add(20 * time.Hour)
	s := &Session{SessionData: UserSession{Cookies: []*Cookie{
		{Name: "locale", Value: "en", Expires: later},
		{Name: "fast-sid", Value: "v", Expires: soon},
	}}}
	got, name, ok := s.EarliestCookieExpiry()
	if !ok || !got.Equal(soon) || name != "fast-sid" {
		t.Fatalf("EarliestCookieExpiry = (%v, %q, %t), want (%v, fast-sid, true)", got, name, ok, soon)
	}
}

// TestLoginCapturesRealExpiryForANewLogin is the end-to-end proof of delivery
// item 1: a login that completes against a cloud which reports an expiry yields
// a session file carrying that expiry, while the poll's own session cookies stay
// unknown.
func TestLoginCapturesRealExpiryForANewLogin(t *testing.T) {
	f, c := newFakeCloud(t, "SUCCESS_WITH_COOKIES")
	if _, err := c.BeginLoginSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	login := &Login{Token: fakeToken, Payload: QRBindingPrefix + fakeToken, Host: "example.test",
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(TokenTTL - tokenSafetyMargin)}

	sess, done, err := c.PollLogin(context.Background(), login)
	if err != nil || !done || sess == nil {
		t.Fatalf("poll: sess=%v done=%v err=%v", sess, done, err)
	}
	if f.homeListCalls != 1 {
		t.Fatalf("probe calls = %d, want 1", f.homeListCalls)
	}
	expiry, name, ok := sess.EarliestCookieExpiry()
	if !ok {
		t.Fatal("a new login whose cloud reported an expiry stored NO expiry")
	}
	if name != "fast-sid" {
		t.Fatalf("expiry attributed to %q, want fast-sid", name)
	}
	if until := time.Until(expiry); until < 47*time.Hour || until > 49*time.Hour {
		t.Fatalf("stored expiry is %v out, want the ~48h the fake cloud reported", until)
	}
	with, total := sess.CookiesWithExpiry()
	if with != 2 || total != 4 {
		// fast-sid (48h) and gTyPlatLang (1000h) declared one; s-sid and locale
		// did not, and must remain unknown.
		t.Fatalf("cookiesWithExpiry = %d/%d, want 2/4 (only the cookies the cloud gave an Expires for)", with, total)
	}

	// ...and it must survive a save/load round trip, which is what makes a
	// countdown possible for FUTURE logins.
	path := t.TempDir() + "/captured.json"
	if err := SaveSession(path, sess); err != nil {
		t.Fatal(err)
	}
	back, err := LoadSession(path)
	if err != nil {
		t.Fatal(err)
	}
	gotExpiry, gotName, gotOK := back.EarliestCookieExpiry()
	if !gotOK || !gotExpiry.Equal(expiry) || gotName != name {
		t.Fatalf("expiry did not survive save/load: (%v, %q, %t) vs (%v, %q, %t)", gotExpiry, gotName, gotOK, expiry, name, ok)
	}
	t.Logf("captured expiry persisted: %s (%s), %d/4 cookies declare one", expiry.UTC().Format(time.RFC3339), name, with)
}

// TestLoginLeavesExpiryUnknownWhenTheCloudReportsNone is the other half of the
// honesty rule: when the cloud reports no expiry, nothing is invented, and the
// session is still usable.
func TestLoginLeavesExpiryUnknownWhenTheCloudReportsNone(t *testing.T) {
	f, c := newFakeCloud(t, "SUCCESS_WITH_COOKIES")
	f.suppressExpiryHeader = true
	if _, err := c.BeginLoginSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	login := &Login{Token: fakeToken, Payload: QRBindingPrefix + fakeToken, Host: "example.test",
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(TokenTTL - tokenSafetyMargin)}

	sess, done, err := c.PollLogin(context.Background(), login)
	if err != nil || !done || sess == nil {
		t.Fatalf("poll: sess=%v done=%v err=%v", sess, done, err)
	}
	if _, _, ok := sess.EarliestCookieExpiry(); ok {
		t.Fatal("an expiry was invented for a cloud that reported none")
	}
	with, total := sess.CookiesWithExpiry()
	if with != 0 || total != 4 {
		t.Fatalf("cookiesWithExpiry = %d/%d, want 0/4", with, total)
	}
	// The session must still be fully usable.
	if fast, sSID, n := sess.AuthCookieStatus(); !fast || !sSID || n != 4 {
		t.Fatalf("captured session unusable: fast=%t s-sid=%t n=%d", fast, sSID, n)
	}
	t.Logf("cloud reported no expiry: stored expiry stays unknown (%d cookies, 0 with a deadline)", total)
}

// TestOldZeroExpiryFileStillLoads proves backward compatibility: the file shape
// that exists on disk today (all four cookies expires=0001-01-01T00:00:00Z)
// loads, is usable, and reports expiry as unknown.
func TestOldZeroExpiryFileStillLoads(t *testing.T) {
	path := t.TempDir() + "/legacy.json"
	legacy := `{
  "region": "us-west",
  "email": "user@example.test",
  "userKey": "us-west_user_at_example_test",
  "lastRefresh": "2026-09-20T00:33:49.261916387Z",
  "sessionData": {
    "cookies": [
      {"name":"gTyPlatLang","value":"en","domain":"","path":"","expires":"0001-01-01T00:00:00Z","secure":false,"httpOnly":false},
      {"name":"locale","value":"en","domain":"","path":"","expires":"0001-01-01T00:00:00Z","secure":false,"httpOnly":false},
      {"name":"s-sid","value":"` + strings.Repeat("a", 82) + `","domain":"","path":"","expires":"0001-01-01T00:00:00Z","secure":false,"httpOnly":false},
      {"name":"fast-sid","value":"` + strings.Repeat("b", 32) + `","domain":"","path":"","expires":"0001-01-01T00:00:00Z","secure":false,"httpOnly":false}
    ],
    "lastValidated": "2026-09-20T00:33:49.261916387Z",
    "loginResult": {"uid":"az1","email":"user@example.test","domain":{"mobileMqttsUrl":"m1.example","mqttsPort":8883}},
    "region": "us-west",
    "serverHost": "protect-us.ismartlife.me",
    "userEmail": "user@example.test"
  }
}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadSession(path)
	if err != nil {
		t.Fatalf("a legacy zero-expiry file must still load: %v", err)
	}
	if _, err := NewClientFromSession(s); err != nil {
		t.Fatalf("a legacy zero-expiry file must still build a client: %v", err)
	}
	if _, _, ok := s.EarliestCookieExpiry(); ok {
		t.Fatal("a zero-expiry file reported a deadline; the API would show an invented countdown")
	}
	with, total := s.CookiesWithExpiry()
	if with != 0 || total != 4 {
		t.Fatalf("cookiesWithExpiry = %d/%d, want 0/4", with, total)
	}
	t.Logf("legacy zero-expiry session loads and is usable; expiry correctly reported as unknown (%d/%d)", with, total)
}

// TestRefreshExpiryFoldsALiveProbeBackIn covers the pre-M6 session: it can
// acquire a real deadline in memory (never on disk by this call) from a probe.
func TestRefreshExpiryFoldsALiveProbeBackIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "fast-sid=v; Path=/; Expires="+
			time.Now().Add(30*time.Hour).UTC().Format(http.TimeFormat)+"; Secure; HttpOnly")
		_, _ = w.Write([]byte(`{"result":[],"success":true,"status":"ok"}`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	c := newFakeAuthedClient(t, srv.URL, u.Host)

	s := &Session{
		Region: "us-west", Email: "user@example.test",
		SessionData: UserSession{
			LoginResult: &LoginResult{UID: "uid"},
			Cookies:     []*Cookie{{Name: "fast-sid", Value: "v"}, {Name: "s-sid", Value: "v"}},
			ServerHost:  u.Host,
		},
	}
	if _, _, ok := s.EarliestCookieExpiry(); ok {
		t.Fatal("precondition: the session should start with no known expiry")
	}
	if err := c.RefreshExpiry(context.Background(), s); err != nil {
		t.Fatalf("RefreshExpiry: %v", err)
	}
	expiry, name, ok := s.EarliestCookieExpiry()
	if !ok || name != "fast-sid" {
		t.Fatalf("RefreshExpiry did not fold the server expiry back in: (%v, %q, %t)", expiry, name, ok)
	}
	if until := time.Until(expiry); until < 29*time.Hour || until > 31*time.Hour {
		t.Fatalf("folded expiry is %v out, want ~30h", until)
	}
	if !s.SessionData.LastValidated.After(time.Now().Add(-time.Minute)) {
		t.Error("RefreshExpiry did not update lastValidated on a live probe")
	}
}

// TestRefreshExpiryReportsARejectedSession keeps the liveness verdict typed.
func TestRefreshExpiryReportsARejectedSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"success":false,"errorCode":"USER_SESSION_LOSS","errorMsg":"Not login"}`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	c := newFakeAuthedClient(t, srv.URL, u.Host)

	s := &Session{SessionData: UserSession{
		LoginResult: &LoginResult{UID: "uid"},
		Cookies:     []*Cookie{{Name: "fast-sid", Value: "v"}, {Name: "s-sid", Value: "v"}},
		ServerHost:  u.Host,
	}}
	err := c.RefreshExpiry(context.Background(), s)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("err = %v, want ErrSessionExpired", err)
	}
	// A rejected probe must not have written an expiry.
	if _, _, ok := s.EarliestCookieExpiry(); ok {
		t.Fatal("a rejected probe produced an expiry")
	}
}

// TestRenderQRPNGIsValidPNG checks the magic bytes of a rendered login QR.
func TestRenderQRPNGIsValidPNG(t *testing.T) {
	payload := QRBindingPrefix + fakeToken
	png, err := RenderQRPNG(payload, QRImageSize)
	if err != nil {
		t.Fatalf("RenderQRPNG: %v", err)
	}
	if len(png) < 8 {
		t.Fatalf("png too short: %d bytes", len(png))
	}
	magic := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}
	if string(png[:8]) != string(magic) {
		t.Fatalf("magic bytes = % x, want % x", png[:8], magic)
	}
	// IHDR width/height are big-endian uint32 at offsets 16 and 20.
	w := int(png[16])<<24 | int(png[17])<<16 | int(png[18])<<8 | int(png[19])
	h := int(png[20])<<24 | int(png[21])<<16 | int(png[22])<<8 | int(png[23])
	if w != QRImageSize || h != QRImageSize {
		t.Fatalf("IHDR %dx%d, want %dx%d", w, h, QRImageSize, QRImageSize)
	}
	t.Logf("QR PNG: %d bytes, magic=% x, IHDR=%dx%d", len(png), png[:8], w, h)
}
