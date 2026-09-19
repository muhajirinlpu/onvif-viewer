package tuyaqr

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
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
				// completes the scan. Values here are fake.
				w.Header().Add("Set-Cookie", "fast-sid=fakesidvalue; Path=/")
				w.Header().Add("Set-Cookie", "s-sid=fakesidsessionvalue; Path=/")
				w.Header().Add("Set-Cookie", "locale=en; Path=/")
				w.Header().Add("Set-Cookie", "gTyPlatLang=en; Path=/")
				_, _ = w.Write([]byte(scannedOK))
				return
			}
			_, _ = w.Write([]byte(body))
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
