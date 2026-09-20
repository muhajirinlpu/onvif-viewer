package tuyaqr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// DefaultHost is the Tuya data-centre host measured for this account
// (region label "us-west"): the host the Bardi mobile app talks to.
const DefaultHost = "protect-us.ismartlife.me"

// DefaultRegion is the region label stored in the session file.
const DefaultRegion = "us-west"

// QRBindingPrefix is the literal string the Tuya app expects inside the QR
// image, followed by the token from BeginLogin. MEASURED.
const QRBindingPrefix = "tuyaSmart--qrLogin?token="

// TokenTTL is how long a QR token stays valid. MEASURED at ~12 minutes: the
// token answered polls at t+731s and was rejected as expired by t+737s. The UI
// must show a countdown and refresh well before this.
const TokenTTL = 12 * time.Minute

// tokenSafetyMargin is subtracted from TokenTTL when reporting ExpiresAt, so a
// countdown driven by it reaches zero before the cloud actually rejects polls.
const tokenSafetyMargin = 30 * time.Second

// QR image defaults.
const (
	QRImageSize = 512
)

// API paths. All are POST + JSON.
const (
	pathQCtoken      = "/api/login/security/QCtoken"
	pathPoll         = "/api/login/poll"
	pathAppInfo      = "/api/new/common/getAppInfo"
	pathHomeList     = "/api/new/common/homeList"
	pathRoomList     = "/api/new/common/roomList"
	pathSharedList   = "/api/new/playback/shareList"
	pathJarvisConfig = "/api/jarvis/config"
	pathJarvisMQTT   = "/api/jarvis/mqtt"
)

// Login holds the QR-login handshake state for one token. Create it with
// BeginLogin and drive it with its Poll method.
type Login struct {
	// Token is the QR login token. SECRET-ADJACENT: it is only meaningful
	// together with a scan by the account owner, but it must never be logged
	// or written anywhere except the QR image.
	Token string `json:"token"`

	// Payload is the exact string to encode into the QR image:
	// "tuyaSmart--qrLogin?token=<Token>".
	Payload string `json:"payload"`

	// Host is the cloud host this token was issued by.
	Host string `json:"host"`

	// IssuedAt / ExpiresAt bound the token's life. ExpiresAt already includes
	// a safety margin (TokenTTL - 30s).
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Remaining returns how long the token is still (safely) usable.
func (l *Login) Remaining() time.Duration {
	if l == nil || l.ExpiresAt.IsZero() {
		return 0
	}
	d := time.Until(l.ExpiresAt)
	if d < 0 {
		return 0
	}
	return d
}

// Expired reports whether the local countdown has run out. The cloud is the
// authority; this only lets the UI warn early.
func (l *Login) Expired() bool { return l.Remaining() == 0 }

// Options configures a Client. Every field is optional.
type Options struct {
	// Host overrides DefaultHost. No scheme.
	Host string
	// HTTPClient overrides the default client (15s timeout, no jar).
	HTTPClient *http.Client
	// Timeout is used when HTTPClient is nil. Defaults to 15s.
	Timeout time.Duration
	// UserAgent is sent on every request. Optional.
	UserAgent string

	// baseOverride replaces "https://<host>" when building URLs. It exists so
	// in-package tests can point the client at an httptest server; nothing
	// else should set it.
	baseOverride string
}

// Client talks to the Tuya protect cloud. A Client built without arguments is
// anonymous and can only run the QR-login handshake; use NewClient(session)
// for the authenticated device calls.
type Client struct {
	host      string // bare host, e.g. protect-us.ismartlife.me
	base      string // URL prefix, normally "https://" + host
	http      *http.Client
	userAgent string
}

func (o Options) client() *Client {
	host := strings.TrimSpace(o.Host)
	if host == "" {
		host = DefaultHost
	}
	timeout := o.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	hc := o.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: timeout}
	}
	base := "https://" + host
	if o.baseOverride != "" {
		base = strings.TrimSuffix(o.baseOverride, "/")
	}
	return &Client{host: host, base: base, http: hc, userAgent: o.UserAgent}
}

// NewClient returns an anonymous client (QR login only) for the given host.
// Pass an empty host to use DefaultHost.
func NewClient(opts ...Option) *Client {
	o := Options{}
	for _, fn := range opts {
		fn(&o)
	}
	return o.client()
}

// Option configures an Options value.
type Option func(*Options)

// WithHost sets the cloud host.
func WithHost(host string) Option { return func(o *Options) { o.Host = host } }

// WithHTTPClient sets the underlying HTTP client (e.g. one with a cookie jar).
func WithHTTPClient(hc *http.Client) Option { return func(o *Options) { o.HTTPClient = hc } }

// WithTimeout sets the request timeout when no HTTP client is supplied.
func WithTimeout(d time.Duration) Option { return func(o *Options) { o.Timeout = d } }

// Host returns the host this client talks to.
func (c *Client) Host() string { return c.host }

// --- wire types -------------------------------------------------------------

type qcTokenResponse struct {
	Result  string `json:"result"`
	Success bool   `json:"success"`
	Status  string `json:"status"`
	ErrCode string `json:"errorCode"`
	ErrMsg  string `json:"errorMsg"`
}

type pollResponse struct {
	// Result is either the boolean `true` (still waiting) or the login object
	// (scan completed). MEASURED for both shapes.
	Result  json.RawMessage `json:"result"`
	Success bool            `json:"success"`
	Status  string          `json:"status"`
	ErrCode string          `json:"errorCode"`
	ErrMsg  string          `json:"errorMsg"`
}

type apiEnvelope struct {
	Result  json.RawMessage `json:"result"`
	Success bool            `json:"success"`
	Status  string          `json:"status"`
	ErrCode string          `json:"errorCode"`
	ErrMsg  string          `json:"errorMsg"`
}

// --- QR handshake -----------------------------------------------------------

// BeginLogin requests a fresh QR token and renders it as a PNG. It is
// equivalent to NewClient(...).BeginLogin(ctx).
func BeginLogin(ctx context.Context, opts ...Option) (token string, qrPNG []byte, err error) {
	return NewClient(opts...).BeginLogin(ctx)
}

// BeginLogin requests a fresh QR login token from /api/login/security/QCtoken
// and renders the login QR as a PNG (512x512, magic bytes 0x89 'P' 'N' 'G').
//
// The returned token is needed by PollLogin; the PNG is what the HTTP layer
// shows to the user.
func (c *Client) BeginLogin(ctx context.Context) (string, []byte, error) {
	login, err := c.BeginLoginSession(ctx)
	if err != nil {
		return "", nil, err
	}
	png, err := RenderQRPNG(login.Payload, QRImageSize)
	if err != nil {
		return "", nil, err
	}
	return login.Token, png, nil
}

// BeginLoginSession is BeginLogin without the image rendering: it returns the
// handshake state (token, payload, expiry). Use it when the caller renders its
// own QR or wants the token's lifetime.
func (c *Client) BeginLoginSession(ctx context.Context) (*Login, error) {
	body, status, err := c.post(ctx, pathQCtoken, nil)
	if err != nil {
		return nil, err
	}
	var r qcTokenResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("tuyaqr: QCtoken: unparseable response (HTTP %d)", status)
	}
	if !r.Success || r.Result == "" {
		return nil, &APIError{StatusCode: status, ErrorCode: r.ErrCode, ErrorMsg: r.ErrMsg}
	}
	now := time.Now()
	return &Login{
		Token:     r.Result,
		Payload:   QRBindingPrefix + r.Result,
		Host:      c.host,
		IssuedAt:  now,
		ExpiresAt: now.Add(TokenTTL - tokenSafetyMargin),
	}, nil
}

// PollLogin asks the cloud once whether the token has been scanned. It is
// equivalent to NewClient(...).PollLogin(ctx, login).
func PollLogin(ctx context.Context, login *Login, opts ...Option) (*Session, bool, error) {
	return NewClient(opts...).PollLogin(ctx, login)
}

// PollLogin performs ONE poll of /api/login/poll for the given handshake.
//
// Returns:
//   - (nil, false, nil)                       scan not performed yet;
//   - (session, true, nil)                    scan completed, cookies captured;
//   - (nil, false, *QRExpiredError)           token expired  -> errors.Is(err, ErrQRExpired)
//   - (nil, false, *QRScannedError)           token used elsewhere -> ErrQRScanned
//   - (nil, false, err)                       transport/other API failure.
//
// The caller drives the loop (typically every 1-2s) so it can render a
// countdown and stop when the token expires.
func (c *Client) PollLogin(ctx context.Context, login *Login) (*Session, bool, error) {
	if login == nil || login.Token == "" {
		return nil, false, errors.New("tuyaqr: nil or empty login")
	}
	// Local pre-check: never waste a poll on a token we know is past its life.
	if login.Expired() {
		return nil, false, &QRExpiredError{ErrorCode: "USER_QR_LOGIN_TOKEN_EXPIRE", ErrorMsg: "local TTL elapsed"}
	}

	payload, err := json.Marshal(map[string]string{"token": login.Token})
	if err != nil {
		return nil, false, err
	}

	// A dedicated jar per poll: the cloud sets session cookies ON THE POLL that
	// completes the scan, and those cookies ARE the credential. They are
	// captured immediately and never reused implicitly.
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, false, err
	}
	hc := c.httpWithJar(jar)

	body, status, setCookies, err := c.postWithHeaders(ctx, hc, pathPoll, payload)
	if err != nil {
		return nil, false, err
	}
	var r pollResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, false, fmt.Errorf("tuyaqr: poll: unparseable response (HTTP %d)", status)
	}

	if !r.Success {
		switch strings.ToUpper(r.ErrCode) {
		case "USER_QR_LOGIN_TOKEN_EXPIRE", "USER_QR_LOGIN_TOKEN_INVALID":
			return nil, false, &QRExpiredError{ErrorCode: r.ErrCode, ErrorMsg: r.ErrMsg}
		case "USER_QR_LOGIN_TOKEN_SCANED":
			return nil, false, &QRScannedError{ErrorCode: r.ErrCode, ErrorMsg: r.ErrMsg}
		default:
			if r.ErrCode == "" && status == http.StatusOK {
				// success=false with no code: treat as still waiting.
				return nil, false, nil
			}
			return nil, false, &APIError{StatusCode: status, ErrorCode: r.ErrCode, ErrorMsg: r.ErrMsg}
		}
	}

	// Success: either `result:true` (waiting) or a login object (done).
	// The presence of a `uid` field inside result is the success signal. MEASURED.
	var probe struct {
		UID string `json:"uid"`
	}
	if err := json.Unmarshal(r.Result, &probe); err == nil && probe.UID != "" {
		var lr LoginResult
		if err := json.Unmarshal(r.Result, &lr); err != nil {
			return nil, false, fmt.Errorf("tuyaqr: poll: cannot decode login result: %w", err)
		}
		sess, err := c.sessionFrom(lr, jar, setCookies)
		if err != nil {
			return nil, false, err
		}
		// The poll's own Set-Cookie is a SESSION cookie on the real cloud: it
		// carries no Expires, so nothing truthful can be persisted from it.
		// One authenticated call with the freshly captured credentials fixes
		// that: MEASURED, the cloud re-emits `fast-sid` WITH the real expiry
		// (~2.5 days out) on every authenticated response. Whatever the cloud
		// reports is stored verbatim; when it reports nothing, the stored
		// expiry stays zero and the API keeps saying "unknown" rather than
		// inventing a deadline.
		if _, _, probeSet, probeErr := c.postWithHeaders(ctx, hc, pathHomeList, nil); probeErr == nil {
			sess.applyReportedExpiry(probeSet, time.Now())
		}
		return sess, true, nil
	}
	return nil, false, nil
}

// applyReportedExpiry copies server-reported expiries onto the cookies of s,
// matching by name. It only ever moves a stored expiry from zero to a real
// future value: a response that declares no expiry (the common case for the
// session cookies) leaves the stored value untouched, and a value in the past
// is never persisted. Returns the number of cookies that gained an expiry.
func (s *Session) applyReportedExpiry(setCookies []string, now time.Time) int {
	if s == nil || len(setCookies) == 0 {
		return 0
	}
	reported := capturedCookies(setCookies, now)
	if len(reported) == 0 {
		return 0
	}
	byName := make(map[string]time.Time, len(reported))
	for _, c := range reported {
		if c != nil && !c.Expires.IsZero() {
			byName[c.Name] = c.Expires
		}
	}
	applied := 0
	for _, stored := range s.SessionData.Cookies {
		if stored == nil {
			continue
		}
		expiry, ok := byName[stored.Name]
		if !ok {
			continue
		}
		if stored.Expires.Equal(expiry) {
			continue
		}
		stored.Expires = expiry
		applied++
	}
	return applied
}

// capturedCookies converts the Set-Cookie headers of a response into stored
// cookies, keeping the server-reported Expires.
//
// This is how a REAL cookie expiry enters the session file. The response's
// cookie jar cannot be used for this: on a host-only cookie (no Domain
// attribute, which is what the Tuya cloud sends) Go's cookiejar stores an empty
// Domain, and http.Cookie.String() then renders the cookie as "Domain=", which
// net/http parses back as a DOMAIN=NULL COOKIE with a DEFAULT PATH. Both are
// then dropped by the jar, so the capture silently loses the credential.
//
// Reading the headers directly sidesteps that entirely: the Expires the cloud
// actually sent is preserved verbatim.
//
// A past expiry is DROPPED rather than stored. Go's http.ParseCookie turns a
// Set-Cookie with no Max-Age/Expires into "Expires=<year 1>; Max-Age=0", i.e.
// the session cookie the QR login actually sets arrives as an expiry in the
// year 1. Persisting that would make the API report a deadline in the past for
// a session that works, which is exactly the kind of invented countdown this
// milestone exists to prevent. Zero therefore means "the cloud declared none",
// and the caller must report expiry as unknown.
func capturedCookies(setCookies []string, now time.Time) []*Cookie {
	out := make([]*Cookie, 0, len(setCookies))
	for _, raw := range setCookies {
		parsed, err := http.ParseSetCookie(raw)
		if err != nil || parsed == nil || parsed.Name == "" {
			continue
		}
		c := &Cookie{
			Name:     parsed.Name,
			Value:    parsed.Value,
			Domain:   parsed.Domain,
			Path:     parsed.Path,
			Secure:   parsed.Secure,
			HttpOnly: parsed.HttpOnly,
		}
		if !parsed.Expires.IsZero() && parsed.Expires.After(now) {
			c.Expires = parsed.Expires
		}
		out = append(out, c)
	}
	return out
}

// sessionFrom assembles a Session from a completed login, preferring the
// Set-Cookie headers of the completing poll (which carry the server's real
// expiry) and falling back to the jar when no headers were observed.
func (c *Client) sessionFrom(lr LoginResult, jar http.CookieJar, setCookies []string) (*Session, error) {
	origin := c.origin()
	now := time.Now()
	var cookies []*Cookie
	if captured := capturedCookies(setCookies, now); len(captured) > 0 {
		cookies = captured
	} else {
		for _, ck := range jar.Cookies(origin) {
			cookies = append(cookies, &Cookie{
				Name: ck.Name, Value: ck.Value, Domain: ck.Domain, Path: ck.Path,
				Expires: ck.Expires, Secure: ck.Secure, HttpOnly: ck.HttpOnly,
			})
		}
	}
	if len(cookies) == 0 {
		// The login succeeded but no cookies were captured: discovery would
		// fail with USER_SESSION_LOSS. Fail loudly rather than persist junk.
		return nil, errors.New("tuyaqr: login succeeded but no session cookies were set by the cloud")
	}
	s := &Session{
		Region:      DefaultRegion,
		Email:       lr.Email,
		UserKey:     DefaultRegion + "_" + strings.NewReplacer("@", "_at_", ".", "_").Replace(lr.Email),
		LastRefresh: now,
		SessionData: UserSession{
			LoginResult:   &lr,
			Cookies:       cookies,
			LastValidated: now,
			ServerHost:    c.host,
			Region:        DefaultRegion,
			UserEmail:     lr.Email,
		},
	}
	if fast, sid, _ := s.AuthCookieStatus(); !fast || !sid {
		return nil, fmt.Errorf("tuyaqr: login captured %d cookies (%s) but fast-sid/s-sid are missing; discovery would fail",
			len(cookies), strings.Join(s.CookieNames(), ","))
	}
	return s, nil
}

// --- authenticated calls ----------------------------------------------------

// NewClientFromSession builds an authenticated client from a stored session.
// The session's cookies are loaded into a private jar; the session file is not
// touched.
func NewClientFromSession(s *Session, opts ...Option) (*Client, error) {
	o := Options{}
	for _, fn := range opts {
		fn(&o)
	}
	if o.Host == "" {
		o.Host = s.ServerHost()
	}
	jar, err := s.CookieJar()
	if err != nil {
		return nil, err
	}
	if o.HTTPClient != nil {
		clone := *o.HTTPClient
		clone.Jar = jar
		o.HTTPClient = &clone
	} else {
		o.HTTPClient = &http.Client{Timeout: requestTimeout(o.Timeout), Jar: jar}
	}
	return o.client(), nil
}

// NewClientForSessionFile loads a session file and returns an authenticated
// client plus the parsed session. Convenience for the HTTP layer.
func NewClientForSessionFile(path string, opts ...Option) (*Client, *Session, error) {
	s, err := LoadSession(path)
	if err != nil {
		return nil, nil, err
	}
	c, err := NewClientFromSession(s, opts...)
	if err != nil {
		return nil, nil, err
	}
	return c, s, nil
}

// RefreshExpiry performs ONE authenticated probe and folds any expiry the cloud
// reports back into the session, updating LastValidated when the probe says the
// session is still live. It returns ErrSessionExpired (wrapped) when the cloud
// rejects the cookies, so the caller can both mark the session dead and stop the
// streams it is feeding.
//
// This is the only way a stored expiry can legitimately appear for a session
// that was captured before M6: the cloud re-issues fast-sid WITH its real expiry
// on an authenticated call. Nothing here invents a value — if the cloud reports
// none, the stored expiry stays zero and the API keeps saying "unknown".
func (c *Client) RefreshExpiry(ctx context.Context, s *Session) error {
	_, _, setCookies, err := c.postWithHeaders(ctx, c.http, pathHomeList, nil)
	if err != nil {
		return err
	}
	if s != nil {
		s.applyReportedExpiry(setCookies, time.Now())
		s.SessionData.LastValidated = time.Now()
	}
	return nil
}

// Validate checks the stored session against the cloud with a cheap
// authenticated call. It returns ErrSessionExpired (wrapped) when the cookies
// are rejected, so the HTTP layer can prompt for a new QR scan.
func (c *Client) Validate(ctx context.Context) error {
	_, _, err := c.post(ctx, pathHomeList, []byte{})
	return err
}

// Cameras enumerates the account's cameras across every home and room, plus
// cameras shared with the account, and fetches each one's WebRTC/streaming
// configuration from /api/jarvis/config.
//
// A camera is any device whose category is "sp" or "dghsxj" (the same filter
// the working reference implementations use).
func (c *Client) Cameras(ctx context.Context) ([]Device, error) {
	var out []Device
	seen := map[string]bool{}

	add := func(cfg DeviceConfig, d Device) {
		if d.DeviceID == "" || seen[d.DeviceID] {
			return
		}
		if !IsCamera(d.Category) {
			return
		}
		seen[d.DeviceID] = true
		d.Config = &cfg
		out = append(out, d)
	}

	homes, err := c.homes(ctx)
	if err != nil {
		return nil, err
	}
	type target struct {
		homeID string
		device Device
	}
	var targets []target
	for _, h := range homes {
		devices, err := c.roomDevices(ctx, h.HomeID())
		if err != nil {
			continue // a home we cannot read must not sink the whole listing
		}
		for _, d := range devices {
			if IsCamera(d.Category) {
				targets = append(targets, target{homeID: h.HomeID(), device: d})
			}
		}
	}
	for _, sh := range c.sharedDevices(ctx) {
		if IsCamera(sh.Category) {
			targets = append(targets, target{device: sh})
		}
	}

	for _, t := range targets {
		cfg, err := c.DeviceConfig(ctx, t.device.DeviceID)
		if err != nil {
			if errors.Is(err, ErrSessionExpired) {
				return nil, err
			}
			// A camera without a config is still a discovered camera.
			add(DeviceConfig{}, t.device)
			continue
		}
		add(cfg, t.device)
	}
	return out, nil
}

// Devices returns every device on the account (cameras and everything else),
// without fetching per-device configs. Useful for diagnostics.
func (c *Client) Devices(ctx context.Context) ([]Device, error) {
	var out []Device
	seen := map[string]bool{}
	push := func(d Device) {
		if d.DeviceID == "" || seen[d.DeviceID] {
			return
		}
		seen[d.DeviceID] = true
		out = append(out, d)
	}
	homes, err := c.homes(ctx)
	if err != nil {
		return nil, err
	}
	for _, h := range homes {
		devices, err := c.roomDevices(ctx, h.HomeID())
		if err != nil {
			continue
		}
		for _, d := range devices {
			push(d)
		}
	}
	for _, d := range c.sharedDevices(ctx) {
		push(d)
	}
	return out, nil
}

// DeviceConfig fetches auth/localKey/p2pConfig/skill for one device from
// /api/jarvis/config.
func (c *Client) DeviceConfig(ctx context.Context, deviceID string) (DeviceConfig, error) {
	payload, err := json.Marshal(DeviceConfigRequest{
		DevID:         deviceID,
		ClientTraceID: fmt.Sprintf("%x", rand.Int63()),
	})
	if err != nil {
		return DeviceConfig{}, err
	}
	var out DeviceConfig
	if err := c.postInto(ctx, pathJarvisConfig, payload, &out); err != nil {
		return DeviceConfig{}, err
	}
	return out, nil
}

// MQTTCredentials fetches the account's MQTT broker credentials.
func (c *Client) MQTTCredentials(ctx context.Context) (*MQTTCredentials, error) {
	var out MQTTCredentials
	if err := c.postInto(ctx, pathJarvisMQTT, []byte("{}"), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// origin returns the URL the stored cookies belong to.
func (c *Client) origin() *url.URL {
	u, err := url.Parse(c.base)
	if err != nil {
		return &url.URL{Scheme: "https", Host: c.host, Path: "/"}
	}
	u.Path = "/"
	return u
}

// isLoopback reports whether host is a local test server (used only to allow
// the httptest redirect guard to behave like the real one).
func isLoopback(host string) bool {
	h := host
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i]
	}
	return h == "127.0.0.1" || h == "localhost" || h == "::1" || h == "[::1]"
}

// --- internal plumbing ------------------------------------------------------

func requestTimeout(d time.Duration) time.Duration {
	if d == 0 {
		return 15 * time.Second
	}
	return d
}

// httpWithJar clones the client with a different cookie jar.
func (c *Client) httpWithJar(jar http.CookieJar) *http.Client {
	if c.http == nil {
		return &http.Client{Timeout: 15 * time.Second, Jar: jar}
	}
	clone := *c.http
	clone.Jar = jar
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != c.host || req.URL.Scheme != "https" {
			if !isLoopback(req.URL.Host) {
				return errors.New("tuyaqr: refused cross-origin redirect (session credentials must not travel)")
			}
		}
		if len(via) >= 10 {
			return errors.New("tuyaqr: too many redirects")
		}
		return nil
	}
	return &clone
}

func (c *Client) post(ctx context.Context, path string, body []byte) ([]byte, int, error) {
	raw, status, _, err := c.postWithHeaders(ctx, c.http, path, body)
	return raw, status, err
}

// postWith is postWithHeaders without the response headers.
func (c *Client) postWith(ctx context.Context, hc *http.Client, path string, body []byte) ([]byte, int, error) {
	raw, status, _, err := c.postWithHeaders(ctx, hc, path, body)
	return raw, status, err
}

// postWithHeaders performs the request and also returns the raw Set-Cookie
// headers. The QR-login poll needs them: they are the only place the cloud's
// real cookie Expires is visible, and the cookie jar cannot carry it (a
// host-only Set-Cookie round-tripped through Cookie.String() is re-parsed as a
// domain=NULL cookie with a default path and then rejected by the jar).
func (c *Client) postWithHeaders(ctx context.Context, hc *http.Client, path string, body []byte) ([]byte, int, []string, error) {
	if body == nil {
		body = []byte{}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, nil, err
	}
	c.applyHeaders(req, path)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, resp.StatusCode, nil, err
	}
	setCookies := resp.Header.Values("Set-Cookie")
	if resp.StatusCode == http.StatusUnauthorized {
		var e apiEnvelope
		_ = json.Unmarshal(raw, &e)
		return raw, resp.StatusCode, setCookies, &SessionExpiredError{
			StatusCode: resp.StatusCode, ErrorCode: firstNonEmpty(e.ErrCode, "USER_SESSION_LOSS"), ErrorMsg: e.ErrMsg,
		}
	}
	if resp.StatusCode != http.StatusOK {
		var e apiEnvelope
		_ = json.Unmarshal(raw, &e)
		return raw, resp.StatusCode, setCookies, &APIError{StatusCode: resp.StatusCode, ErrorCode: e.ErrCode, ErrorMsg: firstNonEmpty(e.ErrMsg, strings.TrimSpace(string(raw)))}
	}
	return raw, resp.StatusCode, setCookies, nil
}

// postInto posts and decodes the envelope's result into out, translating cloud
// refusals into typed errors.
func (c *Client) postInto(ctx context.Context, path string, body []byte, out any) error {
	raw, status, err := c.post(ctx, path, body)
	if err != nil {
		return err
	}
	var env apiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("tuyaqr: %s: unparseable response (HTTP %d)", path, status)
	}
	if !env.Success {
		code := strings.ToUpper(env.ErrCode)
		if code == "USER_SESSION_LOSS" || code == "USER_SESSION_INVALID" || env.Status == "not_login" {
			return &SessionExpiredError{StatusCode: status, ErrorCode: env.ErrCode, ErrorMsg: env.ErrMsg}
		}
		return &APIError{StatusCode: status, ErrorCode: env.ErrCode, ErrorMsg: env.ErrMsg}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(env.Result, out); err != nil {
		return fmt.Errorf("tuyaqr: %s: cannot decode result: %w", path, err)
	}
	return nil
}

func (c *Client) applyHeaders(req *http.Request, path string) {
	origin := c.base
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", origin)
	referer := origin + "/login"
	if strings.HasPrefix(path, "/api/jarvis") || strings.Contains(path, "playback") {
		referer = origin + "/playback"
	}
	req.Header.Set("Referer", referer)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
}

func (c *Client) homes(ctx context.Context) ([]Home, error) {
	var out []Home
	if err := c.postInto(ctx, pathHomeList, []byte{}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) roomDevices(ctx context.Context, homeID string) ([]Device, error) {
	payload, err := json.Marshal(RoomListRequest{HomeID: homeID})
	if err != nil {
		return nil, err
	}
	var rooms []Room
	if err := c.postInto(ctx, pathRoomList, payload, &rooms); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []Device
	for _, r := range rooms {
		for _, d := range r.DeviceList {
			if d.DeviceID == "" || seen[d.DeviceID] {
				continue
			}
			seen[d.DeviceID] = true
			out = append(out, d)
		}
	}
	return out, nil
}

func (c *Client) sharedDevices(ctx context.Context) []Device {
	var res struct {
		SecurityWebCShareInfoList []struct {
			DeviceInfoList []Device `json:"deviceInfoList"`
		} `json:"securityWebCShareInfoList"`
	}
	if err := c.postInto(ctx, pathSharedList, []byte{}, &res); err != nil {
		return nil
	}
	var out []Device
	for _, sh := range res.SecurityWebCShareInfoList {
		out = append(out, sh.DeviceInfoList...)
	}
	return out
}

// RenderQRPNG encodes payload as a QR PNG of the given size in pixels.
// The output starts with the PNG magic bytes 0x89 'P' 'N' 'G'.
func RenderQRPNG(payload string, size int) ([]byte, error) {
	if payload == "" {
		return nil, errors.New("tuyaqr: empty QR payload")
	}
	if size <= 0 {
		size = QRImageSize
	}
	return qrcode.Encode(payload, qrcode.Medium, size)
}

// RenderQRText returns a small ASCII QR for terminal diagnostics. It is meant
// for developer tooling only; do not put its output in logs shipped anywhere,
// because it encodes the login token.
func RenderQRText(payload string) (string, error) {
	q, err := qrcode.New(payload, qrcode.Low)
	if err != nil {
		return "", err
	}
	return q.ToString(false), nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
