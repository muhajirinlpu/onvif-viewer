package tuyaqr

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// --- the probe's rejection classification ------------------------------------
//
// RefreshExpiry is the ONE authenticated call that decides whether a Tuya stream
// is stopped, so the TYPING it produces is load-bearing. It is typed through
// *SessionExpiredError, whose Is method makes errors.Is(err, ErrSessionExpired)
// true — and SessionExpired(err) in internal/provider is the predicate the
// decision point must use.
//
// The bug this file guards had two halves:
//
//  1. Everything that was not an HTTP 401 came back UNTYPED — a transport error,
//     a context deadline, a body-read error and an HTTP 5xx were all
//     indistinguishable from "the cloud rejected these cookies". The provider
//     then treated "not verified" as "dead" and stood every Tuya stream down.
//
//  2. A 200 carrying the cloud's own rejection envelope (the MEASURED
//     `{"success":false,"errorCode":"USER_SESSION_LOSS","status":"not_login"}`
//     shape, which postInto has always recognised) was NOT typed here, so the
//     SAME server verdict was typed one way through postInto and another way
//     through the probe.
//
// These tests pin both: the definitive case must be definitively typed, and the
// inconclusive cases must be provably NOT typed as expired.

// probeCloud answers /api/new/common/homeList with a scripted response.
type probeCloud struct {
	status  int
	body    string
	rawEOF  bool
	delay   time.Duration
	handler func(w http.ResponseWriter, r *http.Request)
	calls   int
}

func (p *probeCloud) serve(t *testing.T) (*Client, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.calls++
		if p.handler != nil {
			p.handler(w, r)
			return
		}
		if p.delay > 0 {
			time.Sleep(p.delay)
		}
		if p.rawEOF {
			// Hijack and close without a response: the client sees an EOF on
			// the body rather than an HTTP status.
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, err := hj.Hijack()
				if err == nil {
					_ = conn.Close()
					return
				}
			}
		}
		if p.status != 0 {
			w.WriteHeader(p.status)
		}
		_, _ = w.Write([]byte(p.body))
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return newFakeAuthedClient(t, srv.URL, u.Host), srv.Close
}

// probeSession is a minimal session with the auth pair, for RefreshExpiry.
func probeSession(host string) *Session {
	return &Session{
		Region: "us-west", Email: "user@example.test", UserKey: "us-west_user_at_example_test",
		LastRefresh: time.Now(),
		SessionData: UserSession{
			LoginResult: &LoginResult{UID: "uid", Email: "user@example.test"},
			Cookies: []*Cookie{
				{Name: "fast-sid", Value: strings.Repeat("a", 32), Path: "/"},
				{Name: "s-sid", Value: strings.Repeat("b", 82), Path: "/"},
			},
			LastValidated: time.Now(), ServerHost: host, Region: "us-west", UserEmail: "user@example.test",
		},
	}
}

// TestRefreshExpiryTypesTheCloudsOwnRejectionInEveryShape it can arrive in. The
// three markers are the ones the cloud actually uses, and the 401 is the one the
// provider's cached latch has always keyed on.
func TestRefreshExpiryTypesTheCloudsOwnRejectionInEveryShape(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantCode string
	}{
		{
			name:   "401 with USER_SESSION_LOSS",
			status: http.StatusUnauthorized,
			body:   `{"success":false,"errorCode":"USER_SESSION_LOSS","errorMsg":"Not login"}`,
		},
		{
			name:   "401 with no envelope at all",
			status: http.StatusUnauthorized,
			body:   ``,
		},
		{
			name:     "200 with USER_SESSION_LOSS",
			status:   http.StatusOK,
			body:     `{"success":false,"errorCode":"USER_SESSION_LOSS","errorMsg":"Not login"}`,
			wantCode: "USER_SESSION_LOSS",
		},
		{
			name:     "200 with USER_SESSION_INVALID",
			status:   http.StatusOK,
			body:     `{"success":false,"errorCode":"USER_SESSION_INVALID"}`,
			wantCode: "USER_SESSION_INVALID",
		},
		{
			name:   "200 with status not_login and no errorCode",
			status: http.StatusOK,
			body:   `{"success":false,"status":"not_login"}`,
		},
		{
			name:   "200 with lowercase errorCode",
			status: http.StatusOK,
			body:   `{"success":false,"errorCode":"user_session_loss"}`,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cloud := &probeCloud{status: tc.status, body: tc.body}
			c, _ := cloud.serve(t)
			s := probeSession(strings.TrimPrefix(strings.SplitN(c.base, "//", 2)[1], ""))

			err := c.RefreshExpiry(context.Background(), s)
			if err == nil {
				t.Fatal("err = nil, want the cloud's rejection to be typed")
			}
			if !errors.Is(err, ErrSessionExpired) {
				t.Fatalf("err = %v, want errors.Is(err, ErrSessionExpired)", err)
			}
			var typed *SessionExpiredError
			if !errors.As(err, &typed) {
				t.Fatalf("err = %v, want *SessionExpiredError", err)
			}
			if tc.wantCode != "" && typed.ErrorCode != tc.wantCode {
				t.Errorf("errorCode = %q, want %q", typed.ErrorCode, tc.wantCode)
			}
			// A rejected probe must never have written an expiry.
			if _, _, ok := s.EarliestCookieExpiry(); ok {
				t.Error("a rejected probe produced a cookie expiry")
			}
		})
	}
}

// TestRefreshExpiryLeavesInconclusiveFailuresUNTYPED is the other half, and the
// half that caused the outage: NOTHING except a server-side rejection may look
// like an expired session.
func TestRefreshExpiryLeavesInconclusiveFailuresUNTYPED(t *testing.T) {
	t.Run("HTTP 500", func(t *testing.T) {
		cloud := &probeCloud{status: http.StatusInternalServerError, body: `{"success":false,"errorCode":"SERVER_ERROR"}`}
		c, _ := cloud.serve(t)
		assertInconclusive(t, c.RefreshExpiry(context.Background(), probeSession("")), "HTTP 500")
	})
	t.Run("HTTP 502", func(t *testing.T) {
		cloud := &probeCloud{status: http.StatusBadGateway, body: `bad gateway`}
		c, _ := cloud.serve(t)
		assertInconclusive(t, c.RefreshExpiry(context.Background(), probeSession("")), "HTTP 502")
	})
	t.Run("HTTP 503", func(t *testing.T) {
		cloud := &probeCloud{status: http.StatusServiceUnavailable}
		c, _ := cloud.serve(t)
		assertInconclusive(t, c.RefreshExpiry(context.Background(), probeSession("")), "HTTP 503")
	})
	t.Run("HTTP 504", func(t *testing.T) {
		cloud := &probeCloud{status: http.StatusGatewayTimeout}
		c, _ := cloud.serve(t)
		assertInconclusive(t, c.RefreshExpiry(context.Background(), probeSession("")), "HTTP 504")
	})
	t.Run("HTTP 200 with an unparseable body", func(t *testing.T) {
		// RESIDUAL GAP, PINNED RATHER THAN CLAIMED FIXED. A 200 whose body is
		// not the JSON envelope is currently reported as a SUCCESSFUL probe,
		// because RefreshExpiry only inspects the answer for a rejection and
		// otherwise trusts "it was an authenticated call that came back".
		//
		// That is the same CLASS of mistake as the bug being fixed — reading an
		// answer that decided nothing as if it decided something — but in the
		// permissive direction, and it does NOT cause a stand-down, so it is out
		// of scope for this change. It is asserted here so the behaviour cannot
		// drift silently and so the next person sees what is actually true. It
		// is reported as an unproven/residual item alongside this change.
		cloud := &probeCloud{status: http.StatusOK, body: `<html>maintenance</html>`}
		c, _ := cloud.serve(t)
		err := c.RefreshExpiry(context.Background(), probeSession(""))
		if err != nil {
			t.Fatalf("err = %v: this change did NOT touch the success path, so an unparseable 200 is still treated as a live probe; "+
				"if this fails, the success path was changed and the residual gap is now closed (delete this comment and assert it as inconclusive)", err)
		}
		if errors.Is(err, ErrSessionExpired) {
			t.Fatal("an unparseable 200 was typed as an expired session, which would stop every stream")
		}
	})
	t.Run("HTTP 200 with success:true and no result", func(t *testing.T) {
		cloud := &probeCloud{status: http.StatusOK, body: `{"success":true}`}
		c, _ := cloud.serve(t)
		if err := c.RefreshExpiry(context.Background(), probeSession("")); err != nil {
			t.Fatalf("err = %v, want nil for a successful probe", err)
		}
	})
	t.Run("HTTP 200 with success:false but an UNRELATED errorCode", func(t *testing.T) {
		cloud := &probeCloud{status: http.StatusOK, body: `{"success":false,"errorCode":"SOME_OTHER_ERROR","errorMsg":"nope"}`}
		c, _ := cloud.serve(t)
		// An unrelated business error is not the session being rejected, and it
		// is also not something the probe can conclude from: it must NOT stop a
		// stream.
		if err := c.RefreshExpiry(context.Background(), probeSession("")); errors.Is(err, ErrSessionExpired) {
			t.Fatalf("err = %v was typed as an expired session; only a session-lifecycle code may be", err)
		}
	})
	t.Run("connection reset", func(t *testing.T) {
		cloud := &probeCloud{rawEOF: true}
		c, _ := cloud.serve(t)
		assertInconclusive(t, c.RefreshExpiry(context.Background(), probeSession("")), "connection reset")
	})
	t.Run("context deadline", func(t *testing.T) {
		cloud := &probeCloud{status: http.StatusOK, body: `{"success":true}`, delay: 2 * time.Second}
		c, _ := cloud.serve(t)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		err := c.RefreshExpiry(ctx, probeSession(""))
		if err == nil {
			t.Fatal("err = nil although the deadline elapsed")
		}
		assertInconclusive(t, err, "context deadline")
	})
	t.Run("DNS failure", func(t *testing.T) {
		// A host that cannot resolve. .invalid is reserved by RFC 2606, so this
		// cannot accidentally reach a real server.
		s := newFakeAuthedClient(t, "https://does-not-exist.invalid", "does-not-exist.invalid")
		err := s.RefreshExpiry(context.Background(), probeSession("does-not-exist.invalid"))
		if err == nil {
			t.Fatal("err = nil although the host cannot resolve")
		}
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) {
			t.Logf("err = %v (not a *net.DNSError on this platform, which is fine: the point is that it is NOT typed as expired)", err)
		}
		assertInconclusive(t, err, "DNS failure")
	})
}

// assertInconclusive is the shared assertion: the error must be non-nil, must NOT
// satisfy errors.Is(err, ErrSessionExpired), and must NOT be a
// *SessionExpiredError. Anything else and the provider cannot tell a network blip
// from a cloud rejection — which is the bug.
func assertInconclusive(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: err = nil, want an error", what)
	}
	if errors.Is(err, ErrSessionExpired) {
		t.Fatalf("%s: err = %v was typed as an EXPIRED session; it is inconclusive and must not be", what, err)
	}
	var typed *SessionExpiredError
	if errors.As(err, &typed) {
		t.Fatalf("%s: err = %v is a *SessionExpiredError; it is inconclusive and must not be", what, err)
	}
	if errors.Is(err, ErrNoSession) {
		t.Fatalf("%s: err = %v was typed as ErrNoSession; a network failure is not a missing credential", what, err)
	}
}

// TestSessionRejectionEnvelopeIsConservative pins the 200-envelope classifier
// directly, including the cases it must REFUSE.
func TestSessionRejectionEnvelopeIsConservative(t *testing.T) {
	rejections := []string{
		`{"success":false,"errorCode":"USER_SESSION_LOSS"}`,
		`{"success":false,"errorCode":"USER_SESSION_INVALID"}`,
		`{"success":false,"status":"not_login"}`,
		`{"success":false,"status":"NOT_LOGIN"}`,
		`{"success":false,"errorCode":"user_session_loss"}`,
		`{"success":false,"errorCode":" USER_SESSION_LOSS "}`,
	}
	for _, body := range rejections {
		if _, ok := sessionRejectionEnvelope([]byte(body)); !ok {
			t.Errorf("sessionRejectionEnvelope(%s) = false, want true", body)
		}
	}
	notRejections := []string{
		`{"success":true,"status":"ok"}`,
		`{"success":true,"errorCode":"USER_SESSION_LOSS"}`, // success:true wins
		`{"success":false,"errorCode":"SOME_ERROR"}`,
		`{"success":false}`,
		`{"success":false,"status":"ok"}`,
		`<html>maintenance</html>`,
		``,
		`null`,
	}
	for _, body := range notRejections {
		if _, ok := sessionRejectionEnvelope([]byte(body)); ok {
			t.Errorf("sessionRejectionEnvelope(%s) = true, want false: an inconclusive body must never look like a rejection", body)
		}
	}
}

// TestRefreshExpiryStillSucceedsOnAHealthyProbe keeps the happy path pinned: the
// new classification must not have made a working probe look like a failure.
func TestRefreshExpiryStillSucceedsOnAHealthyProbe(t *testing.T) {
	cloud := &probeCloud{
		status: http.StatusOK,
		body:   `{"result":[],"success":true,"status":"ok"}`,
		handler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Set-Cookie", "fast-sid=v; Path=/; Expires="+
				time.Now().Add(48*time.Hour).UTC().Format(http.TimeFormat)+"; Secure; HttpOnly")
			w.Header().Add("Set-Cookie", "s-sid=v; Path=/; Secure; HttpOnly")
			_, _ = w.Write([]byte(`{"result":[],"success":true,"status":"ok"}`))
		},
	}
	c, _ := cloud.serve(t)
	s := probeSession("")
	if err := c.RefreshExpiry(context.Background(), s); err != nil {
		t.Fatalf("RefreshExpiry: %v", err)
	}
	if _, name, ok := s.EarliestCookieExpiry(); !ok || name != "fast-sid" {
		t.Fatalf("the live probe did not fold the reported expiry back in: (%q, %t)", name, ok)
	}
	if !s.SessionData.LastValidated.After(time.Now().Add(-time.Minute)) {
		t.Error("a live probe did not update lastValidated")
	}
}
