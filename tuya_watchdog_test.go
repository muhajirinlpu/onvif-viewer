package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/provider"
	"dengan.dev/camera-streamer/internal/tuyaqr"
)

// --- the periodic session watchdog's WORDING --------------------------------
//
// The wording is the operator-facing half of the tri-state fix, so it is tested
// rather than trusted. MEASURED on the live install on 2026-09-22: the periodic
// probe failed at 11:30:47 with the SAME cookies the cloud had accepted at
// 11:27:14 and accepted again at 11:33:07, and the log said
//
//	periodic Tuya session check: session invalid ... streams stood down until a new QR scan
//
// — an announcement that the credential was dead and a human was needed, when in
// fact nothing had been proven and the streams should have kept running. That one
// line is how three occurrences turned into 6.9 hours of dead camera.

// watchdogCloud is a scripted stand-in for the Tuya cloud on the watchdog path.
type watchdogCloud struct {
	probeErr error
}

func (c *watchdogCloud) Cameras(context.Context) ([]tuyaqr.Device, error) { return nil, nil }
func (c *watchdogCloud) Validate(context.Context) error                   { return c.probeErr }
func (c *watchdogCloud) RefreshExpiry(context.Context, *tuyaqr.Session) error {
	return c.probeErr
}

// watchdogProvider builds a Tuya provider over an in-memory store holding a
// usable session, with the cloud scripted.
func watchdogProvider(t *testing.T, cloud *watchdogCloud) *provider.Tuya {
	t.Helper()
	store := tuyaqr.NewMemorySessionStore()
	now := time.Now()
	session := &tuyaqr.Session{
		Region: "us-west", Email: "watchdog@example.test", UserKey: "us-west_watchdog",
		LastRefresh: now,
		SessionData: tuyaqr.UserSession{
			LoginResult: &tuyaqr.LoginResult{UID: "az1", Email: "watchdog@example.test"},
			ServerHost:  tuyaqr.DefaultHost,
			Region:      "us-west",
			UserEmail:   "watchdog@example.test",
			Cookies: []*tuyaqr.Cookie{
				{Name: "gTyPlatLang", Value: "en"},
				{Name: "locale", Value: "en"},
				{Name: "fast-sid", Value: strings.Repeat("a", 32)},
				{Name: "s-sid", Value: strings.Repeat("b", 82)},
			},
		},
	}
	if err := store.Save(session); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return provider.NewTuya("",
		provider.WithTuyaStore(store),
		provider.WithTuyaCloudClientForTest(cloud),
	)
}

// watchdogLog builds a logger over a temp database and returns it plus a reader
// for the newest message it holds.
func watchdogLog(t *testing.T) (*logger.Logger, func() string) {
	t.Helper()
	l, err := logger.NewLogger(filepath.Join(t.TempDir(), "watchdog.db"))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	t.Cleanup(l.Close)
	latest := func() string {
		logs, err := l.GetRecentLogs(20)
		if err != nil {
			t.Fatalf("GetRecentLogs: %v", err)
		}
		if len(logs) == 0 {
			return ""
		}
		return logs[0].Message
	}
	return l, latest
}

// TestWatchdogSaysCouldNotCheckRatherThanSessionInvalidForAnInconclusiveProbe is
// the wording contract: the ONLY message that may say "session invalid" is the
// one for a conclusive cloud rejection.
func TestWatchdogSaysCouldNotCheckRatherThanSessionInvalidForAnInconclusiveProbe(t *testing.T) {
	for _, probeErr := range []error{
		context.DeadlineExceeded,
		&net.DNSError{Err: "no such host", Name: tuyaqr.DefaultHost},
		errors.New("read tcp 10.0.0.2:54321->10.0.0.9:443: read: connection reset by peer"),
		&tuyaqr.APIError{StatusCode: 500, ErrorCode: "SERVER_ERROR"},
		&tuyaqr.APIError{StatusCode: 503},
	} {
		probeErr := probeErr
		t.Run(fmt.Sprintf("%T/%v", probeErr, probeErr), func(t *testing.T) {
			cloud := &watchdogCloud{probeErr: probeErr}
			p := watchdogProvider(t, cloud)
			l, latest := watchdogLog(t)

			if cont := tuyaSessionWatchdogOnce(p, l); !cont {
				t.Fatal("the watchdog stopped although the provider is still configured")
			}
			msg := latest()
			if msg == "" {
				t.Fatal("an inconclusive check logged nothing, so an operator cannot tell it apart from a healthy session")
			}
			if strings.Contains(msg, "session invalid") {
				t.Fatalf("message = %q, want NO \"session invalid\": nothing was proven invalid (%v)", msg, probeErr)
			}
			if !strings.Contains(msg, "could not check") {
				t.Errorf("message = %q, want it to say the session could not be checked", msg)
			}
			if !strings.Contains(msg, "no stream was stood down") && !strings.Contains(msg, "streams keep running") {
				t.Errorf("message = %q, want it to say plainly that nothing was stopped", msg)
			}
			if !strings.Contains(msg, "no QR scan") {
				t.Errorf("message = %q, want it to say no QR scan is needed", msg)
			}
		})
	}
}

// TestWatchdogSaysSessionInvalidOnlyForARealCloudRejection is the other side: when
// the cloud really does reject the cookie, the log must say so unambiguously, and
// the wording must not have been softened into mush by the fix above.
func TestWatchdogSaysSessionInvalidOnlyForARealCloudRejection(t *testing.T) {
	cloud := &watchdogCloud{probeErr: &tuyaqr.SessionExpiredError{StatusCode: 401, ErrorCode: "USER_SESSION_LOSS", ErrorMsg: "Not login"}}
	p := watchdogProvider(t, cloud)
	l, latest := watchdogLog(t)

	if cont := tuyaSessionWatchdogOnce(p, l); !cont {
		t.Fatal("the watchdog stopped although the provider is still configured")
	}
	msg := latest()
	if !strings.Contains(msg, "session invalid") {
		t.Fatalf("message = %q, want \"session invalid\" for a real cloud rejection", msg)
	}
	if !strings.Contains(msg, "streams stood down") {
		t.Errorf("message = %q, want it to say the streams were stood down", msg)
	}

	// And the status the same call produced must agree with the log line.
	status, err := p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.ReloginRequired || status.CheckFailed || status.CheckState != "invalid" {
		t.Errorf("status = %+v, want reloginRequired=true checkFailed=false checkState=invalid", status)
	}
}

// TestWatchdogIsSilentForAHealthySession keeps the loop from becoming noise: an
// accepted probe says nothing, exactly as before.
func TestWatchdogIsSilentForAHealthySession(t *testing.T) {
	cloud := &watchdogCloud{}
	p := watchdogProvider(t, cloud)
	l, latest := watchdogLog(t)

	if cont := tuyaSessionWatchdogOnce(p, l); !cont {
		t.Fatal("the watchdog stopped although the provider is still configured")
	}
	if msg := latest(); msg != "" {
		t.Errorf("message = %q, want silence for a session the cloud accepted", msg)
	}
}

// TestWatchdogStopsWhenTuyaIsNoLongerConfigured keeps the existing loop exit
// condition, which the watchdog-once split must not have changed.
func TestWatchdogStopsWhenTuyaIsNoLongerConfigured(t *testing.T) {
	l, _ := watchdogLog(t)
	if cont := tuyaSessionWatchdogOnce(provider.NewTuya(""), l); cont {
		t.Fatal("the watchdog continued although no store is configured")
	}
}

// TestTheSessionJSONCarriesTheTriStateAdditively pins the wire contract the UI
// reads: the three pre-existing honesty axes keep their names and meanings, and
// the tri-state is ADDITIVE.
func TestTheSessionJSONCarriesTheTriStateAdditively(t *testing.T) {
	cloud := &watchdogCloud{probeErr: context.DeadlineExceeded}
	p := watchdogProvider(t, cloud)
	status, err := p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		// The pre-existing axes: unchanged names, unchanged meanings.
		"configured", "filePresent", "cloudVerified", "valid",
		"expiryKnown", "expirySource", "reloginRequired",
		// The additive tri-state.
		"checkFailed", "checkState",
	} {
		if _, ok := wire[key]; !ok {
			t.Errorf("the session JSON is missing %q: %s", key, raw)
		}
	}
	if wire["checkFailed"] != true || wire["checkState"] != "unknown" {
		t.Errorf("wire = %v, want checkFailed=true checkState=unknown", wire)
	}
	if wire["reloginRequired"] != false {
		t.Errorf("reloginRequired = %v, want false: an inconclusive check must not demand a QR scan", wire["reloginRequired"])
	}
	if detail, _ := wire["detail"].(string); strings.Contains(detail, "scan a new QR code") {
		t.Errorf("detail = %q, want no QR demand for an inconclusive check", detail)
	}
}
