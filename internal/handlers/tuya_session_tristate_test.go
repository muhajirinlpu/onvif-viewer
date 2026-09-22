package handlers

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/provider"
	"dengan.dev/camera-streamer/internal/tuyaqr"
)

// --- /api/tuya/session under an INCONCLUSIVE probe ---------------------------
//
// The UI polls this endpoint and enters its re-login flow when the response says
// the session is dead. MEASURED on the live install on 2026-09-22: a probe that
// could not reach a conclusion was reported as a dead session, the UI demanded a
// QR scan, and the cameras stayed down for 6.9 hours until a human obliged.
//
// So the contract this file pins is a STATUS CODE and a FLAG:
//
//   - an inconclusive probe  => HTTP 200, valid unchanged, checkFailed:true,
//     reloginRequired:false, and the UI's re-login flow is NOT entered;
//   - a real cloud rejection => HTTP 200 as well (the shape the UI has always
//     read), reloginRequired:true, so the UI DOES offer the QR scan.
//
// 502 is reserved for a genuine internal failure to produce a status at all.

// scriptedCloud is the handler tests' scriptable stand-in for the Tuya cloud.
type scriptedCloud struct {
	probeErr error
	calls    int
}

func (c *scriptedCloud) Cameras(context.Context) ([]tuyaqr.Device, error) { return nil, nil }
func (c *scriptedCloud) Validate(context.Context) error                   { return c.probeErr }
func (c *scriptedCloud) RefreshExpiry(context.Context, *tuyaqr.Session) error {
	c.calls++
	return c.probeErr
}

// sessionEnvWithCloud wires a handler whose Tuya session lives in a SQLite store
// and whose cloud is scripted, so no network is involved.
//
// The validation cache is shortened through the provider's own exported test
// seam, because the default 30s window would make a poll return the previous
// verdict and the test would be measuring the cache rather than the decision.
func sessionEnvWithCloud(t *testing.T, cloud *scriptedCloud, load *tuyaqr.Session) (*testEnv, *tuyaqr.SQLiteSessionStore) {
	t.Helper()
	env := testHandler(t)
	store, err := tuyaqr.NewSQLiteSessionStore(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteSessionStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	if load != nil {
		if err := store.Save(load); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	tuyaProvider := provider.NewTuya("",
		provider.WithTuyaStore(store),
		provider.WithTuyaCloudClientForTest(cloud),
		provider.WithTuyaValidateTTL(20*time.Millisecond),
	)
	logins := provider.NewLoginManager(provider.WithLoginStore(store))
	env.handler.SetProviders(provider.NewSet(provider.NewONVIF(env.handler.onvifClient), tuyaProvider), logins, tuyaProvider, nil)
	return env, store
}

// TestSessionEndpointStaysOKAndSaysCouldNotVerifyForAnInconclusiveProbe is the
// centrepiece of the API half: a browser must never be pushed into a re-login
// flow by a probe that proved nothing.
func TestSessionEndpointStaysOKAndSaysCouldNotVerifyForAnInconclusiveProbe(t *testing.T) {
	for _, probeErr := range []error{
		context.DeadlineExceeded,
		&net.DNSError{Err: "no such host", Name: "protect-us.ismartlife.me"},
		errors.New("read tcp: connection reset by peer"),
		&tuyaqr.APIError{StatusCode: 500, ErrorCode: "SERVER_ERROR"},
		&tuyaqr.APIError{StatusCode: 502},
		&tuyaqr.APIError{StatusCode: 503},
	} {
		probeErr := probeErr
		t.Run(probeErr.Error(), func(t *testing.T) {
			cloud := &scriptedCloud{probeErr: probeErr}
			env, _ := sessionEnvWithCloud(t, cloud, handlerSession(time.Time{}))

			rec := httptest.NewRecorder()
			env.handler.TuyaSession(rec, httptest.NewRequest(http.MethodGet, "/api/tuya/session", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (%s): a probe that could not verify must not turn this endpoint into an error",
					rec.Code, rec.Body.String())
			}
			body := decodeBody(t, rec)
			if body["checkFailed"] != true {
				t.Errorf("checkFailed = %#v, want true (%v)", body["checkFailed"], probeErr)
			}
			if state, _ := body["checkState"].(string); state != "unknown" {
				t.Errorf("checkState = %#v, want \"unknown\"", body["checkState"])
			}
			if body["reloginRequired"] != false {
				t.Fatalf("reloginRequired = %#v, want false: nothing proved the session dead, and a QR scan cannot fix a network blip",
					body["reloginRequired"])
			}
			// Valid still reflects the last DEFINITIVE verdict. No probe has
			// ever succeeded in this process, so it is honestly false — and the
			// detail must NOT dress that up as a cloud rejection.
			if body["valid"] != false {
				t.Errorf("valid = %#v, want false: no probe has ever been accepted here", body["valid"])
			}
			detail, _ := body["detail"].(string)
			if strings.Contains(detail, "rejected by the cloud") {
				t.Errorf("detail = %q, want it NOT to claim the cloud rejected the session", detail)
			}
			if !strings.Contains(detail, "could not be verified") {
				t.Errorf("detail = %q, want it to say the session could not be verified", detail)
			}
		})
	}
}

// TestSessionEndpointReportsCachedValidityThroughAnInconclusiveProbe: the case
// the live install was actually in. The cloud had already accepted these cookies,
// then one probe could not reach a conclusion. The endpoint must keep saying the
// session is valid while flagging that the NEWEST check did not complete.
func TestSessionEndpointReportsCachedValidityThroughAnInconclusiveProbe(t *testing.T) {
	cloud := &scriptedCloud{}
	env, _ := sessionEnvWithCloud(t, cloud, handlerSession(time.Time{}))

	// First poll: the cloud accepts.
	rec := httptest.NewRecorder()
	env.handler.TuyaSession(rec, httptest.NewRequest(http.MethodGet, "/api/tuya/session", nil))
	first := decodeBody(t, rec)
	if first["valid"] != true || first["checkFailed"] != false {
		t.Fatalf("first poll = %v, want valid=true checkFailed=false", first)
	}

	// The network drops, and the cache window is short enough that the next poll
	// re-probes.
	cloud.probeErr = &net.DNSError{Err: "no such host", Name: "protect-us.ismartlife.me"}
	time.Sleep(60 * time.Millisecond)

	rec = httptest.NewRecorder()
	env.handler.TuyaSession(rec, httptest.NewRequest(http.MethodGet, "/api/tuya/session", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := decodeBody(t, rec)
	if body["valid"] != true {
		t.Errorf("valid = %#v, want true: the last DEFINITIVE verdict stands, a DNS failure proves nothing", body["valid"])
	}
	if body["checkFailed"] != true || body["checkState"] != "unknown" {
		t.Errorf("checkFailed=%#v checkState=%#v, want true/unknown", body["checkFailed"], body["checkState"])
	}
	if body["reloginRequired"] != false {
		t.Errorf("reloginRequired = %#v, want false", body["reloginRequired"])
	}
	detail, _ := body["detail"].(string)
	if !strings.Contains(detail, "could not be verified") {
		t.Errorf("detail = %q, want the could-not-verify wording", detail)
	}
	if !strings.Contains(detail, "streams keep running") {
		t.Errorf("detail = %q, want it to say the streams keep running", detail)
	}
}

// TestSessionEndpointStillDemandsAReloginForARealRejection makes sure the
// softening above did not soften THIS: a cloud rejection must still be
// unmistakable, on the same 200 shape the UI has always read.
func TestSessionEndpointStillDemandsAReloginForARealRejection(t *testing.T) {
	cloud := &scriptedCloud{probeErr: &tuyaqr.SessionExpiredError{StatusCode: 401, ErrorCode: "USER_SESSION_LOSS", ErrorMsg: "Not login"}}
	env, _ := sessionEnvWithCloud(t, cloud, handlerSession(time.Time{}))

	rec := httptest.NewRecorder()
	env.handler.TuyaSession(rec, httptest.NewRequest(http.MethodGet, "/api/tuya/session", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["valid"] != false {
		t.Errorf("valid = %#v, want false after a cloud rejection", body["valid"])
	}
	if body["reloginRequired"] != true {
		t.Fatalf("reloginRequired = %#v, want TRUE: a real cloud rejection still needs a QR scan", body["reloginRequired"])
	}
	if body["checkFailed"] != false || body["checkState"] != "invalid" {
		t.Errorf("checkFailed=%#v checkState=%#v, want false/invalid", body["checkFailed"], body["checkState"])
	}
	detail, _ := body["detail"].(string)
	if !strings.Contains(detail, "rejected by the cloud") {
		t.Errorf("detail = %q, want it to name the cloud rejection", detail)
	}
	if strings.Contains(rec.Body.String(), "s-sid=") || strings.Contains(rec.Body.String(), strings.Repeat("A", 32)) {
		t.Fatalf("a cookie value leaked into the session response: %s", rec.Body.String())
	}
}

// TestSessionEndpointReportsARecoveredSessionWithoutAHuman: once the cloud
// accepts again, the endpoint must stop demanding a QR scan. Nothing else in the
// UI clears that banner, so this is what makes the recovery visible.
func TestSessionEndpointReportsARecoveredSessionWithoutAHuman(t *testing.T) {
	cloud := &scriptedCloud{probeErr: &tuyaqr.SessionExpiredError{StatusCode: 401, ErrorCode: "USER_SESSION_LOSS"}}
	env, _ := sessionEnvWithCloud(t, cloud, handlerSession(time.Time{}))

	rec := httptest.NewRecorder()
	env.handler.TuyaSession(rec, httptest.NewRequest(http.MethodGet, "/api/tuya/session", nil))
	if body := decodeBody(t, rec); body["reloginRequired"] != true {
		t.Fatalf("precondition: reloginRequired = %#v, want true", body["reloginRequired"])
	}

	// The cloud accepts the same stored cookies again. The shortened cache window
	// means the next poll re-probes rather than returning the cached rejection.
	cloud.probeErr = nil
	time.Sleep(60 * time.Millisecond)

	rec = httptest.NewRecorder()
	env.handler.TuyaSession(rec, httptest.NewRequest(http.MethodGet, "/api/tuya/session", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := decodeBody(t, rec)
	if body["valid"] != true {
		t.Errorf("valid = %#v, want true after an accepted probe", body["valid"])
	}
	if body["reloginRequired"] != false {
		t.Fatalf("reloginRequired = %#v, want false: the cloud accepted the session again, so the QR demand must clear", body["reloginRequired"])
	}
	if body["checkFailed"] != false || body["checkState"] != "valid" {
		t.Errorf("checkFailed=%#v checkState=%#v, want false/valid", body["checkFailed"], body["checkState"])
	}
	if _, ok := body["autoResumedStreams"]; !ok {
		t.Log("autoResumedStreams is omitted when zero, which is the documented additive behaviour")
	}
}
