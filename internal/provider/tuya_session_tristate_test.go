package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/models"
	"dengan.dev/camera-streamer/internal/tuyaqr"
)

// --- THE TRI-STATE SESSION VERDICT -------------------------------------------
//
// WHY THIS FILE EXISTS, and why the central assertion is a CALL COUNT.
//
// MEASURED defect, from the live install's own log on 2026-09-22. The SAME
// stored cookies were accepted by the cloud at 11:27:14, the periodic probe
// reported "session INVALID" at 11:30:47, and the cloud accepted the very same
// cookies again at 11:33:07:
//
//	11:27:14  persisted the cloud-reported Tuya session state   (probe OK)
//	11:30:47  periodic check: session INVALID                   (probe failed)
//	11:33:07  persisted the cloud-reported Tuya session state   (probe OK)
//
// `persistSession` runs ONLY when RefreshExpiry returned nil, so each of those
// lines is proof of a successful authenticated cloud call with those cookies. A
// session the cloud keeps accepting cannot have been rejected at 11:30:47. The
// probe verdict was simply UNRELIABLE, and the old code treated "not verified"
// as "the cloud rejected these cookies": every Tuya stream was stood down,
// needs_relogin was set, and a human QR re-scan was demanded. That happened
// three times — 16 minutes, then 6.9 HOURS of dead camera — while ONVIF, which
// has no such probe, was unaffected, which is exactly what made it look like an
// intermittent fault rather than a misclassification.
//
// The predicate that distinguishes the two was ALREADY THERE and was never
// called at the decision point: SessionExpired(err) (tuya.go), which is true only
// for the typed tuyaqr sentinels ErrSessionExpired / ErrNoSession. A transport
// error, a timeout, a DNS failure, an EOF on the body and an HTTP 5xx are all
// untyped or *APIError, so SessionExpired is false for every one of them.
//
// The test that would have caught the bug is therefore not "is Valid false" — it
// is HOW MANY TIMES the stream stopper was asked to suspend streams. Anything
// other than 0 for an inconclusive probe is the bug, and exactly 1 for a genuine
// rejection is the contract that must still hold.

// recordingStopper is a recorder fake on TuyaStreamStopper. It models the real
// *stream.Manager closely enough for the counts to be meaningful:
//
//   - a stream is either running or suspended, never both;
//   - SuspendStreamsForProvider suspends every RUNNING one and reports how many
//     it moved, so a second sweep of an already-suspended set reports 0 — which
//     is what makes ExpiredStreamsStopped a count of distinct stand-downs
//     rather than a count of sweeps;
//   - SuspendedStreams lists exactly the suspended ones, because that is what
//     the recovery path reads.
type recordingStopper struct {
	mu             sync.Mutex
	running        []models.StreamInfo
	suspended      []models.StreamInfo
	suspendCalls   int
	suspendReasons []string
	resumeCalls    int
	resumedIDs     []string
}

func (r *recordingStopper) SuspendStreamsForProvider(_ models.ProviderKind, reason string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.suspendCalls++
	r.suspendReasons = append(r.suspendReasons, reason)
	moved := len(r.running)
	r.suspended = append(r.suspended, r.running...)
	r.running = nil
	return moved, nil
}

func (r *recordingStopper) SuspendedStreams(models.ProviderKind) []models.StreamInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]models.StreamInfo, len(r.suspended))
	copy(out, r.suspended)
	return out
}

func (r *recordingStopper) ResumeSuspended(streamID, rtspURL string, _ models.ProviderKind) (*models.StreamInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resumeCalls++
	r.resumedIDs = append(r.resumedIDs, streamID)
	for i, s := range r.suspended {
		if s.ID == streamID {
			r.suspended = append(append([]models.StreamInfo{}, r.suspended[:i]...), r.suspended[i+1:]...)
			r.running = append(r.running, s)
			break
		}
	}
	return &models.StreamInfo{ID: streamID, Provider: models.ProviderTuya, RtspURL: rtspURL}, nil
}

// suspendCount / resumeCount are the numbers the whole file turns on.
func (r *recordingStopper) suspendCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.suspendCalls
}

func (r *recordingStopper) resumeCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.resumeCalls
}

func (r *recordingStopper) runningCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.running)
}

// twoTuyaStreams is the shape the live install has: two cameras suspended
// together, each keeping its profile token so a resume targets the same device.
func twoTuyaStreams() []models.StreamInfo {
	return []models.StreamInfo{
		{ID: "stream_1", ProfileToken: "tuya:eb9f1d6e677b1b39f222ag", Provider: models.ProviderTuya},
		{ID: "stream_2", ProfileToken: "tuya:aaaaaaaaaaaaaaaaaaaaaa", Provider: models.ProviderTuya},
	}
}

// probeErrorFor builds the error the fake cloud reports for each failure mode
// the tri-state classifier has to tell apart. The distinction is the whole point:
// the first group is the cloud's OWN rejection, the second is everything that
// could not reach a conclusion.
func probeErrorFor(mode string) error {
	switch mode {
	case "401_USER_SESSION_LOSS":
		return &tuyaqr.SessionExpiredError{StatusCode: 401, ErrorCode: "USER_SESSION_LOSS", ErrorMsg: "Not login"}
	case "401_bare":
		return &tuyaqr.SessionExpiredError{StatusCode: 401}
	case "200_USER_SESSION_LOSS":
		return &tuyaqr.SessionExpiredError{StatusCode: 200, ErrorCode: "USER_SESSION_LOSS"}
	case "200_USER_SESSION_INVALID":
		return &tuyaqr.SessionExpiredError{StatusCode: 200, ErrorCode: "USER_SESSION_INVALID"}
	case "200_not_login":
		// How a bare `status:"not_login"` arrival looks once tuyaqr has typed
		// it: a SessionExpiredError with no errorCode at all.
		return &tuyaqr.SessionExpiredError{StatusCode: 200, ErrorMsg: "Not login"}
	case "wrapped_no_session":
		return fmt.Errorf("provider: tuya session: %w", tuyaqr.ErrNoSession)

	case "deadline":
		return context.DeadlineExceeded
	case "wrapped_deadline":
		return fmt.Errorf("tuyaqr: /api/new/common/homeList: %w", context.DeadlineExceeded)
	case "dns":
		return &net.DNSError{Err: "no such host", Name: "protect-us.ismartlife.me", IsNotFound: true}
	case "connection_reset":
		return errors.New("Post \"https://protect-us.ismartlife.me/api/new/common/homeList\": read tcp 10.0.0.2:54321->10.0.0.9:443: read: connection reset by peer")
	case "eof_on_body":
		return io.EOF
	case "unexpected_eof":
		return io.ErrUnexpectedEOF
	case "http_500":
		return &tuyaqr.APIError{StatusCode: 500, ErrorCode: "SERVER_ERROR", ErrorMsg: "internal"}
	case "http_502":
		return &tuyaqr.APIError{StatusCode: 502, ErrorCode: "", ErrorMsg: "bad gateway"}
	case "http_503":
		return &tuyaqr.APIError{StatusCode: 503, ErrorCode: "", ErrorMsg: "unavailable"}
	case "http_403":
		return &tuyaqr.APIError{StatusCode: 403, ErrorCode: "FORBIDDEN", ErrorMsg: "denied"}
	case "unparseable":
		return errors.New("tuyaqr: /api/new/common/homeList: unparseable response (HTTP 200)")
	}
	panic("unknown probe failure mode: " + mode)
}

// definitiveFailures are the ONLY failure modes that may stop a stream.
//
// `wrapped_no_session` is in here deliberately, and it is the one entry that is
// not a cloud verdict: ErrNoSession means the stored credential cannot even be
// assembled (missing fast-sid/s-sid, or nothing stored at all), so no probe could
// ever succeed with it and a QR scan is unambiguously the way out. SessionExpired
// has always documented that ("ErrNoSession ... a fresh QR login is required"),
// and this table pins it so the tri-state change cannot quietly start treating a
// missing credential as "unverifiable" and leave a dead camera grinding.
var definitiveFailures = map[string]bool{
	"401_USER_SESSION_LOSS":    true,
	"401_bare":                 true,
	"200_USER_SESSION_LOSS":    true,
	"200_USER_SESSION_INVALID": true,
	"200_not_login":            true,
	"wrapped_no_session":       true,
}

// allFailureModes is the full table, exercised by several tests.
var allFailureModes = []string{
	"401_USER_SESSION_LOSS", "401_bare", "200_USER_SESSION_LOSS",
	"200_USER_SESSION_INVALID", "200_not_login", "wrapped_no_session",
	"deadline", "wrapped_deadline", "dns", "connection_reset",
	"eof_on_body", "unexpected_eof",
	"http_500", "http_502", "http_503", "http_403",
	"unparseable",
}

// TestSessionRejectionIsTheOnlyFailureThatStopsAStream is THE test that would
// have caught the 2026-09-22 regression. It asserts, per failure mode:
//
//   - a definitive cloud rejection => SessionExpired()==true, Valid==false,
//     ReloginRequired==true, and suspend called EXACTLY ONCE;
//   - every inconclusive failure  => SessionExpired()==false, suspend called
//     ZERO times, ReloginRequired==false, and the streams still RUNNING.
func TestSessionRejectionIsTheOnlyFailureThatStopsAStream(t *testing.T) {
	for _, mode := range allFailureModes {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			probeErr := probeErrorFor(mode)
			wantDefinitive := definitiveFailures[mode]

			// The predicate itself, first: this is the classification the
			// decision point was not using.
			if got := SessionExpired(probeErr); got != wantDefinitive {
				t.Fatalf("SessionExpired(%v) = %t, want %t", probeErr, got, wantDefinitive)
			}

			stopper := &recordingStopper{running: twoTuyaStreams()}
			lister := &fakeLister{probeErr: probeErr, probeErrSet: true}
			p := NewTuya("/tmp/session.json",
				WithTuyaBridge(&fakeBridge{}),
				WithTuyaStreamStopper(stopper),
				withTuyaLister(lister, testSession()))
			// A validateTTL of 0 means every Session() call re-probes, so the
			// verdict under test is always the one just reported.
			p.validateTTL = 0

			status, err := p.Session(context.Background())
			if err != nil {
				t.Fatalf("Session: %v", err)
			}

			if wantDefinitive {
				if stopper.suspendCount() != 1 {
					t.Fatalf("SuspendStreamsForProvider calls = %d, want EXACTLY 1 for a definitive rejection (%v)",
						stopper.suspendCount(), probeErr)
				}
				if status.Valid {
					t.Error("valid = true although the cloud rejected the session")
				}
				if !status.ReloginRequired {
					t.Error("reloginRequired = false although only a QR scan can fix a rejected session")
				}
				if status.CheckFailed {
					t.Error("checkFailed = true: this probe DID reach a conclusion")
				}
				if status.CheckState != "invalid" {
					t.Errorf("checkState = %q, want invalid", status.CheckState)
				}
				if !strings.Contains(status.Detail, "QR") {
					t.Errorf("detail = %q, want it to name the QR scan", status.Detail)
				}
				if status.ExpiredStreamsStopped != len(twoTuyaStreams()) {
					t.Errorf("expiredStreamsStopped = %d, want %d", status.ExpiredStreamsStopped, len(twoTuyaStreams()))
				}
				return
			}

			// INCONCLUSIVE. This is the half that was broken.
			if n := stopper.suspendCount(); n != 0 {
				t.Fatalf("SuspendStreamsForProvider calls = %d, want ZERO for an inconclusive probe (%v): "+
					"a transport/5xx failure is NOT the cloud rejecting the cookies, and standing the streams "+
					"down for it is the 2026-09-22 regression", n, probeErr)
			}
			if stopper.runningCount() != len(twoTuyaStreams()) {
				t.Errorf("running streams = %d, want %d: an inconclusive probe must leave the streams untouched",
					stopper.runningCount(), len(twoTuyaStreams()))
			}
			if status.ReloginRequired {
				t.Errorf("reloginRequired = true for an inconclusive probe (%v): a QR scan cannot repair a network blip", probeErr)
			}
			if !status.CheckFailed {
				t.Error("checkFailed = false although the probe could not verify the session")
			}
			if status.CheckState != "unknown" {
				t.Errorf("checkState = %q, want unknown", status.CheckState)
			}
			if status.CheckError == "" {
				t.Error("checkError is empty, so the response does not say WHY the session could not be verified")
			}
			if status.Detail == "" || strings.Contains(status.Detail, "scan a new QR code") {
				t.Errorf("detail = %q, want an honest \"could not verify\" that does NOT demand a QR scan", status.Detail)
			}
		})
	}
}

// TestInconclusiveProbeLeavesTheLastDefinitiveVerdictAlone: "could not verify" is
// not "invalid". A probe that proves nothing must not overwrite what the last
// conclusive probe proved — that is the exact line that used to read
// `t.lastCheckOK = validateErr == nil`.
func TestInconclusiveProbeLeavesTheLastDefinitiveVerdictAlone(t *testing.T) {
	stopper := &recordingStopper{running: twoTuyaStreams()}
	lister := &fakeLister{}
	p := NewTuya("/tmp/session.json",
		WithTuyaBridge(&fakeBridge{}),
		WithTuyaStreamStopper(stopper),
		withTuyaLister(lister, testSession()))
	p.validateTTL = 0

	// 1) The cloud accepts: valid, nothing suspended.
	status, err := p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.Valid || !status.CloudVerified || status.CheckFailed {
		t.Fatalf("after an accepted probe: valid=%t cloudVerified=%t checkFailed=%t, want true/true/false",
			status.Valid, status.CloudVerified, status.CheckFailed)
	}

	// 2) The network drops. Valid must STAY true.
	lister.probeErrSet = true
	lister.probeErr = &net.DNSError{Err: "no such host", Name: "protect-us.ismartlife.me"}
	status, err = p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.Valid {
		t.Error("valid = false after a DNS failure: the cloud never rejected anything, so validity is UNCHANGED")
	}
	if !status.CloudVerified {
		t.Error("cloudVerified = false after a DNS failure: the last DEFINITIVE verdict was that the cloud accepted it")
	}
	if !status.CheckFailed || status.CheckState != "unknown" {
		t.Errorf("checkFailed=%t checkState=%q, want true/unknown", status.CheckFailed, status.CheckState)
	}
	if stopper.suspendCount() != 0 {
		t.Fatalf("suspend calls = %d, want 0", stopper.suspendCount())
	}

	// 3) The cloud is reachable again: clean, still nothing suspended.
	lister.probeErrSet = false
	status, err = p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.Valid || status.CheckFailed {
		t.Errorf("after recovery: valid=%t checkFailed=%t, want true/false", status.Valid, status.CheckFailed)
	}
	if status.CheckState != "valid" {
		t.Errorf("checkState = %q, want valid", status.CheckState)
	}
	if stopper.suspendCount() != 0 || stopper.resumeCount() != 0 {
		t.Fatalf("suspend=%d resume=%d, want 0/0: a blip that never stood anything down must not resume anything either",
			stopper.suspendCount(), stopper.resumeCount())
	}
}

// TestInconclusiveProbeDoesNotClearAGenuineRejection is the other direction, and
// it matters just as much: a transient failure must not be read as good news
// either. A definitive rejection STAYS definitive until a probe is accepted.
func TestInconclusiveProbeDoesNotClearAGenuineRejection(t *testing.T) {
	stopper := &recordingStopper{running: twoTuyaStreams()}
	lister := &fakeLister{probeErr: probeErrorFor("401_USER_SESSION_LOSS"), probeErrSet: true}
	p := NewTuya("/tmp/session.json",
		WithTuyaBridge(&fakeBridge{}),
		WithTuyaStreamStopper(stopper),
		withTuyaLister(lister, testSession()))
	p.validateTTL = 0

	if _, err := p.Session(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stopper.suspendCount() != 1 {
		t.Fatalf("suspend calls = %d, want 1", stopper.suspendCount())
	}

	// The cloud becomes unreachable. The session is still REJECTED — nothing has
	// proven otherwise — so the demand for a QR scan must stand.
	lister.probeErr = context.DeadlineExceeded
	status, err := p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Valid {
		t.Error("valid = true after an inconclusive probe that followed a rejection: nothing was proven")
	}
	if !status.ReloginRequired {
		t.Error("reloginRequired = false: a rejection is not undone by a probe that reached no conclusion")
	}
	if !status.CheckFailed {
		t.Error("checkFailed = false: the newest check genuinely did not complete")
	}
	if status.CheckState != "unknown" {
		t.Errorf("checkState = %q, want unknown (the CHECK is unknown even though the session is invalid)", status.CheckState)
	}
	if stopper.suspendCount() != 1 {
		t.Errorf("suspend calls = %d, want 1: an inconclusive probe must never re-sweep the stream manager", stopper.suspendCount())
	}
	if stopper.resumeCount() != 0 {
		t.Fatal("an inconclusive probe resumed streams: only an ACCEPTED probe may")
	}
}

// TestRepeatedRejectionSuspendsExactlyOnce pins the call count for a session the
// cloud keeps rejecting. SuspendStreamsForProvider is called on the TRANSITION
// into a rejected state only, so ExpiredStreamsStopped counts distinct
// stand-downs rather than probes.
func TestRepeatedRejectionSuspendsExactlyOnce(t *testing.T) {
	stopper := &recordingStopper{running: twoTuyaStreams()}
	lister := &fakeLister{probeErr: probeErrorFor("401_USER_SESSION_LOSS"), probeErrSet: true}
	p := NewTuya("/tmp/session.json",
		WithTuyaBridge(&fakeBridge{}),
		WithTuyaStreamStopper(stopper),
		withTuyaLister(lister, testSession()))
	p.validateTTL = 0

	var status *SessionStatus
	for i := 0; i < 4; i++ {
		var err error
		status, err = p.Session(context.Background())
		if err != nil {
			t.Fatal(err)
		}
	}
	if stopper.suspendCount() != 1 {
		t.Fatalf("suspend calls = %d across 4 rejected probes, want EXACTLY 1", stopper.suspendCount())
	}
	if status.ExpiredStreamsStopped != len(twoTuyaStreams()) {
		t.Errorf("expiredStreamsStopped = %d, want %d (it counts streams, not sweeps)",
			status.ExpiredStreamsStopped, len(twoTuyaStreams()))
	}
	if !status.ReloginRequired {
		t.Error("reloginRequired = false after four rejections")
	}
}

// TestAnInconclusiveProbeIsCachedSoTheUIBurstCannotRetryStormTheCloud: the UI
// polls /api/tuya/session, and an inconclusive verdict must not turn a browser
// burst into a burst of cloud calls just because it is "not a success".
func TestAnInconclusiveProbeIsCachedSoTheUIBurstCannotRetryStormTheCloud(t *testing.T) {
	stopper := &recordingStopper{running: twoTuyaStreams()}
	lister := &fakeLister{probeErr: &net.DNSError{Err: "no such host", Name: "protect-us.ismartlife.me"}, probeErrSet: true}
	p := NewTuya("/tmp/session.json",
		WithTuyaBridge(&fakeBridge{}),
		WithTuyaStreamStopper(stopper),
		withTuyaLister(lister, testSession()),
		withTuyaValidateTTL(time.Minute))

	for i := 0; i < 5; i++ {
		if _, err := p.Session(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if lister.refreshCalls != 1 {
		t.Fatalf("probe calls = %d across 5 polls, want 1: an inconclusive verdict must be cached like any other",
			lister.refreshCalls)
	}
	if stopper.suspendCount() != 0 {
		t.Fatalf("suspend calls = %d, want 0", stopper.suspendCount())
	}
	if p.checkStateForTest() != "unknown" {
		t.Errorf("checkState = %q, want unknown", p.checkStateForTest())
	}
}

// TestSessionDetailNeverNamesASecret: the "could not verify" text is
// operator-facing and goes out over HTTP, so it must carry the CLASS of failure
// and never a raw error body or a cookie.
func TestSessionDetailNeverNamesASecret(t *testing.T) {
	stopper := &recordingStopper{}
	lister := &fakeLister{
		probeErr: errors.New(`Post "https://protect-us.ismartlife.me/api/new/common/homeList": ` +
			`dial tcp 10.0.0.9:443: connect: connection refused (cookie fast-sid=` + strings.Repeat("A", 32) + `)`),
		probeErrSet: true,
	}
	p := NewTuya("/tmp/session.json",
		WithTuyaBridge(&fakeBridge{}),
		WithTuyaStreamStopper(stopper),
		withTuyaLister(lister, testSession()))
	p.validateTTL = 0

	status, err := p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blob := status.Detail + " " + status.CheckError
	if strings.Contains(blob, strings.Repeat("A", 32)) {
		t.Fatalf("a cookie-shaped value leaked into the session detail: %q", blob)
	}
	if !strings.Contains(status.CheckError, "network connection to the cloud failed") {
		t.Errorf("checkError = %q, want the FAILURE CLASS in words", status.CheckError)
	}

	// And the JSON wire shape: the additive fields must be present and named
	// exactly as the UI expects.
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"checkFailed", "checkError", "checkState", "valid", "reloginRequired", "detail"} {
		if _, ok := wire[key]; !ok {
			t.Errorf("the session JSON is missing %q: %s", key, raw)
		}
	}
	if wire["checkFailed"] != true || wire["checkState"] != "unknown" {
		t.Errorf("wire = %v, want checkFailed=true checkState=unknown", wire)
	}
}

// TestLocalCredentialFailureDoesNotStopStreams: when no usable credential can be
// assembled locally there is nothing to probe with, so the session is reported
// as definitively needing a QR scan — but standing the OTHER streams down would
// be the same overreach this change removes, and it is not the cloud's verdict.
func TestLocalCredentialFailureDoesNotStopStreams(t *testing.T) {
	stopper := &recordingStopper{running: twoTuyaStreams()}
	p := NewTuya("/nonexistent/dir/session.json", WithTuyaStreamStopper(stopper), WithTuyaBridge(&fakeBridge{}))
	p.validateTTL = 0

	status, err := p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Valid || !status.ReloginRequired {
		t.Errorf("valid=%t reloginRequired=%t, want false/true with no usable credential", status.Valid, status.ReloginRequired)
	}
	if status.CheckFailed {
		t.Error("checkFailed = true: an unusable local credential is a conclusion, not a network blip")
	}
	if status.CheckState != "invalid" {
		t.Errorf("checkState = %q, want invalid", status.CheckState)
	}
	if stopper.suspendCount() != 0 {
		t.Fatalf("suspend calls = %d, want 0: no cloud rejection happened, so no stream may be stopped", stopper.suspendCount())
	}
}

// --- the recovery half -------------------------------------------------------

// TestARejectedSessionSelfHealsWhenTheCloudAcceptsAgain is the recovery contract
// that turns the head-fix into a real fix. A genuine rejection still latches
// (nothing else can be done with the same cookies), but the latch CLEARS ITSELF
// the moment a probe is accepted, because the credential was never discarded and
// the profile tokens were kept.
func TestARejectedSessionSelfHealsWhenTheCloudAcceptsAgain(t *testing.T) {
	stopper := &recordingStopper{running: twoTuyaStreams()}
	lister := &fakeLister{probeErr: probeErrorFor("401_USER_SESSION_LOSS"), probeErrSet: true}
	p := NewTuya("/tmp/session.json",
		WithTuyaBridge(&fakeBridge{}),
		WithTuyaStreamStopper(stopper),
		withTuyaLister(lister, testSession()))
	p.validateTTL = 0

	// 1) The cloud rejects: the streams go down and a QR scan is demanded.
	status, err := p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.ReloginRequired || status.Valid {
		t.Fatalf("after a rejection: reloginRequired=%t valid=%t, want true/false", status.ReloginRequired, status.Valid)
	}
	if stopper.suspendCount() != 1 || stopper.runningCount() != 0 {
		t.Fatalf("suspend=%d running=%d, want 1/0", stopper.suspendCount(), stopper.runningCount())
	}

	// 2) A later probe is accepted — with the SAME stored cookies, no QR scan,
	// no user input. This is the state the live install reached 2m20s after its
	// "failure" on 2026-09-22.
	lister.probeErrSet = false
	status, err = p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.ReloginRequired {
		t.Error("reloginRequired = true although the cloud accepted the session again: the latch did not clear")
	}
	if !status.Valid {
		t.Error("valid = false although an accepted probe just ran")
	}
	if stopper.resumeCount() != len(twoTuyaStreams()) {
		t.Fatalf("resume calls = %d, want %d: the stood-down streams must come back on their own",
			stopper.resumeCount(), len(twoTuyaStreams()))
	}
	if stopper.runningCount() != len(twoTuyaStreams()) {
		t.Errorf("running streams = %d, want %d", stopper.runningCount(), len(twoTuyaStreams()))
	}
	if status.AutoResumedStreams != len(twoTuyaStreams()) {
		t.Errorf("autoResumedStreams = %d, want %d: the self-heal must be visible from outside the process",
			status.AutoResumedStreams, len(twoTuyaStreams()))
	}
	// The resume must target the SAME cameras, in the order they were suspended.
	want := []string{"stream_1", "stream_2"}
	if strings.Join(stopper.resumedIDs, ",") != strings.Join(want, ",") {
		t.Errorf("resumed ids = %v, want %v (same cameras, no re-selection)", stopper.resumedIDs, want)
	}
	if stopper.suspendCount() != 1 {
		t.Errorf("suspend calls = %d, want 1: recovery must not re-suspend anything", stopper.suspendCount())
	}
}

// TestTheStartPathProbeAlsoSelfHeals: the start-stream gate is the OTHER place a
// probe decides, and it must reach the same verdict. Before a rejection it lets
// the start through; after a rejection a transient failure must not turn into a
// refusal, and an accepted probe must still clear the latch.
func TestTheStartPathProbeAlsoSelfHeals(t *testing.T) {
	stopper := &recordingStopper{running: []models.StreamInfo{
		{ID: "stream_1", ProfileToken: "tuya:eb9f1d6e677b1b39f222ag", Provider: models.ProviderTuya},
	}}
	// The lister's `err` drives Validate (the start-path probe) and `probeErr`
	// drives RefreshExpiry, so the two probes can differ.
	lister := &fakeLister{err: probeErrorFor("401_USER_SESSION_LOSS")}
	p := NewTuya("/tmp/session.json",
		WithTuyaBridge(&fakeBridge{}),
		WithTuyaStreamStopper(stopper),
		withTuyaLister(lister, testSession()))
	p.validateTTL = time.Nanosecond

	// A definitive rejection on the start path refuses the start.
	if _, err := p.StartStream("eb9f1d6e677b1b39f222ag"); !errors.Is(err, ErrSessionReloginRequired) {
		t.Fatalf("err = %v, want ErrSessionReloginRequired", err)
	}
	if stopper.suspendCount() != 1 {
		t.Fatalf("suspend calls = %d, want 1", stopper.suspendCount())
	}

	// The cloud is unreachable. The start must NOT be reported as a dead
	// session: the probe reached no conclusion.
	time.Sleep(2 * time.Millisecond)
	lister.err = &net.DNSError{Err: "no such host", Name: "protect-us.ismartlife.me"}
	if _, err := p.StartStream("eb9f1d6e677b1b39f222ag"); errors.Is(err, ErrSessionReloginRequired) {
		t.Fatalf("a transport failure was reported as a dead session: %v", err)
	}
	if stopper.suspendCount() != 1 {
		t.Fatalf("suspend calls = %d, want 1: an inconclusive probe may not re-suspend", stopper.suspendCount())
	}

	// The cloud accepts again: the latch clears without a QR scan.
	time.Sleep(2 * time.Millisecond)
	lister.err = nil
	if _, err := p.StartStream("eb9f1d6e677b1b39f222ag"); err != nil {
		t.Fatalf("StartStream after recovery: %v", err)
	}
	if stopper.resumeCount() != 1 {
		t.Fatalf("resume calls = %d, want 1: the start-path probe accepted the session, so the stand-down must be undone",
			stopper.resumeCount())
	}
}

// TestWatchdogDetailSaysRecoveryIsAutomatic: the operator-facing text must say
// plainly what happens next, because the whole failure mode being fixed here was
// a human being told to scan a QR code that could not have helped.
func TestWatchdogDetailSaysRecoveryIsAutomatic(t *testing.T) {
	stopper := &recordingStopper{running: twoTuyaStreams()}
	lister := &fakeLister{probeErr: context.DeadlineExceeded, probeErrSet: true}
	p := NewTuya("/tmp/session.json",
		WithTuyaBridge(&fakeBridge{}),
		WithTuyaStreamStopper(stopper),
		withTuyaLister(lister, testSession()))
	p.validateTTL = 0

	// Before any rejection, with streams running: an inconclusive probe is
	// plainly not a stand-down and needs no human.
	status, err := p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status.Detail, "streams keep running") {
		t.Errorf("detail = %q, want it to say the streams keep running", status.Detail)
	}
	if !strings.Contains(status.Detail, "no QR scan") {
		t.Errorf("detail = %q, want it to say no QR scan is needed", status.Detail)
	}

	// After a real rejection has stood the streams down, a later inconclusive
	// probe must promise the automatic resume rather than a QR scan.
	lister.probeErr = probeErrorFor("401_USER_SESSION_LOSS")
	if _, err := p.Session(context.Background()); err != nil {
		t.Fatal(err)
	}
	lister.probeErr = context.DeadlineExceeded
	status, err = p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status.Detail, "resumed automatically") {
		t.Errorf("detail = %q, want it to say the stood-down streams resume automatically", status.Detail)
	}
	if strings.Contains(status.Detail, "scan a new QR code;") {
		t.Errorf("detail = %q, want no demand for a QR scan while the check is inconclusive", status.Detail)
	}
}

// checkStateForTest reads the tri-state word for tests in this file without
// reaching into the provider's mutex from outside.
func (t *Tuya) checkStateForTest() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.checkStateLocked()
}
