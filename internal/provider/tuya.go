package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"dengan.dev/camera-streamer/internal/models"
	"dengan.dev/camera-streamer/internal/tuyaengine"
	"dengan.dev/camera-streamer/internal/tuyaqr"
)

// sessionProbeTimeout bounds the liveness probe issued when a stream start fails,
// so a hung cloud cannot make the HTTP request hang with it.
const sessionProbeTimeout = 8 * time.Second

// TuyaStreaming is the slice of tuyaengine.Bridge this package needs. Declaring
// it here (rather than importing *tuyaengine.Bridge concretely) keeps the Tuya
// provider unit-testable without an engine, while the real bridge satisfies it
// directly.
type TuyaStreaming interface {
	StartStream(spec tuyaengine.DeviceSpec) (*models.StreamInfo, error)
	Resolve(deviceID string) (string, error)
}

// TuyaList is the slice of *tuyaqr.Client this package needs.
type TuyaList interface {
	Cameras(ctx context.Context) ([]tuyaqr.Device, error)
	Validate(ctx context.Context) error
	// RefreshExpiry probes the cloud once and folds any server-reported cookie
	// expiry into the session. Implemented by *tuyaqr.Client.
	RefreshExpiry(ctx context.Context, s *tuyaqr.Session) error
}

// TuyaStreamStopper is the stream registry the provider uses to stand down and
// later resume the streams a dead Tuya session can no longer feed.
//
// The whole point of this interface is the M6 "stop the bleed" behaviour: an
// HLS watchdog restarts ffmpeg whenever the playlist stops advancing, so a
// stream whose Tuya source is dead would otherwise loop forever. Standing the
// stream down is a deliberate, logged degradation — and because the stream is
// SUSPENDED rather than removed, a re-login can resume exactly the same cameras
// instead of making the user re-pick them.
type TuyaStreamStopper interface {
	// SuspendStreamsForProvider stands down every stream of a provider,
	// keeping their registered state so they can be resumed. It returns how
	// many were suspended.
	SuspendStreamsForProvider(provider models.ProviderKind, reason string) (int, error)
	// SuspendedStreams lists the suspended streams of a provider.
	SuspendedStreams(provider models.ProviderKind) []models.StreamInfo
	// ResumeSuspended restarts a suspended stream with a fresh RTSP URL.
	ResumeSuspended(streamID, rtspURL string, provider models.ProviderKind) (*models.StreamInfo, error)
}

// Tuya is the Tuya/Smart Life provider: discovery through internal/tuyaqr and
// streaming through internal/tuyaengine.
//
// Both halves are thin adapters. Discovery talks to the same cloud calls the
// verified tuyaqr package already makes; streaming hands the device id to the
// verified Bridge, which serves it over loopback RTSP into the existing
// (unmodified) stream.Manager pipeline. Nothing here talks WebRTC or RTSP.
//
// Security: the provider holds no cookie values itself and its outputs are
// built only from tuyaqr.Device fields plus Device.Redacted(). Device.Config
// (p2p auth token, localKey) is never copied into a Camera or into a log line.
type Tuya struct {
	sessionFile string
	resolution  string
	host        string

	bridge  TuyaStreaming
	stopper TuyaStreamStopper
	log     TuyaLogger

	validateTTL time.Duration

	mu          sync.Mutex
	client      TuyaList
	session     *tuyaqr.Session
	lastCheck   time.Time
	lastCheckOK bool
	lastErr     string
	// expiryOrigin records whether the stored expiry came from the cloud
	// ("cookie:fast-sid") or is genuinely unknown (""). It is never guessed.
	expiryOrigin string
	// expiryUpdatedAt is when the expiry was last refreshed from the cloud.
	expiryUpdatedAt time.Time
	// stoppedStreams counts Tuya streams this provider stopped because the
	// session died. It is the observable trace of "stop the bleed".
	stoppedStreams int
}

// TuyaLogger is the minimal logger surface used for secret-free diagnostics.
type TuyaLogger interface {
	LogInfo(streamID, source, message string)
	LogWarn(streamID, source, message string)
	LogError(streamID, source, message string)
}

// TuyaOption configures a Tuya provider.
type TuyaOption func(*Tuya)

// WithTuyaBridge attaches the stream bridge. Without it, discovery still works
// but starting a Tuya stream fails with a clear message.
func WithTuyaBridge(b TuyaStreaming) TuyaOption { return func(t *Tuya) { t.bridge = b } }

// WithTuyaResolution overrides the engine stream resolution ("sd" default).
func WithTuyaResolution(r string) TuyaOption { return func(t *Tuya) { t.resolution = r } }

// WithTuyaHost overrides the Tuya region host.
func WithTuyaHost(h string) TuyaOption { return func(t *Tuya) { t.host = h } }

// WithTuyaLogger attaches a logger for secret-free discovery diagnostics.
func WithTuyaLogger(l TuyaLogger) TuyaOption { return func(t *Tuya) { t.log = l } }

// WithTuyaStreamStopper attaches the stream registry the provider uses to stop
// the streams a dead session can no longer feed. Without it, a session loss is
// still reported but nothing is stopped, and the HLS watchdog keeps restarting
// ffmpeg against a dead source forever.
func WithTuyaStreamStopper(s TuyaStreamStopper) TuyaOption { return func(t *Tuya) { t.stopper = s } }

// withTuyaLister injects a discovery client. Test-only seam: the real one is
// built from the session file.
func withTuyaLister(l TuyaList, s *tuyaqr.Session) TuyaOption {
	return func(t *Tuya) {
		t.client = l
		t.session = s
	}
}

// withTuyaValidateTTL shortens the session-validation cache in tests.
func withTuyaValidateTTL(d time.Duration) TuyaOption { return func(t *Tuya) { t.validateTTL = d } }

// NewTuya builds a Tuya provider over a read-only session file. It does not
// touch the cloud or the file here: the session is loaded lazily on first use so
// that constructing the provider cannot fail a server start.
func NewTuya(sessionFile string, opts ...TuyaOption) *Tuya {
	t := &Tuya{
		sessionFile: sessionFile,
		resolution:  tuyaengine.DefaultResolution,
		host:        tuyaengine.DefaultTuyaHost,
		validateTTL: 30 * time.Second,
	}
	for _, fn := range opts {
		fn(t)
	}
	return t
}

// Kind reports Tuya.
func (t *Tuya) Kind() Kind { return KindTuya }

// SessionFile is the read-only session path this provider reads.
func (t *Tuya) SessionFile() string { return t.sessionFile }

// Configured reports whether a session file is wired up at all.
func (t *Tuya) Configured() bool { return strings.TrimSpace(t.sessionFile) != "" }

// ErrSessionReloginRequired is returned when a Tuya stream cannot be started or
// kept running because the stored session is dead. The HTTP layer maps it to a
// 401 + reloginRequired so the UI can offer the one-click QR again.
var ErrSessionReloginRequired = errors.New("provider: tuya session expired; a new QR scan is required")

// StartStream turns a Tuya device id into a running HLS stream through the
// existing pipeline. This is the only Tuya-specific step in the seam.
//
// The session is checked BEFORE the stream is registered, and checked again when
// the engine refuses. That order matters and was measured: the Tuya engine will
// happily register a stream whose session is dead and only fail on connect, which
// leaves the HLS watchdog restarting ffmpeg against it forever (MEASURED: a
// cloud-rejected session produced reconnectCount 2->3->4 with ffmpeg respawned
// every ~40s and not one segment). Probing first turns that storm into a single
// clean 401 plus a visible re-login prompt.
func (t *Tuya) StartStream(deviceID string) (*models.StreamInfo, error) {
	if t.bridge == nil {
		return nil, fmt.Errorf("provider: tuya streaming is not configured in this process")
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return nil, fmt.Errorf("provider: tuya device id is required")
	}

	// Liveness checkpoint BEFORE anything is started. The verdict is cached by
	// Session(), so a burst of starts does not become a burst of cloud calls.
	if t.sessionRejected() {
		t.degradeOnSessionLoss(ErrSessionReloginRequired)
		return nil, fmt.Errorf("%w (camera %s): not started", ErrSessionReloginRequired, deviceID)
	}

	spec := tuyaengine.DeviceSpec{
		DeviceID:    deviceID,
		SessionFile: t.sessionFile,
		Resolution:  t.resolution,
		Host:        t.host,
	}
	if t.log != nil {
		// Device id and resolution only: no session file contents, no config.
		t.log.LogInfo("tuya:"+deviceID, "tuya", "starting Tuya stream (resolution="+t.resolution+")")
	}
	info, err := t.bridge.StartStream(spec)
	if err != nil {
		// The engine refused. Re-check liveness so "the credentials are dead" is
		// told apart from "this camera refused", and stand the other streams down
		// only when the cloud actually rejects us. The second probe is
		// deliberately uncached: the session may have died in between.
		if t.probeSessionRejected() {
			t.degradeOnSessionLoss(ErrSessionReloginRequired)
			return nil, fmt.Errorf("%w (camera %s): %v", ErrSessionReloginRequired, deviceID, err)
		}
		return nil, fmt.Errorf("provider: tuya start stream: %w", err)
	}
	if info != nil {
		// The manager already tagged the stream (the bridge's starter does it at
		// creation time). Setting it here too keeps the response honest for any
		// other StreamStarter implementation passed to the bridge.
		info.Provider = KindTuya
	}
	return info, nil
}

// sessionRejected reports whether the stored session is dead, using the cached
// verdict when it is still fresh. This is the cheap gate on the start path.
func (t *Tuya) sessionRejected() bool {
	t.mu.Lock()
	fresh := t.lastCheck != (time.Time{}) && time.Since(t.lastCheck) < t.validateTTL
	rejected := fresh && !t.lastCheckOK
	t.mu.Unlock()
	if fresh {
		return rejected
	}
	return t.probeSessionRejected()
}

// probeSessionRejected always asks the cloud, ignoring the cache. Only a typed
// ErrSessionExpired counts as a rejection: a transport failure must never be
// mistaken for a dead session, or a flaky network would stop every stream.
func (t *Tuya) probeSessionRejected() bool {
	client, err := t.clientFor()
	if err != nil {
		// The session file itself is unusable (missing fast-sid/s-sid, or gone).
		// That is also a "scan a new QR" condition, so it counts.
		return true
	}
	probeCtx, cancel := context.WithTimeout(context.Background(), sessionProbeTimeout)
	defer cancel()
	probeErr := client.Validate(probeCtx)
	t.mu.Lock()
	t.lastCheck = time.Now()
	t.lastCheckOK = probeErr == nil
	if probeErr != nil {
		t.lastErr = probeErr.Error()
	} else {
		t.lastErr = ""
	}
	t.mu.Unlock()
	if probeErr != nil {
		return SessionExpired(probeErr)
	}
	return false
}

// Cameras lists the account's cameras and filters out every non-camera device.
//
// tuyaqr.Cameras already applies IsCamera, but the filter is re-applied here on
// purpose: this provider is the last place before the JSON reaches a browser, and
// the measured account has 5 devices of which 4 are `cz` switches/meters. A
// regression in either layer must not be able to put a smart plug in the camera
// grid.
func (t *Tuya) Cameras(ctx context.Context) ([]Camera, error) {
	client, err := t.clientFor()
	if err != nil {
		return nil, err
	}
	devices, err := client.Cameras(ctx)
	if err != nil {
		return nil, fmt.Errorf("provider: tuya discovery: %w", err)
	}
	out := make([]Camera, 0, len(devices))
	var skipped []string
	for _, d := range devices {
		if !tuyaqr.IsCamera(d.Category) {
			skipped = append(skipped, d.DeviceID)
			continue
		}
		out = append(out, cameraFromTuyaDevice(d))
	}
	if t.log != nil {
		t.log.LogInfo("tuya", "tuya", fmt.Sprintf("discovery: %d camera(s) after filtering, %d non-camera device(s) excluded", len(out), len(skipped)))
	}
	return out, nil
}

// cameraFromTuyaDevice maps a cloud device onto the shared Camera shape. Only
// non-secret fields are copied, so the result can be serialised to the browser.
func cameraFromTuyaDevice(d tuyaqr.Device) Camera {
	detail := "category=" + d.Category
	if d.ProductID != "" {
		detail += " product=" + d.ProductID
	}
	if !d.Online {
		detail += " offline"
	}
	return Camera{
		ID:       d.DeviceID,
		Name:     d.DeviceName,
		Provider: KindTuya,
		Detail:   detail,
		Online:   d.Online,
	}
}

// SessionStatus is the secret-free view of the stored Tuya session that
// GET /api/tuya/session returns. It never carries a cookie value or an sid.
//
// The three questions the UI needs answered are reported SEPARATELY, because
// collapsing them is what made the old response misleading:
//
//	Configured   - is a session file wired up at all?
//	FilePresent  - does that file load and carry fast-sid/s-sid?
//	CloudVerified- did an ACTUAL authenticated call to the cloud just succeed?
//	ExpiryKnown  - did the cloud ever tell us when the cookies expire?
//
// `ExpiryKnown` false is a first-class, honest answer, not an error. The
// user's stored session has ZERO expiry on all four cookies, so no truthful
// countdown exists for it; ExpiresAt and RemainingSeconds are then null/0 and
// ExpirySource says "unknown".
type SessionStatus struct {
	Configured   bool `json:"configured"`
	FilePresent  bool `json:"filePresent"`
	CloudVerified bool `json:"cloudVerified"`
	// Valid is the single boolean the UI gates on. It means "an authenticated
	// call to the cloud just succeeded": file presence alone is NOT validity.
	Valid bool `json:"valid"`

	// ExpiresAt is the cloud-reported cookie deadline, or null when unknown.
	ExpiresAt *time.Time `json:"expiresAt"`
	// RemainingSeconds counts down to ExpiresAt. It is 0 whenever unknown, and
	// deliberately never an estimate.
	RemainingSeconds int `json:"remainingSeconds"`
	// ExpiryKnown is false when no stored cookie declares an expiry. When it is
	// false the UI MUST show "expiry unknown" rather than a countdown.
	ExpiryKnown bool `json:"expiryKnown"`
	// ExpirySource names where ExpiresAt came from, e.g. "cookie:fast-sid", or
	// "unknown". The cookie name makes the claim auditable.
	ExpirySource string `json:"expirySource"`
	// CookiesWithExpiry / CookieCount expose how much of the credential
	// actually carries a declared deadline.
	CookiesWithExpiry int `json:"cookiesWithExpiry"`
	CookieCount       int `json:"cookieCount"`

	LastRefresh *time.Time `json:"lastRefresh,omitempty"`
	// LastCheckedAt is when the cloud was last probed (the cache timestamp).
	LastCheckedAt *time.Time `json:"lastCheckedAt,omitempty"`
	// CheckedSecondsAgo is how stale that probe is, so a cached answer is
	// never presented as a fresh one.
	CheckedSecondsAgo int      `json:"checkedSecondsAgo"`
	CacheTTLSeconds   int      `json:"cacheTtlSeconds"`
	CookieNames       []string `json:"cookieNames,omitempty"`

	// ExpiredStreamsStopped counts streams this provider deliberately stopped
	// because the session died. It is how "stop the bleed" is visible.
	ExpiredStreamsStopped int `json:"expiredStreamsStopped,omitempty"`
	// ReloginRequired is true only when a fresh QR scan is the way out.
	ReloginRequired bool   `json:"reloginRequired"`
	Detail          string `json:"detail,omitempty"`
}

// Session reports whether the stored session still works.
//
// Validity is decided by the cloud (a real authenticated Validate call), because
// the stored cookies carry no Expires timestamp at all — MEASURED on the real
// session file: all 4 cookies have a zero expiry and an empty Domain. So
// `expiresAt` is populated only when a cookie actually declares one, and is null
// otherwise rather than being invented. The result is cached briefly so a
// polling UI cannot hammer the cloud.
//
// When the cloud rejects the session, the session is marked invalid AND every
// Tuya stream is stopped, because an HLS watchdog would otherwise restart ffmpeg
// against a dead source forever.
func (t *Tuya) Session(ctx context.Context) (*SessionStatus, error) {
	if !t.Configured() {
		return &SessionStatus{Configured: false, Detail: "no Tuya session file is configured"}, nil
	}

	t.mu.Lock()
	cached := t.client != nil && t.session != nil && t.lastCheck != (time.Time{}) && time.Since(t.lastCheck) < t.validateTTL
	if cached {
		status := t.statusLocked()
		t.mu.Unlock()
		return status, nil
	}
	t.mu.Unlock()

	client, err := t.clientFor()
	if err != nil {
		t.mu.Lock()
		t.lastCheck = time.Now()
		t.lastCheckOK = false
		t.lastErr = err.Error()
		t.expiryOrigin = ""
		status := t.statusLocked()
		t.mu.Unlock()
		return status, nil
	}
	// RefreshExpiry both checks liveness AND folds any server-reported cookie
	// expiry into the in-memory session, so a session captured before M6 can
	// acquire a real (cloud-stated) countdown without being rewritten on disk.
	validateErr := client.RefreshExpiry(ctx, t.session)

	t.mu.Lock()
	t.lastCheck = time.Now()
	t.lastCheckOK = validateErr == nil
	if validateErr != nil {
		t.lastErr = validateErr.Error()
	} else {
		t.lastErr = ""
	}
	t.refreshExpiryLocked()
	status := t.statusLocked()
	sessionDead := !t.lastCheckOK
	t.mu.Unlock()

	if sessionDead {
		// Degrade visibly and stop the bleed. This is deliberately done
		// outside the lock: stopping a stream joins the ffmpeg process.
		t.degradeOnSessionLoss(validateErr)
		t.mu.Lock()
		status = t.statusLocked()
		t.mu.Unlock()
	}
	return status, nil
}

// refreshExpiryLocked recomputes the reported expiry from the (possibly just
// refreshed) in-memory session. Caller holds t.mu.
func (t *Tuya) refreshExpiryLocked() {
	if t.session == nil {
		t.expiryOrigin = ""
		return
	}
	if _, name, ok := t.session.EarliestCookieExpiry(); ok {
		t.expiryOrigin = "cookie:" + name
		t.expiryUpdatedAt = time.Now()
		return
	}
	// No stored cookie declares an expiry. Say so rather than guessing.
	t.expiryOrigin = ""
}

// degradeOnSessionLoss marks the session dead and stops every Tuya stream.
//
// A dead Tuya session is unrecoverable without a human scan: retrying cannot
// help. Leaving the streams running only makes the HLS watchdog restart ffmpeg
// every hlsStallTimeout against a source that will never produce a frame, which
// is both a reconnect storm in the log and pointless CPU. Stopping them is the
// honest degradation, and it is what makes the one-click recovery cheap.
func (t *Tuya) degradeOnSessionLoss(cause error) {
	t.mu.Lock()
	t.lastCheckOK = false
	if cause != nil {
		t.lastErr = cause.Error()
	}
	stopper := t.stopper
	t.mu.Unlock()

	if stopper == nil {
		return
	}
	const reason = "the Tuya session expired: re-login is required"
	stopped, err := stopper.SuspendStreamsForProvider(models.ProviderTuya, reason)
	t.mu.Lock()
	t.stoppedStreams += stopped
	t.mu.Unlock()
	if stopped > 0 && t.log != nil {
		t.log.LogWarn("tuya", "tuya", fmt.Sprintf(
			"stored Tuya session was rejected by the cloud; stood down %d Tuya stream(s) so the HLS watchdog cannot restart ffmpeg against a dead source", stopped))
	}
	if err != nil && t.log != nil {
		t.log.LogError("tuya", "tuya", fmt.Sprintf("standing down a Tuya stream after session loss failed: %v", err))
	}
}

// SuspendStreams stands down every Tuya stream this process is running, keeping
// their registered state so a later re-login can resume exactly those cameras.
// It is the "stop the bleed" action exposed for a deliberate logout, where the
// credentials are gone by intent rather than by cloud rejection.
func (t *Tuya) SuspendStreams() (int, error) {
	t.mu.Lock()
	stopper := t.stopper
	t.mu.Unlock()
	if stopper == nil {
		return 0, nil
	}
	const reason = "the Tuya session was removed by a local logout: re-login is required"
	n, err := stopper.SuspendStreamsForProvider(models.ProviderTuya, reason)
	if n > 0 {
		t.mu.Lock()
		t.stoppedStreams += n
		t.mu.Unlock()
	}
	return n, err
}

// ResumeStreams re-registers and restarts the Tuya streams that were suspended
// when the session died, using the (new) session file. It is the recovery half
// of the M6 lifecycle: the same cameras come back without the user re-picking
// anything, because the profile tokens — and therefore the devices — were never
// discarded.
//
// It is a no-op when nothing is suspended, so calling it after every successful
// login is safe. Each device is resumed independently: one camera that the cloud
// has taken offline must not prevent the others from coming back.
func (t *Tuya) ResumeStreams(ctx context.Context) (int, []string, error) {
	if t.bridge == nil {
		return 0, nil, fmt.Errorf("provider: tuya streaming is not configured in this process")
	}
	if t.stopper == nil {
		return 0, nil, fmt.Errorf("provider: no stream registry is attached, so suspended streams cannot be resumed")
	}
	suspended := t.stopper.SuspendedStreams(models.ProviderTuya)
	if len(suspended) == 0 {
		return 0, nil, nil
	}
	// The session file has just been replaced by the scan; drop the cached
	// client so the engine and the next probe both read the new credentials.
	t.Invalidate()

	resumed := 0
	var failures []string
	for _, stream := range suspended {
		deviceID := strings.TrimPrefix(stream.ProfileToken, tuyaengine.ProfileTokenPrefix)
		if deviceID == "" || deviceID == stream.ProfileToken {
			failures = append(failures, fmt.Sprintf("%s: not a Tuya profile token", stream.ProfileToken))
			continue
		}
		rtspURL, err := t.bridge.Resolve(deviceID)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", deviceID, err))
			continue
		}
		if _, err := t.stopper.ResumeSuspended(stream.ID, rtspURL, models.ProviderTuya); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", deviceID, err))
			continue
		}
		resumed++
	}
	if resumed > 0 && t.log != nil {
		t.log.LogInfo("tuya", "tuya", fmt.Sprintf("resumed %d Tuya stream(s) after a successful re-login", resumed))
	}
	if len(failures) > 0 {
		return resumed, failures, fmt.Errorf("provider: %d resumed, %d failed", resumed, len(failures))
	}
	return resumed, nil, nil
}

// statusLocked builds the status view. Caller holds t.mu or is single-threaded.
func (t *Tuya) statusLocked() *SessionStatus {
	status := &SessionStatus{
		Configured:      true,
		FilePresent:     t.session != nil,
		CloudVerified:   t.lastCheckOK,
		Valid:           t.session != nil && t.lastCheckOK,
		ExpirySource:    "unknown",
		CacheTTLSeconds: int(t.validateTTL.Seconds()),
	}
	status.ExpiredStreamsStopped = t.stoppedStreams
	if !t.lastCheck.IsZero() {
		checked := t.lastCheck
		status.LastCheckedAt = &checked
		status.CheckedSecondsAgo = int(time.Since(checked).Seconds())
	}
	if t.session != nil {
		status.CookieNames = t.session.CookieNames()
		status.CookieCount = len(status.CookieNames)
		with, total := t.session.CookiesWithExpiry()
		status.CookiesWithExpiry = with
		status.CookieCount = total
		if expiry, name, ok := t.session.EarliestCookieExpiry(); ok {
			status.ExpiresAt = &expiry
			status.ExpiryKnown = true
			status.ExpirySource = "cookie:" + name
			if remaining := time.Until(expiry); remaining > 0 {
				status.RemainingSeconds = int(remaining.Seconds())
			}
		}
		if !t.session.LastRefresh.IsZero() {
			last := t.session.LastRefresh
			status.LastRefresh = &last
		}
	}
	if !t.lastCheckOK {
		status.ReloginRequired = t.session != nil
	}
	return t.buildDetail(status)
}

// buildDetail fills ReloginRequired and Detail from the facts already gathered.
func (t *Tuya) buildDetail(status *SessionStatus) *SessionStatus {
	switch {
	case t.session == nil:
		status.ReloginRequired = true
		status.Detail = "no usable stored session" + detailSuffix(t.lastErr)
	case !t.lastCheckOK:
		status.ReloginRequired = true
		status.Detail = "the stored Tuya session was rejected by the cloud; scan a new QR code"
	default:
		if status.ExpiryKnown {
			status.Detail = "accepted by the cloud; expiry is the cloud-reported cookie deadline"
		} else {
			status.Detail = "accepted by the cloud; the stored cookies declare no expiry, so no countdown can be shown"
		}
	}
	return status
}

// detailSuffix appends a bounded, secret-free reason when there is one.
func detailSuffix(errText string) string {
	if strings.TrimSpace(errText) == "" {
		return ""
	}
	if len(errText) > 160 {
		errText = errText[:160] + "..."
	}
	return ": " + errText
}

// clientFor lazily loads the session file and builds an authenticated client.
// The file is opened read-only and never rewritten here.
func (t *Tuya) clientFor() (TuyaList, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil {
		return t.client, nil
	}
	if !t.Configured() {
		return nil, fmt.Errorf("%w: no Tuya session file configured", ErrUnknownProvider)
	}
	client, session, err := tuyaqr.NewClientForSessionFile(t.sessionFile)
	if err != nil {
		return nil, fmt.Errorf("provider: tuya session: %w", err)
	}
	t.client = client
	t.session = session
	return client, nil
}

// Invalidate drops the cached session and its validation result, so the next
// discovery call reloads the session file. Called after a successful QR scan:
// the file on disk has just been replaced and the cached cookies are stale.
//
// The streaming bridge needs no equivalent: internal/go2rtc reads the session
// file itself on every engine connect.
func (t *Tuya) Invalidate() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.client = nil
	t.session = nil
	t.lastCheck = time.Time{}
	t.lastCheckOK = false
	t.lastErr = ""
}

// SessionExpired reports whether a discovery error means the user must scan a
// new QR code. The HTTP layer uses it to pick a 401 over a 500.
func SessionExpired(err error) bool {
	return errors.Is(err, tuyaqr.ErrSessionExpired) || errors.Is(err, tuyaqr.ErrNoSession)
}
