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

	bridge TuyaStreaming
	log    TuyaLogger

	validateTTL time.Duration

	mu          sync.Mutex
	client      TuyaList
	session     *tuyaqr.Session
	lastCheck   time.Time
	lastCheckOK bool
	lastErr     string
}

// TuyaLogger is the minimal logger surface used for secret-free diagnostics.
type TuyaLogger interface {
	LogInfo(streamID, source, message string)
	LogWarn(streamID, source, message string)
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

// StartStream turns a Tuya device id into a running HLS stream through the
// existing pipeline. This is the only Tuya-specific step in the seam.
func (t *Tuya) StartStream(deviceID string) (*models.StreamInfo, error) {
	if t.bridge == nil {
		return nil, fmt.Errorf("provider: tuya streaming is not configured in this process")
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return nil, fmt.Errorf("provider: tuya device id is required")
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
type SessionStatus struct {
	Configured       bool       `json:"configured"`
	Valid            bool       `json:"valid"`
	ExpiresAt        *time.Time `json:"expiresAt"`
	RemainingSeconds int        `json:"remainingSeconds"`
	LastRefresh      *time.Time `json:"lastRefresh,omitempty"`
	CookieNames      []string   `json:"cookieNames,omitempty"`
	Detail           string     `json:"detail,omitempty"`
}

// Session reports whether the stored session still works.
//
// Validity is decided by the cloud (a real authenticated Validate call), because
// the stored cookies carry no Expires timestamp at all — MEASURED on the real
// session file: all 4 cookies have a zero expiry and an empty Domain. So
// `expiresAt` is populated only when a cookie actually declares one, and is null
// otherwise rather than being invented. The result is cached briefly so a
// polling UI cannot hammer the cloud.
func (t *Tuya) Session(ctx context.Context) (*SessionStatus, error) {
	if !t.Configured() {
		return &SessionStatus{Configured: false, Valid: false, Detail: "no Tuya session file is configured"}, nil
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
		return &SessionStatus{Configured: true, Valid: false, Detail: err.Error()}, nil
	}
	validateErr := client.Validate(ctx)

	t.mu.Lock()
	t.lastCheck = time.Now()
	t.lastCheckOK = validateErr == nil
	if validateErr != nil {
		t.lastErr = validateErr.Error()
	} else {
		t.lastErr = ""
	}
	status := t.statusLocked()
	t.mu.Unlock()
	return status, nil
}

// statusLocked builds the status view. Caller holds t.mu or is single-threaded.
func (t *Tuya) statusLocked() *SessionStatus {
	status := &SessionStatus{
		Configured: true,
		Valid:      t.lastCheckOK,
	}
	if t.session != nil {
		status.CookieNames = t.session.CookieNames()
		if !t.session.LastRefresh.IsZero() {
			last := t.session.LastRefresh
			status.LastRefresh = &last
		}
		if earliest, ok := earliestCookieExpiry(t.session); ok {
			status.ExpiresAt = &earliest
			if remaining := time.Until(earliest); remaining > 0 {
				status.RemainingSeconds = int(remaining.Seconds())
			}
		}
	}
	if t.lastErr != "" {
		status.Detail = "stored session was rejected: a new QR scan is required"
		if !status.Valid {
			status.RemainingSeconds = 0
		}
	}
	if !status.Valid && status.Detail == "" {
		status.Detail = "session is not usable"
	}
	if status.Valid && status.Detail == "" {
		if status.ExpiresAt == nil {
			status.Detail = "accepted by the cloud; the stored cookies declare no expiry"
		} else {
			status.Detail = "accepted by the cloud"
		}
	}
	return status
}

// earliestCookieExpiry returns the soonest non-zero cookie expiry, if any.
func earliestCookieExpiry(s *tuyaqr.Session) (time.Time, bool) {
	if s == nil {
		return time.Time{}, false
	}
	var earliest time.Time
	for _, c := range s.SessionData.Cookies {
		if c == nil || c.Expires.IsZero() {
			continue
		}
		if earliest.IsZero() || c.Expires.Before(earliest) {
			earliest = c.Expires
		}
	}
	if earliest.IsZero() {
		return time.Time{}, false
	}
	return earliest, true
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
