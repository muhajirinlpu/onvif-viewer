package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/models"
	"dengan.dev/camera-streamer/internal/tuyaengine"
	"dengan.dev/camera-streamer/internal/tuyaqr"
)

// sessionProbeTimeout bounds the liveness probe issued when a stream start fails,
// so a hung cloud cannot make the HTTP request hang with it.
const sessionProbeTimeout = 8 * time.Second

// storeStatusLocked fills the store axes. Caller holds t.mu (or is
// single-threaded), because it reads the provider's cached session.
//
// A store with no explicit reason still gets one: the response must always
// explain where the credential is, and a caller that wired a store directly
// (tests, embedders) must not be able to strip that explanation by omitting it.
func (t *Tuya) storeStatusLocked() (kind, location, reason, fallbackFrom string, modes []tuyaqr.FileMode, accounts []tuyaqr.StoredSession) {
	if t.store == nil {
		return "", "", "", "", nil, nil
	}
	kind = t.store.Kind()
	location = t.store.Location()
	reason = t.storeReason
	fallbackFrom = t.storeFallbackFrom
	if strings.TrimSpace(reason) == "" {
		switch kind {
		case tuyaqr.StoreKindSQLite:
			reason = "the session is kept in the project database " + location
		case tuyaqr.StoreKindFile:
			reason = "the session is kept in the file " + location
		default:
			reason = "the session is kept in a " + kind + " store"
		}
	}
	if s, ok := t.store.(*tuyaqr.SQLiteSessionStore); ok {
		modes = s.ObservedModes()
	}
	if listed, err := t.store.Accounts(); err == nil {
		accounts = listed
	}
	return
}

// TuyaStreaming is the slice of tuyaengine.Bridge this package needs. Declaring
// it here (rather than importing *tuyaengine.Bridge concretely) keeps the Tuya
// provider unit-testable without an engine, while the real bridge satisfies it
// directly.
type TuyaStreaming interface {
	StartStream(spec tuyaengine.DeviceSpec) (*models.StreamInfo, error)
	Resolve(deviceID string) (string, error)
}

// TuyaStreamRegistrar is the ENGINE-REGISTRATION half of the bridge, declared
// separately from TuyaStreaming so the start-up path can only REGISTER a device.
//
// It is deliberately narrower, because the start-up path must be able to do
// exactly one thing and no more:
//
//   - it must NOT call StartStream, which would spawn a SECOND ffmpeg for a
//     camera that is about to be restored;
//   - it must NOT persist anything, because a stream_configs row for this
//     camera already exists (with the empty URL Bug 1 stores) and re-writing it
//     is stream.Manager's job, not this path's.
//
// Registering a device with the engine is what makes the camera's EPHEMERAL
// loopback RTSP URL exist again in this process, which is the precondition for
// stream.Manager.RestoreStreams to resolve it at all.
type TuyaStreamRegistrar interface {
	RegisterStream(spec tuyaengine.DeviceSpec) (rtspURL, profileToken string, err error)
}

// TuyaResolutionStore persists and reads back the per-camera resolution choice.
// It is the *logger.Logger in production; declaring the sliver here keeps the
// provider testable without a database.
//
// Both methods are needed, not just the writer: StartStream must apply the
// STORED value so a camera that was switched to HD comes back on HD after a
// restart without the browser re-sending anything.
type TuyaResolutionStore interface {
	StreamResolution(profileToken string) (string, error)
	SetStreamResolution(profileToken, resolution string) error
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
	store       tuyaqr.SessionStore
	// materialized is the 0600 file the DB store last wrote for the vendored
	// go2rtc driver. It is a path, never a credential.
	materialized string
	resolution   string
	host         string
	// resolutions is the per-camera resolution store. When it is nil the
	// provider keeps the single process-wide default in `resolution`, so an
	// embedder that does not wire persistence still works exactly as before.
	resolutions TuyaResolutionStore

	bridge  TuyaStreaming
	stopper TuyaStreamStopper
	log     TuyaLogger
	// registrar is the engine-registration seam used at start-up. It is a
	// separate (and strictly narrower) capability from bridge: see
	// TuyaStreamRegistrar.
	registrar TuyaStreamRegistrar

	validateTTL time.Duration

	mu          sync.Mutex
	client      TuyaList
	session     *tuyaqr.Session
	lastCheck   time.Time
	lastCheckOK bool
	lastErr     string
	// account is the stored credential this provider has loaded: a label,
	// never a secret.
	account tuyaqr.Account
	// storeReason / storeFallbackFrom explain why this store was chosen and,
	// when non-empty, that a preferred store failed and a fallback was used.
	// They are operator-facing words, never credentials.
	storeReason       string
	storeFallbackFrom string
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

// WithTuyaStreamRegistrar attaches the engine-registration seam used to
// re-register a PERSISTED Tuya camera with the engine at start-up, without
// starting a stream. The real *tuyaengine.Bridge satisfies it.
//
// A nil registrar is the honest answer for an install where Tuya streaming is
// disabled: RegisterStoredDevice then reports that, instead of pretending.
func WithTuyaStreamRegistrar(r TuyaStreamRegistrar) TuyaOption {
	return func(t *Tuya) { t.registrar = r }
}

// WithTuyaResolution overrides the engine stream resolution ("sd" default).
//
// It is now the process-wide DEFAULT, not the answer: once a per-camera store is
// attached, each camera's own stored choice wins, and this value is what a camera
// with no stored choice runs at.
func WithTuyaResolution(r string) TuyaOption { return func(t *Tuya) { t.resolution = r } }

// WithTuyaResolutionStore attaches the per-camera resolution store, so the user's
// sd|hd choice is persisted per device id and survives a restart.
func WithTuyaResolutionStore(s TuyaResolutionStore) TuyaOption {
	return func(t *Tuya) { t.resolutions = s }
}

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
// built from the session store.
func withTuyaLister(l TuyaList, s *tuyaqr.Session) TuyaOption {
	return func(t *Tuya) {
		t.client = l
		t.session = s
		if s != nil {
			t.account = s.Account()
		}
	}
}

// WithTuyaStore attaches the session store the provider reads credentials from.
// This is the seam the database-backed installation uses.
func WithTuyaStore(store tuyaqr.SessionStore) TuyaOption {
	return func(t *Tuya) { t.store = store }
}

// WithTuyaAccount names the account to read when the store holds more than one.
// It is a label (region + email), never a credential. Leaving it empty means
// "the only account in the store", and a store with several accounts then
// answers with an error that names them rather than picking one.
func WithTuyaAccount(a tuyaqr.Account) TuyaOption {
	return func(t *Tuya) { t.account = a.Normalize() }
}

// WithTuyaResolvedStore attaches a store together with the selection decision
// that produced it (store kind, location and the reason for the choice). The
// reason is reported by GET /api/tuya/session so an operator can always see
// where the credential went and why.
func WithTuyaResolvedStore(res *tuyaqr.ResolvedStore) TuyaOption {
	return func(t *Tuya) {
		if res == nil {
			return
		}
		t.store = res.Store
		t.storeReason = res.Reason
		t.storeFallbackFrom = res.FallbackFrom
	}
}

// WithTuyaValidateTTL overrides the session-validation cache window.
func WithTuyaValidateTTL(d time.Duration) TuyaOption { return func(t *Tuya) { t.validateTTL = d } }

// WithTuyaCloudClientForTest injects the discovery/validation client, so a test
// in another package (internal/handlers drives the real HTTP surface) can run
// the whole path without a network round trip.
//
// It injects the CLIENT only, never a session: the session still comes from the
// store, which is the behaviour under test.
func WithTuyaCloudClientForTest(l TuyaList) TuyaOption {
	return func(t *Tuya) { t.client = l }
}

// withTuyaValidateTTL shortens the session-validation cache in tests.
func withTuyaValidateTTL(d time.Duration) TuyaOption { return func(t *Tuya) { t.validateTTL = d } }

// NewTuya builds a Tuya provider over a session store. The path form is kept
// from the file-only era: it builds a file store bound to that exact path, so
// every existing caller - and every test that passes a path - behaves exactly
// as before. Pass WithTuyaStore to use the database instead.
//
// Nothing touches the cloud or the store here: the session is loaded lazily on
// first use so that constructing the provider cannot fail a server start.
func NewTuya(sessionFile string, opts ...TuyaOption) *Tuya {
	t := &Tuya{
		sessionFile: sessionFile,
		resolution:  tuyaengine.DefaultResolution,
		host:        tuyaengine.DefaultTuyaHost,
		validateTTL: 30 * time.Second,
	}
	if strings.TrimSpace(sessionFile) != "" {
		t.store = tuyaqr.NewFileSessionStore(sessionFile)
	}
	for _, fn := range opts {
		fn(t)
	}
	return t
}

// Kind reports Tuya.
func (t *Tuya) Kind() Kind { return KindTuya }

// Store reports the session store in use (nil when none is configured).
func (t *Tuya) Store() tuyaqr.SessionStore { return t.store }

// SessionFile reports a read-only session FILE path, or "" when the store is
// not file-backed. It is kept because tuyaengine takes a path; a database-backed
// store answers with the 0600 materialized copy, never with a database path.
func (t *Tuya) SessionFile() string {
	if t.store == nil {
		return ""
	}
	if t.store.Kind() == tuyaqr.StoreKindFile {
		return t.sessionFile
	}
	return t.materialized
}

// sessionPathForEngine returns the file path the vendored go2rtc driver must be
// given, materializing a private 0600 copy when the store is a database.
func (t *Tuya) sessionPathForEngine(s *tuyaqr.Session) (string, error) {
	if t.store == nil {
		return "", fmt.Errorf("%w: no Tuya session store is configured", tuyaqr.ErrNoSession)
	}
	if s == nil {
		return "", fmt.Errorf("%w: no Tuya session is loaded", tuyaqr.ErrNoSession)
	}
	path, err := t.store.Materialize(s)
	if err != nil {
		return "", err
	}
	t.mu.Lock()
	t.materialized = path
	t.mu.Unlock()
	return path, nil
}

// Configured reports whether a session store is wired up at all.
func (t *Tuya) Configured() bool { return t.store != nil }

// ErrSessionReloginRequired is returned when a Tuya stream cannot be started or
// kept running because the stored session is dead. The HTTP layer maps it to a
// 401 + reloginRequired so the UI can offer the one-click QR again.
var ErrSessionReloginRequired = errors.New("provider: tuya session expired; a new QR scan is required")

// StartStream turns a Tuya device id into a running HLS stream through the
// existing pipeline. This is the only Tuya-specific step in the seam.
//
// It uses the resolution STORED for this camera, falling back to the provider's
// process-wide default (SD). Callers that want to change it call SetResolution
// first, which persists the choice — that is what makes resolution survive a
// restart.
//
// The session is checked BEFORE the stream is registered, and checked again when
// the engine refuses. That order matters and was measured: the Tuya engine will
// happily register a stream whose session is dead and only fail on connect, which
// leaves the HLS watchdog restarting ffmpeg against it forever (MEASURED: a
// cloud-rejected session produced reconnectCount 2->3->4 with ffmpeg respawned
// every ~40s and not one segment). Probing first turns that storm into a single
// clean 401 plus a visible re-login prompt.
func (t *Tuya) StartStream(deviceID string) (*models.StreamInfo, error) {
	return t.StartStreamAt(deviceID, "")
}

// StartStreamAt starts a Tuya stream at an explicit resolution. An empty
// resolution means "the stored one, else the provider default".
//
// An explicit resolution is persisted FIRST, so the stream that starts and the
// row that will restore it can never disagree: a start that fails after
// persisting leaves the camera on the requested resolution, which is the
// user's stated intent and is visible in the UI.
func (t *Tuya) StartStreamAt(deviceID string, resolution string) (*models.StreamInfo, error) {
	if t.bridge == nil {
		return nil, fmt.Errorf("provider: tuya streaming is not configured in this process")
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return nil, fmt.Errorf("provider: tuya device id is required")
	}

	resolved, err := t.resolveStartResolution(deviceID, resolution)
	if err != nil {
		return nil, err
	}

	// Liveness checkpoint BEFORE anything is started. The verdict is cached by
	// Session(), so a burst of starts does not become a burst of cloud calls.
	if t.sessionRejected() {
		t.degradeOnSessionLoss(ErrSessionReloginRequired)
		return nil, fmt.Errorf("%w (camera %s): not started", ErrSessionReloginRequired, deviceID)
	}

	// The engine consumes a session FILE (internal/go2rtc is vendored and
	// frozen), so a database-backed session is materialized as a private 0600
	// copy here and that copy is what the engine reads.
	session, err := t.currentSession()
	if err != nil {
		t.degradeOnSessionLoss(ErrSessionReloginRequired)
		return nil, fmt.Errorf("%w (camera %s): %v", ErrSessionReloginRequired, deviceID, err)
	}
	sessionPath, err := t.sessionPathForEngine(session)
	if err != nil {
		return nil, fmt.Errorf("provider: tuya session is not readable: %w", err)
	}

	spec := tuyaengine.DeviceSpec{
		DeviceID:    deviceID,
		SessionFile: sessionPath,
		Resolution:  resolved,
		Host:        t.host,
	}
	if t.log != nil {
		// Device id and resolution only: no session file contents, no config.
		t.log.LogInfo("tuya:"+deviceID, "tuya", "starting Tuya stream (resolution="+resolved+")")
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
		info.Resolution = resolved
	}
	return info, nil
}

// TuyaRegistrationOutcome explains what RegisterStoredDevice did, WITHOUT an
// error, because "nothing to register" is not a failure of the viewer: an
// install with no session yet, and a camera the engine already serves, are both
// normal.
type TuyaRegistrationOutcome struct {
	// DeviceID is the device this call was about.
	DeviceID string
	// ProfileToken is the namespaced token the stream manager addresses it by.
	ProfileToken string
	// RTSPURL is the live loopback URL the engine serves the device on, when
	// Registered is true. It is engine-allocated and changes every start, which
	// is exactly why it is never persisted.
	RTSPURL string
	// Resolution is what the engine was asked to serve the camera at.
	Resolution string
	// Registered is true only when the engine now serves this device.
	Registered bool
	// SkippedReason is set when Registered is false, and is a full sentence an
	// operator can act on. It is never an empty string in that case.
	SkippedReason string
}

// RegisterStoredDeviceForProfile re-registers a PERSISTED Tuya camera with the
// engine, so that a stream row left by a PREVIOUS run of this process can be
// restored by the current one.
//
// WHY THIS EXISTS (the defect, MEASURED live): a Tuya stream's RTSP URL is a
// loopback address on OUR OWN in-process engine, and that engine binds an
// EPHEMERAL port that changes on every start. So a Tuya stream_configs row is
// stored with an EMPTY url (see stream.Manager.startStreamWithOptions) and
// stream.Manager.RestoreStreams asks the engine for the live address instead of
// replaying a frozen one. But NOTHING used to put the device back into the
// engine at boot, so restore asked the engine about a device it had never heard
// of, correctly reported not-found, and skipped the camera. Net effect: 1 stream
// before a restart, 0 after. This call is the missing half.
//
// It takes the PROFILE TOKEN, not a device id, because the token is the only
// device identifier a stored row carries: the row's profile_token is
// "tuya:<deviceId>" (tuyaengine.ProfileTokenPrefix), so the device id is
// recoverable from the token alone.
//
// It REGISTERS and does nothing else: no stream is started (RestoreStreams will
// start exactly one ffmpeg for it) and nothing is persisted (the row already
// exists, with the empty URL by design).
//
// It never returns an error for an ordinary "cannot register right now"
// condition — no session, camera offline, engine refusal — because a camera that
// is offline must NOT be able to break the viewer's start-up. The caller decides
// what to log; the returned outcome always says what happened and why.
func (t *Tuya) RegisterStoredDeviceForProfile(profileToken string) TuyaRegistrationOutcome {
	outcome := TuyaRegistrationOutcome{ProfileToken: strings.TrimSpace(profileToken)}
	deviceID, ok := storedDeviceID(outcome.ProfileToken)
	if !ok {
		// An ONVIF token can legitimately reach here (the sweep is profile-token
		// driven); it is not an error, it is simply not ours.
		outcome.SkippedReason = "not a Tuya profile token, so there is nothing to register with the Tuya engine"
		return outcome
	}
	outcome.DeviceID = deviceID
	return t.RegisterStoredDevice(deviceID)
}

// RegisterStoredDevice is the device-id form of RegisterStoredDeviceForProfile.
func (t *Tuya) RegisterStoredDevice(deviceID string) TuyaRegistrationOutcome {
	outcome := TuyaRegistrationOutcome{DeviceID: strings.TrimSpace(deviceID)}
	if outcome.DeviceID == "" {
		outcome.SkippedReason = "the stored row names no device, so there is nothing to register"
		return outcome
	}
	token, err := tuyaengine.ProfileTokenFor(outcome.DeviceID)
	if err != nil {
		outcome.SkippedReason = fmt.Sprintf("the stored row names an unusable device id: %v", err)
		return outcome
	}
	outcome.ProfileToken = token

	t.mu.Lock()
	registrar := t.registrar
	t.mu.Unlock()
	if registrar == nil {
		outcome.SkippedReason = "Tuya streaming is not configured in this process, so the engine cannot be given this camera"
		return outcome
	}

	// The engine consumes a session FILE (internal/go2rtc is vendored and
	// frozen); a database-backed session is materialized as a private 0600 copy
	// here and that copy is what the engine reads.
	session, err := t.currentSession()
	if err != nil {
		outcome.SkippedReason = fmt.Sprintf("no Tuya session is available yet (%v), so the engine cannot be given this camera", err)
		return outcome
	}
	sessionPath, err := t.sessionPathForEngine(session)
	if err != nil {
		outcome.SkippedReason = fmt.Sprintf("the stored Tuya session is not readable (%v), so the engine cannot be given this camera", err)
		return outcome
	}

	// An empty request means "the resolution already stored for this camera", so
	// the restore replays the user's own choice. Reading it does not write it.
	resolved, err := t.resolveStartResolution(outcome.DeviceID, "")
	if err != nil {
		outcome.SkippedReason = fmt.Sprintf("the stored resolution could not be resolved: %v", err)
		return outcome
	}
	outcome.Resolution = resolved

	spec := tuyaengine.DeviceSpec{
		DeviceID:    outcome.DeviceID,
		SessionFile: sessionPath,
		Resolution:  resolved,
		Host:        t.host,
	}
	rtspURL, _, err := registrar.RegisterStream(spec)
	if err != nil {
		outcome.SkippedReason = fmt.Sprintf("the Tuya engine would not accept this camera: %v", err)
		return outcome
	}
	if strings.TrimSpace(rtspURL) == "" {
		outcome.SkippedReason = "the Tuya engine registered the camera but reported no RTSP URL for it"
		return outcome
	}
	outcome.RTSPURL = rtspURL
	outcome.Registered = true
	return outcome
}

// storedDeviceID recovers the device id a stored profile token names.
func storedDeviceID(profileToken string) (string, bool) {
	if !tuyaengine.IsTuyaProfileToken(profileToken) {
		return "", false
	}
	deviceID := strings.TrimPrefix(profileToken, tuyaengine.ProfileTokenPrefix)
	if deviceID == "" || deviceID == profileToken {
		return "", false
	}
	return deviceID, true
}

// resolveStartResolution decides which resolution a start should use and, when
// the caller named one explicitly, persists it.
//
// The order is deliberate: the store is consulted for a camera whose choice was
// made in an earlier session, so restarting the server (or re-logging in) brings
// the camera back at the resolution the user picked, while a camera nobody has
// chosen for stays on SD.
func (t *Tuya) resolveStartResolution(deviceID string, requested string) (string, error) {
	t.mu.Lock()
	store := t.resolutions
	fallback := t.resolution
	t.mu.Unlock()
	if fallback == "" {
		fallback = tuyaengine.DefaultResolution
	}
	if store == nil {
		// No persistence wired: honour an explicit request (validated by the
		// engine's own DeviceSpec.Validate) and otherwise keep the default.
		if strings.TrimSpace(requested) == "" {
			return fallback, nil
		}
		return strings.ToLower(strings.TrimSpace(requested)), nil
	}
	token, err := tuyaengine.ProfileTokenFor(deviceID)
	if err != nil {
		return "", fmt.Errorf("provider: %w", err)
	}
	if strings.TrimSpace(requested) != "" {
		if err := store.SetStreamResolution(token, requested); err != nil {
			return "", fmt.Errorf("provider: cannot store the resolution for camera %s: %w", deviceID, err)
		}
		return logger.NormalizeResolution(requested), nil
	}
	stored, err := store.StreamResolution(token)
	if err != nil {
		if t.log != nil {
			t.log.LogWarn("tuya:"+deviceID, "tuya", fmt.Sprintf("could not read the stored resolution (%v); using %s", err, fallback))
		}
		return fallback, nil
	}
	return logger.NormalizeResolution(stored), nil
}

// ResolutionFor reports the resolution a camera would start at right now, and
// whether it differs from the SD default. It is what GET /api/providers/cameras
// uses so the UI can show a camera's stored choice before it is started.
func (t *Tuya) ResolutionFor(deviceID string) (string, error) {
	return t.resolveStartResolution(deviceID, "")
}

// SetResolution persists the resolution for one camera WITHOUT starting it, so
// the UI can record the choice and the next start applies it.
func (t *Tuya) SetResolution(deviceID, resolution string) (string, error) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return "", fmt.Errorf("provider: tuya device id is required")
	}
	if err := logger.ValidateResolution(resolution); err != nil {
		return "", err
	}
	t.mu.Lock()
	store := t.resolutions
	t.mu.Unlock()
	normalized := logger.NormalizeResolution(resolution)
	if store == nil {
		// Nothing to persist, but the process-wide default is still honoured so
		// an embedder without a store sees the choice take effect.
		t.mu.Lock()
		t.resolution = normalized
		t.mu.Unlock()
		return normalized, nil
	}
	token, err := tuyaengine.ProfileTokenFor(deviceID)
	if err != nil {
		return "", fmt.Errorf("provider: %w", err)
	}
	if err := store.SetStreamResolution(token, normalized); err != nil {
		return "", err
	}
	return normalized, nil
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
		cam := cameraFromTuyaDevice(d)
		// The stored resolution is reported per camera so the UI can show the
		// choice before the stream is started. A read failure degrades to the
		// SD default rather than dropping the camera from the list.
		if stored, resErr := t.ResolutionFor(d.DeviceID); resErr == nil {
			cam.Resolution = stored
		} else {
			cam.Resolution = tuyaengine.DefaultResolution
		}
		cam.ResolutionOptions = tuyaengine.Resolutions()
		out = append(out, cam)
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
	Configured    bool `json:"configured"`
	FilePresent   bool `json:"filePresent"`
	CloudVerified bool `json:"cloudVerified"`
	// Valid is the single boolean the UI gates on. It means "an authenticated
	// call to the cloud just succeeded": file presence alone is NOT validity.
	Valid bool `json:"valid"`

	// StoreKind / StoreLocation / StoreReason say WHERE the credential is kept
	// and WHY that choice was made. With the session in the project database
	// these are the honest replacement for "the session file exists", and they
	// are additions: FilePresent still means exactly what it always did, and
	// still reports true when a database-backed session is present, because a
	// stored credential that loads is present whatever the storage medium.
	StoreKind     string `json:"storeKind"`
	StoreLocation string `json:"storeLocation"`
	StoreReason   string `json:"storeReason,omitempty"`
	// StoreFileModes reports the observed permission of the database and its
	// -wal/-shm siblings. It is how the 0600 hardening is verifiable from
	// outside the process instead of being a claim.
	StoreFileModes []tuyaqr.FileMode `json:"storeFileModes,omitempty"`
	// Accounts are the stored accounts, described without any secret. A
	// single-account install has one entry.
	Accounts []tuyaqr.StoredSession `json:"accounts,omitempty"`
	// StoreFallbackFrom is set when the preferred store could not be opened and
	// a fallback was used. Non-empty means "this is the degraded case".
	StoreFallbackFrom string `json:"storeFallbackFrom,omitempty"`
	// Email / Region identify the account whose credential is loaded. They are
	// account labels the UI already showed, not secrets.
	Email  string `json:"email,omitempty"`
	Region string `json:"region,omitempty"`

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
	if validateErr == nil {
		// PERSIST what the cloud just stated. This is the M8 half of the M6
		// expiry work: capturing a deadline is only useful if it survives the
		// process, and with the session in the database the deadline belongs in
		// the same row as the cookies it describes. Nothing is invented - only
		// a value the cloud reported is written - and a store failure is logged
		// rather than hidden, because silently losing the expiry would put the
		// API back to "unknown" with no explanation.
		t.persistSession(t.session)
	}

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
	status.StoreKind, status.StoreLocation, status.StoreReason, status.StoreFallbackFrom,
		status.StoreFileModes, status.Accounts = t.storeStatusLocked()
	status.ExpiredStreamsStopped = t.stoppedStreams
	if !t.lastCheck.IsZero() {
		checked := t.lastCheck
		status.LastCheckedAt = &checked
		status.CheckedSecondsAgo = int(time.Since(checked).Seconds())
	}
	if t.session != nil {
		status.Email = t.session.Account().Normalize().Email
		status.Region = t.session.Account().Normalize().Region
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

// persistSession writes the (possibly just refreshed) session back to the
// store. It is called on the refresh path only, and only when the cloud
// accepted the session, so a credential the cloud rejected can never be
// re-saved.
//
// Failures are logged and swallowed: losing a persisted expiry degrades the
// countdown to "unknown", which is honest, and must not turn a working session
// check into an HTTP 502.
func (t *Tuya) persistSession(s *tuyaqr.Session) {
	if s == nil {
		return
	}
	t.mu.Lock()
	store := t.store
	logger := t.log
	t.mu.Unlock()
	if store == nil {
		return
	}
	if err := store.Save(s); err != nil {
		if logger != nil {
			// The account label and the failure only: never cookie material.
			logger.LogWarn("tuya", "tuya", fmt.Sprintf(
				"the refreshed Tuya session for %s could not be written back to the %s store: %v",
				s.Account(), store.Kind(), err))
		}
		return
	}
	if logger != nil {
		logger.LogInfo("tuya", "tuya", fmt.Sprintf(
			"persisted the cloud-reported Tuya session state for %s into the %s store (%d cookie(s))",
			s.Account(), store.Kind(), len(s.CookieNames())))
	}
}

// clientFor lazily loads the session from the store and builds an authenticated
// client. Nothing is written: the store is only read here.
//
// A client that is already cached does NOT short-circuit the session load. That
// matters because the two are cached separately and an injected client (the test
// seam, and any future caller) arrives with no session behind it; returning early
// there left t.session nil, so the probe ran against nothing, reported
// cloudVerified=true and then reported filePresent=false — a status that claims
// the cloud accepted a credential the process does not hold.
func (t *Tuya) clientFor() (TuyaList, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil && t.session != nil {
		return t.client, nil
	}
	session, err := t.loadSessionLocked()
	if err != nil {
		return nil, fmt.Errorf("provider: tuya session: %w", err)
	}
	t.session = session
	if t.client != nil {
		return t.client, nil
	}
	client, err := tuyaqr.NewClientFromSession(session)
	if err != nil {
		return nil, fmt.Errorf("provider: tuya session: %w", err)
	}
	t.client = client
	return client, nil
}

// loadSessionLocked reads the stored session. Caller holds t.mu.
//
// With no account named it takes the store's single account, so a
// single-account install needs no configuration; a store holding several
// accounts produces an error that NAMES them instead of silently binding a
// stream to whichever credential happened to sort first.
func (t *Tuya) loadSessionLocked() (*tuyaqr.Session, error) {
	if t.store == nil {
		return nil, fmt.Errorf("%w: no Tuya session store is configured", tuyaqr.ErrNoSession)
	}
	account, err := tuyaqr.ResolveAccount(t.store, t.account)
	if err != nil {
		return nil, err
	}
	session, err := t.store.Load(account)
	if err != nil {
		return nil, err
	}
	t.account = account.Normalize()
	return session, nil
}

// currentSession returns the loaded session, loading it if necessary.
func (t *Tuya) currentSession() (*tuyaqr.Session, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.session != nil {
		return t.session, nil
	}
	session, err := t.loadSessionLocked()
	if err != nil {
		return nil, err
	}
	t.session = session
	return session, nil
}

// Invalidate drops the cached session and its validation result, so the next
// discovery call reloads the credential from the store. Called after a
// successful QR scan: the store has just been written and the cached cookies
// are stale.
//
// The streaming bridge needs no equivalent: it is handed the materialized path
// on every start.
func (t *Tuya) Invalidate() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.client = nil
	t.session = nil
	t.lastCheck = time.Time{}
	t.lastCheckOK = false
	t.lastErr = ""
	t.expiryOrigin = ""
}

// SessionExpired reports whether a discovery error means the user must scan a
// new QR code. The HTTP layer uses it to pick a 401 over a 500.
func SessionExpired(err error) bool {
	return errors.Is(err, tuyaqr.ErrSessionExpired) || errors.Is(err, tuyaqr.ErrNoSession)
}
