package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"dengan.dev/camera-streamer/internal/tuyaqr"
)

// LoginStatus is the outcome of a single poll.
type LoginStatus string

const (
	// StatusPending means the QR has not been scanned yet.
	StatusPending LoginStatus = "pending"
	// StatusDone means the scan completed and a session was captured.
	StatusDone LoginStatus = "done"
	// StatusExpired means the token is dead and a NEW QR must be shown. The UI
	// must treat this as terminal for the current token.
	StatusExpired LoginStatus = "expired"
)

// LoginTicket is one QR handshake, shaped for the browser.
type LoginTicket struct {
	// Token is the QR login token. It is returned to the browser because the
	// poll needs it, and is never logged.
	Token            string    `json:"token"`
	QRPNGDataURL     string    `json:"qrPng"`
	ExpiresAt        time.Time `json:"expiresAt"`
	RemainingSeconds int       `json:"remainingSeconds"`
	TTLSeconds       int       `json:"ttlSeconds"`
	Host             string    `json:"host"`
}

// PollResult is the poll response. Session is set only on StatusDone.
type PollResult struct {
	Status           LoginStatus `json:"status"`
	RemainingSeconds int         `json:"remainingSeconds"`
	Session          *Session    `json:"session,omitempty"`
	// ResumedStreams is how many Tuya streams came back automatically after a
	// successful scan, with no device re-selected. This is the observable proof
	// of the one-click recovery path.
	ResumedStreams int `json:"resumedStreams,omitempty"`
	// ResumeFailures names the devices whose streams could not be restarted
	// (device ids only: never a credential).
	ResumeFailures []string `json:"resumeFailures,omitempty"`
}

// Session is the secret-free summary of a freshly captured login.
type Session struct {
	Email       string   `json:"email"`
	Region      string   `json:"region"`
	CookieNames []string `json:"cookieNames"`
	CookieCount int      `json:"cookieCount"`
	SavedAt     string   `json:"savedTo"`
	// StoreKind names the store the session was persisted into (file|sqlite),
	// so the response says WHERE the credential went rather than implying a
	// file that no longer exists.
	StoreKind string `json:"storeKind,omitempty"`
}

// LoginClient is the slice of *tuyaqr.Client the QR handshake needs. Declaring
// it as an interface keeps the state machine testable without touching the
// network, while the real client satisfies it directly.
type LoginClient interface {
	BeginLoginSession(ctx context.Context) (*tuyaqr.Login, error)
	PollLogin(ctx context.Context, login *tuyaqr.Login) (*tuyaqr.Session, bool, error)
}

// LoginManager owns the in-flight QR handshakes for the process.
//
// A handshake is stateful across two HTTP requests (begin -> poll poll poll),
// so the state cannot live in a handler closure. It lives here, keyed by token,
// and expires on its own: a token nobody scans must not leak a map entry.
type LoginManager struct {
	host         string
	sessionFile  string
	store        tuyaqr.SessionStore
	save         func(path string, s *tuyaqr.Session) error
	saveInjected bool
	newClient    func() LoginClient
	onSession    func(*tuyaqr.Session)
	now          func() time.Time

	mu      sync.Mutex
	pending map[string]*pendingLogin
	// lastSaved is the secret-free description of the last session persisted by
	// this manager, so the poll response can say WHERE it went.
	lastSaved StoredSessionRef
}

// StoredSessionRef is the secret-free description of a persisted session: the
// store kind, its location and the account label. No credential material.
type StoredSessionRef struct {
	Kind     string `json:"kind"`
	Location string `json:"location"`
	Account  string `json:"account,omitempty"`
}

type pendingLogin struct {
	login  *tuyaqr.Login
	client LoginClient
}

// LoginOption configures a LoginManager.
type LoginOption func(*LoginManager)

// WithLoginSessionFile is where a completed scan is persisted. Empty disables
// persistence (useful for tests). When no store is attached it also builds the
// file store this path names, so the pre-milestone behaviour is byte for byte
// what it was.
func WithLoginSessionFile(path string) LoginOption {
	return func(m *LoginManager) {
		m.sessionFile = path
		if m.store == nil && strings.TrimSpace(path) != "" {
			m.store = tuyaqr.NewFileSessionStore(path)
		}
	}
}

// WithLoginStore is where a completed scan is persisted. It replaces the file
// store, so the QR flow writes straight into the project database and the
// login path never needs a file at all.
func WithLoginStore(store tuyaqr.SessionStore) LoginOption {
	return func(m *LoginManager) { m.store = store }
}

// WithLoginHost overrides the Tuya region host.
func WithLoginHost(host string) LoginOption {
	return func(m *LoginManager) { m.host = host }
}

// WithLoginSessionSink is notified when a session is captured, so the
// discovery provider can start using it immediately without a restart.
func WithLoginSessionSink(fn func(*tuyaqr.Session)) LoginOption {
	return func(m *LoginManager) { m.onSession = fn }
}

// WithLoginClientFactory replaces the anonymous client factory (tests). Setting
// it disables the default host-pinned factory.
func WithLoginClientFactory(fn func() LoginClient) LoginOption {
	return func(m *LoginManager) { m.newClient = fn }
}

// WithLoginSaver replaces the persistence function (tests). Injecting one makes
// it authoritative: the store is then used only for listing and deletion, so a
// test can observe exactly what was persisted without a filesystem or database.
func WithLoginSaver(fn func(path string, s *tuyaqr.Session) error) LoginOption {
	return func(m *LoginManager) {
		m.save = fn
		m.saveInjected = true
	}
}

// WithLoginClock replaces the clock (tests).
func WithLoginClock(fn func() time.Time) LoginOption { return func(m *LoginManager) { m.now = fn } }

// NewLoginManager builds a QR login manager for a Tuya host.
func NewLoginManager(opts ...LoginOption) *LoginManager {
	m := &LoginManager{
		host:    tuyaqr.DefaultHost,
		pending: map[string]*pendingLogin{},
		now:     time.Now,
		save:    tuyaqr.SaveSession,
	}
	for _, fn := range opts {
		fn(m)
	}
	// Unless a factory was injected (tests), every handshake client is pinned
	// to the configured host. This is done after the options are applied so
	// WithLoginHost actually takes effect.
	if m.newClient == nil {
		host := strings.TrimSpace(m.host)
		m.newClient = func() LoginClient {
			if host == "" {
				return tuyaqr.NewClient()
			}
			return tuyaqr.NewClient(tuyaqr.WithHost(host))
		}
	}
	return m
}

// Begin requests a fresh QR token and returns it rendered as a PNG data URL.
//
// Nothing is persisted here: only a completed scan writes the session file, so
// merely opening the Tuya tab can never disturb a working stored session.
func (m *LoginManager) Begin(ctx context.Context) (*LoginTicket, error) {
	client := m.newClient()
	login, err := client.BeginLoginSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("provider: tuya QR login: %w", err)
	}
	png, err := tuyaqr.RenderQRPNG(login.Payload, tuyaqr.QRImageSize)
	if err != nil {
		return nil, fmt.Errorf("provider: render QR: %w", err)
	}

	m.mu.Lock()
	m.pruneLocked()
	m.pending[login.Token] = &pendingLogin{login: login, client: client}
	m.mu.Unlock()

	remaining := int(login.Remaining().Seconds())
	return &LoginTicket{
		Token:            login.Token,
		QRPNGDataURL:     "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
		ExpiresAt:        login.ExpiresAt,
		RemainingSeconds: remaining,
		TTLSeconds:       int(tuyaqr.TokenTTL.Seconds()),
		Host:             login.Host,
	}, nil
}

// Poll performs ONE poll for a token. It never blocks: the browser drives the
// cadence, which is what lets the UI render a live countdown.
func (m *LoginManager) Poll(ctx context.Context, token string) (*PollResult, error) {
	m.mu.Lock()
	entry, ok := m.pending[token]
	if !ok {
		m.mu.Unlock()
		return nil, ErrLoginUnknown
	}
	if entry.login.Expired() {
		delete(m.pending, token)
		m.mu.Unlock()
		return &PollResult{Status: StatusExpired}, nil
	}
	client := entry.client
	login := entry.login
	m.mu.Unlock()

	session, done, err := client.PollLogin(ctx, login)
	if err != nil {
		switch {
		case errors.Is(err, tuyaqr.ErrQRExpired), errors.Is(err, tuyaqr.ErrQRScanned):
			m.mu.Lock()
			delete(m.pending, token)
			m.mu.Unlock()
			return &PollResult{Status: StatusExpired}, nil
		default:
			return nil, fmt.Errorf("provider: tuya poll: %w", err)
		}
	}
	if !done || session == nil {
		return &PollResult{Status: StatusPending, RemainingSeconds: int(login.Remaining().Seconds())}, nil
	}

	// The scan succeeded. Persist the session BEFORE anything else can consume
	// it, then drop the handshake: a token is single-use.
	var saveErr error
	var ref StoredSessionRef
	switch {
	case m.saveInjected && strings.TrimSpace(m.sessionFile) != "":
		// A test injected the persistence function: it is authoritative, and the
		// store is only consulted for listing and deletion.
		saveErr = m.save(m.sessionFile, session)
		ref = StoredSessionRef{Kind: tuyaqr.StoreKindFile, Location: m.sessionFile, Account: session.Account().String()}
	case m.store != nil:
		// The store is authoritative. With the database store this writes
		// straight into onvif_logs.db and no session FILE exists at all.
		saveErr = m.store.Save(session)
		ref = StoredSessionRef{Kind: m.store.Kind(), Location: m.store.Location(), Account: session.Account().String()}
	case strings.TrimSpace(m.sessionFile) != "":
		// Legacy path: a manager built with an explicit path but no store.
		saveErr = m.save(m.sessionFile, session)
		ref = StoredSessionRef{Kind: tuyaqr.StoreKindFile, Location: m.sessionFile, Account: session.Account().String()}
	}
	m.mu.Lock()
	m.lastSaved = ref
	delete(m.pending, token)
	m.mu.Unlock()

	if m.onSession != nil {
		m.onSession(session)
	}

	summary := &Session{
		Email:       session.Email,
		Region:      session.Region,
		CookieNames: session.CookieNames(),
		CookieCount: len(session.CookieNames()),
	}
	if saveErr != nil {
		return nil, fmt.Errorf("provider: tuya session could not be saved: %w", saveErr)
	}
	summary.SavedAt = ref.Location
	summary.StoreKind = ref.Kind
	return &PollResult{Status: StatusDone, Session: summary}, nil
}

// Logout removes the stored session locally.
//
// HONEST NOTE: the Tuya protect cloud exposes NO server-side logout endpoint for
// these cookies — there is no call that invalidates a fast-sid/s-sid pair. So
// this is LOCAL credential removal and nothing else: the credential is gone from
// this host, but the cookies themselves would still be accepted by the cloud
// until they expire. That is why the UI words it as "sign out on this device"
// rather than pretending the session was revoked server-side.
//
// The removal goes through the store, so a database-backed install deletes the
// ROW (and secure_delete zeroes the blob) while a file-backed install removes
// the file. An already-absent session is not an error: the caller asked for "no
// session", and that is the state.
func (m *LoginManager) Logout() (removed bool, err error) {
	m.mu.Lock()
	// In-flight handshakes belong to the old account; drop them so a scan
	// started before the logout cannot resurrect it.
	m.pending = map[string]*pendingLogin{}
	m.lastSaved = StoredSessionRef{}
	store := m.store
	filePath := m.sessionFile
	m.mu.Unlock()

	if store == nil && strings.TrimSpace(filePath) == "" {
		return false, nil
	}
	if store == nil {
		// Legacy path with no store attached: behave exactly as before.
		if _, statErr := os.Stat(filePath); statErr != nil {
			if os.IsNotExist(statErr) {
				return false, nil
			}
			return false, statErr
		}
		if err := os.Remove(filePath); err != nil {
			return false, err
		}
		return true, nil
	}

	// Every account the store holds must go: the user asked for no session on
	// this device, and for a single-account install that is exactly one row.
	stored, listErr := store.Accounts()
	if listErr != nil {
		return false, listErr
	}
	existed := false
	for _, s := range stored {
		acct := s.Account
		if acct.IsZero() {
			continue
		}
		existed = true
		if err := store.Delete(acct); err != nil {
			return false, err
		}
	}
	// A file-backed store whose file did not parse still needs the removal.
	if !existed {
		if fs, ok := store.(*tuyaqr.FileSessionStore); ok {
			path := fs.Path(tuyaqr.Account{})
			if _, statErr := os.Stat(path); statErr == nil {
				if err := fs.Delete(tuyaqr.Account{}); err != nil {
					return false, err
				}
				existed = true
			}
		}
	}
	return existed, nil
}

// SessionFilePath reports where a captured session is persisted (diagnostics).
// With a database store this is the database path, never a credential.
func (m *LoginManager) SessionFilePath() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.store != nil {
		return m.store.Location()
	}
	return m.sessionFile
}

// StoreKind names the store a captured session is written to (diagnostics).
func (m *LoginManager) StoreKind() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.store != nil {
		return m.store.Kind()
	}
	if strings.TrimSpace(m.sessionFile) != "" {
		return tuyaqr.StoreKindFile
	}
	return ""
}

// LastSaved describes the last session this manager persisted, in secret-free
// terms.
func (m *LoginManager) LastSaved() StoredSessionRef {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastSaved
}

// Pending reports how many handshakes are alive (diagnostics only).
func (m *LoginManager) Pending() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked()
	return len(m.pending)
}

// pruneLocked drops tokens that are past their life. Caller holds m.mu.
func (m *LoginManager) pruneLocked() {
	for token, entry := range m.pending {
		if entry.login.Expired() {
			delete(m.pending, token)
		}
	}
}

// ErrLoginUnknown means the token is not (or no longer) held by this process,
// typically because it expired or the process restarted. The UI must show a
// fresh QR.
var ErrLoginUnknown = errors.New("provider: unknown or expired QR login token")
