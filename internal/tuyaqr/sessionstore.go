package tuyaqr

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Store kinds reported by SessionStore.Kind(). They are surfaced verbatim by
// GET /api/tuya/session as `storeKind`, so an operator can always tell WHERE a
// credential is kept without any part of the credential being revealed.
const (
	StoreKindFile   = "file"
	StoreKindSQLite = "sqlite"
	StoreKindMemory = "memory"
)

// Account identifies one Tuya account. A session store is keyed by it so that
// several accounts can coexist; the legacy session file already keyed on
// (region, email) through its file name (user_<region>_<email>.json).
//
// Neither field is a secret: the email is already shown by the UI. Cookie
// values, sids and the session blob are never part of an Account.
type Account struct {
	Region string `json:"region"`
	Email  string `json:"email"`
}

// Normalize trims the fields and lower-cases the email, so an account loaded
// from a file name and one from a session's own JSON body compare equal.
func (a Account) Normalize() Account {
	return Account{
		Region: strings.ToLower(strings.TrimSpace(a.Region)),
		Email:  strings.ToLower(strings.TrimSpace(a.Email)),
	}
}

// IsZero reports whether the account is unset.
func (a Account) IsZero() bool { return a.Normalize() == Account{} }

// Key is a stable, collision-free lookup key for the account. The unit
// separator cannot appear in a region label or an email address, so no pair of
// distinct accounts can share a key.
func (a Account) Key() string {
	n := a.Normalize()
	return n.Region + "\x1f" + n.Email
}

// String renders the account for diagnostics. It is a label, never a secret.
func (a Account) String() string {
	if a.IsZero() {
		return "(no account)"
	}
	return a.Normalize().Region + "/" + a.Normalize().Email
}

// Account returns the account a session belongs to.
func (s *Session) Account() Account {
	if s == nil {
		return Account{}
	}
	region := s.Region
	if strings.TrimSpace(region) == "" {
		region = s.SessionData.Region
	}
	email := s.Email
	if strings.TrimSpace(email) == "" {
		email = s.SessionData.UserEmail
	}
	return Account{Region: region, Email: email}
}

// StoredSession is the secret-free description of one stored session: enough to
// render a session list, and never enough to use the credential.
type StoredSession struct {
	Account     Account   `json:"account"`
	UpdatedAt   time.Time `json:"updatedAt"`
	LastRefresh time.Time `json:"lastRefresh,omitempty"`
	// CookieCount counts stored cookies; HasAuthPair reports whether both
	// fast-sid and s-sid are present and non-empty. Both are booleans/counts.
	CookieCount int  `json:"cookieCount"`
	HasAuthPair bool `json:"hasAuthPair"`
}

// SessionStore is the storage seam for Tuya sessions.
//
// There are two production implementations, and they differ ONLY in where the
// bytes live:
//
//	FileSessionStore   - the legacy 0600 JSON file in a 0700 directory, kept so
//	                     that every existing caller (CLI tools, the RTSP probe
//	                     and serve commands, the tests) keeps working unchanged.
//	SQLiteSessionStore - the project's own onvif_logs.db, so the session shares
//	                     one lifecycle, one backup story and one lock with the
//	                     stream configs and logs it belongs to.
//
// A third, in-memory implementation exists for tests.
//
// Contract, and why each method is shaped the way it is:
//
//   - Load returns an error wrapping ErrNoSession when nothing is stored. It
//     never returns a partially usable session: implementations validate the
//     fast-sid/s-sid pair exactly as LoadSession does.
//   - Save is an upsert keyed by (region, email) and refuses a session that
//     cannot be used, so an unusable credential can never displace a good one.
//   - Delete removes the stored credential. Removing something that is not
//     there is NOT an error: the caller asked for "no session", and that is the
//     state.
//   - Accounts lists what is stored WITHOUT reading any secret, so the HTTP
//     layer can say honestly what is on this host.
//   - Kind/Location describe the backing store in operator terms (a word and a
//     path/table), never a credential.
//   - Materialize returns a filesystem path holding this session, because the
//     vendored go2rtc Tuya driver consumes a session file and nothing else. The
//     file store returns its own path; a store that does not use a file writes
//     a private 0600 copy and returns that. It exists so a database-backed
//     session can still feed the streaming half without the frozen vendored
//     code being touched.
type SessionStore interface {
	Load(a Account) (*Session, error)
	Save(s *Session) error
	Delete(a Account) error
	Accounts() ([]StoredSession, error)
	Kind() string
	Location() string
	Materialize(s *Session) (string, error)
}

// FileSessionStore is the legacy store: one JSON file per account, mode 0600,
// inside a 0700 directory.
//
// It has two modes. With an explicit path it is bound to exactly that file,
// which is what TUYA_ENGINE_SESSION_FILE names and what every pre-existing
// caller passes. With only a directory it is account-keyed, mapping an Account
// onto DefaultSessionPath(dir, region, email) — the same layout
// tuya-ipc-terminal uses.
type FileSessionStore struct {
	dir      string
	override string
}

// NewFileSessionStore returns a store bound to one exact session file path.
func NewFileSessionStore(path string) *FileSessionStore {
	path = strings.TrimSpace(path)
	return &FileSessionStore{dir: filepath.Dir(path), override: path}
}

// NewFileSessionStoreDir returns an account-keyed store rooted at dir.
func NewFileSessionStoreDir(dir string) *FileSessionStore {
	return &FileSessionStore{dir: strings.TrimSpace(dir)}
}

// Kind reports the file store.
func (f *FileSessionStore) Kind() string { return StoreKindFile }

// Location is the directory (or the exact path) sessions live in.
func (f *FileSessionStore) Location() string {
	if f == nil {
		return ""
	}
	if f.override != "" {
		return f.override
	}
	return f.dir
}

// Path returns the exact file path this store uses for an account.
func (f *FileSessionStore) Path(a Account) string {
	if f == nil {
		return ""
	}
	if f.override != "" {
		return f.override
	}
	return DefaultSessionPath(f.dir, a.Region, a.Email)
}

// Override reports the fixed path, or "" for an account-keyed store.
func (f *FileSessionStore) Override() string {
	if f == nil {
		return ""
	}
	return f.override
}

// Load reads the account's session file. The file is opened read-only.
func (f *FileSessionStore) Load(a Account) (*Session, error) {
	if f == nil {
		return nil, ErrNoSession
	}
	path := f.Path(a)
	if path == "" {
		return nil, fmt.Errorf("%w: no session file path configured", ErrNoSession)
	}
	return LoadSession(path)
}

// Save writes the session atomically, mode 0600, inside a 0700 directory.
func (f *FileSessionStore) Save(s *Session) error {
	if f == nil {
		return errors.New("tuyaqr: nil file session store")
	}
	return SaveSession(f.Path(s.Account()), s)
}

// Delete removes the account's session file. An absent file is not an error.
func (f *FileSessionStore) Delete(a Account) error {
	if f == nil {
		return nil
	}
	path := f.Path(a)
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Accounts describes the stored sessions. Each file is read (read-only) so the
// reported numbers are the session's own, never a guess from the file name.
func (f *FileSessionStore) Accounts() ([]StoredSession, error) {
	if f == nil {
		return nil, nil
	}
	paths := []string{}
	if f.override != "" {
		if _, err := os.Stat(f.override); err == nil {
			paths = append(paths, f.override)
		}
	} else {
		matches, err := filepath.Glob(filepath.Join(f.dir, "user_*.json"))
		if err != nil {
			return nil, err
		}
		paths = append(paths, matches...)
	}
	out := make([]StoredSession, 0, len(paths))
	for _, p := range paths {
		s, err := LoadSession(p)
		if err != nil {
			// A file that cannot yield a usable session is still REPORTED:
			// hiding it is how "a file is present" got mistaken for "the
			// session works". It is listed with zero cookies and no auth pair.
			info, statErr := os.Stat(p)
			if statErr != nil {
				continue
			}
			out = append(out, StoredSession{
				Account:   accountFromPath(p),
				UpdatedAt: info.ModTime(),
			})
			continue
		}
		out = append(out, describeSession(s, p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out, nil
}

// Materialize returns the session file itself: the file store's path IS the
// path the engine consumes. It is written first if it is missing or unusable,
// so a caller that has just captured a session can hand the engine a path
// without a second step.
func (f *FileSessionStore) Materialize(s *Session) (string, error) {
	if f == nil {
		return "", ErrNoSession
	}
	path := f.Path(s.Account())
	if path == "" {
		return "", fmt.Errorf("%w: no session file path configured", ErrNoSession)
	}
	if _, err := os.Stat(path); err != nil {
		if err := f.Save(s); err != nil {
			return "", err
		}
	}
	return path, nil
}

// accountFromPath recovers an account label from a conventional session file
// name. Best-effort: it exists so a corrupt file is still listed.
func accountFromPath(path string) Account {
	base := strings.TrimSuffix(filepath.Base(path), ".json")
	if !strings.HasPrefix(base, "user_") {
		return Account{}
	}
	rest := strings.TrimPrefix(base, "user_")
	sep := strings.Index(rest, "_")
	if sep < 0 {
		return Account{}
	}
	region := rest[:sep]
	email := strings.NewReplacer("_at_", "@", "_", ".").Replace(rest[sep+1:])
	return Account{Region: region, Email: email}
}

// describeSession builds the secret-free description of a loaded session.
func describeSession(s *Session, path string) StoredSession {
	d := StoredSession{Account: s.Account(), LastRefresh: s.LastRefresh}
	if path != "" {
		if info, err := os.Stat(path); err == nil {
			d.UpdatedAt = info.ModTime()
		}
	}
	_, total := s.CookiesWithExpiry()
	d.CookieCount = total
	if fast, sid, _ := s.AuthCookieStatus(); fast && sid {
		d.HasAuthPair = true
	}
	return d
}

// MemorySessionStore is a test double: it stores sessions in memory, keyed by
// account, with no filesystem or database involved. It implements the same
// contract, so it can stand in for either production store in tests.
type MemorySessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
	refs     map[string]StoredSession
	// FailSave / FailDelete inject errors for the failure paths.
	FailSave   error
	FailDelete error
}

// NewMemorySessionStore returns an empty in-memory store.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		sessions: map[string]*Session{},
		refs:     map[string]StoredSession{},
	}
}

// Kind reports the memory store.
func (m *MemorySessionStore) Kind() string { return StoreKindMemory }

// Location names the in-memory map.
func (m *MemorySessionStore) Location() string { return "memory" }

// Load returns the stored session for an account.
func (m *MemorySessionStore) Load(a Account) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[a.Key()]
	if !ok {
		return nil, fmt.Errorf("%w: no session stored for %s", ErrNoSession, a)
	}
	return s, nil
}

// Save upserts a session, refusing one that cannot be used.
func (m *MemorySessionStore) Save(s *Session) error {
	if m.FailSave != nil {
		return m.FailSave
	}
	if s == nil {
		return errors.New("tuyaqr: nil session")
	}
	if fast, sid, _ := s.AuthCookieStatus(); !fast || !sid {
		return fmt.Errorf("%w: missing fast-sid/s-sid", ErrNoSession)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := s.Account().Key()
	m.sessions[key] = s
	m.refs[key] = describeSession(s, "")
	return nil
}

// Delete removes a session. An absent session is not an error.
func (m *MemorySessionStore) Delete(a Account) error {
	if m.FailDelete != nil {
		return m.FailDelete
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, a.Key())
	delete(m.refs, a.Key())
	return nil
}

// Accounts lists what is stored.
func (m *MemorySessionStore) Accounts() ([]StoredSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]StoredSession, 0, len(m.refs))
	for _, r := range m.refs {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Account.Key() < out[j].Account.Key() })
	return out, nil
}

// Materialize writes a private 0600 copy in a 0700 directory and returns it.
func (m *MemorySessionStore) Materialize(s *Session) (string, error) {
	if s == nil {
		return "", ErrNoSession
	}
	dir, err := os.MkdirTemp("", "tuya-memory-session")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "session.json")
	if err := SaveSession(path, s); err != nil {
		return "", err
	}
	return path, nil
}

// --- one-time import --------------------------------------------------------

// ImportResult reports what a one-time import of a legacy session file did.
// Every field is a count, a name or a path: no credential value is ever part of
// it, so it is safe to log verbatim.
type ImportResult struct {
	Source        string    `json:"source"`
	Region        string    `json:"region,omitempty"`
	Email         string    `json:"email,omitempty"`
	CookieCount   int       `json:"cookieCount"`
	CookieNames   []string  `json:"cookieNames,omitempty"`
	Imported      bool      `json:"imported"`
	AlreadyStored bool      `json:"alreadyStored"`
	DestKind      string    `json:"destKind"`
	DestLocation  string    `json:"destLocation"`
	ImportedAt    time.Time `json:"importedAt,omitempty"`
	Detail        string    `json:"detail"`
}

// ImportSessionFile copies one legacy JSON session into a store, once.
//
// It is deliberately NON-DESTRUCTIVE and IDEMPOTENT:
//
//   - the source file is only ever READ (os.ReadFile through LoadSession); it is
//     never renamed, truncated or deleted, so an operator can always fall back
//     to the file they had before,
//   - an account that is already in the destination store is SKIPPED rather than
//     overwritten, so the import can never clobber a fresher credential that a
//     later QR scan captured directly into the store,
//   - running it again therefore reports AlreadyStored and changes nothing.
//
// The destination's existing row also wins when the source is a file store that
// is itself the destination: importing a file into the file store that owns it
// is a no-op.
func ImportSessionFile(store SessionStore, srcPath string) (*ImportResult, error) {
	if store == nil {
		return nil, errors.New("tuyaqr: no destination session store")
	}
	srcPath = strings.TrimSpace(srcPath)
	res := &ImportResult{Source: srcPath, DestKind: store.Kind(), DestLocation: store.Location()}
	if srcPath == "" {
		res.Detail = "no import source was configured"
		return res, nil
	}
	if _, err := os.Stat(srcPath); err != nil {
		if os.IsNotExist(err) {
			res.Detail = "no session file exists at the import source"
			return res, nil
		}
		return nil, err
	}
	// A file store whose own path is the source has nothing to import: the
	// session is already exactly where it belongs.
	if fs, ok := store.(*FileSessionStore); ok && fs.Override() == srcPath {
		res.Detail = "the destination is this same file; nothing to import"
		return res, nil
	}
	session, err := LoadSession(srcPath)
	if err != nil {
		return nil, fmt.Errorf("tuyaqr: import source %s: %w", srcPath, err)
	}
	acct := session.Account()
	res.Region = acct.Region
	res.Email = acct.Email
	res.CookieCount = len(session.CookieNames())
	res.CookieNames = session.CookieNames()

	stored, err := store.Accounts()
	if err != nil {
		return nil, err
	}
	for _, s := range stored {
		if s.Account.Key() == acct.Key() {
			res.AlreadyStored = true
			res.Detail = fmt.Sprintf("the %s store already holds this account; the file was left untouched and the stored session was not overwritten", store.Kind())
			return res, nil
		}
	}
	if err := store.Save(session); err != nil {
		return nil, fmt.Errorf("tuyaqr: import into the %s store: %w", store.Kind(), err)
	}
	res.Imported = true
	res.ImportedAt = time.Now()
	res.Detail = fmt.Sprintf("imported %d cookie(s) from the session file into the %s store; the source file was read only", res.CookieCount, store.Kind())
	return res, nil
}
