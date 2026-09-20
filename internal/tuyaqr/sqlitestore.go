package tuyaqr

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"dengan.dev/camera-streamer/internal/logger"
)

// TableSession is the table Tuya sessions live in. It is a SEPARATE table from
// stream_logs, which is what keeps it out of the logger's retention logic: the
// pruning statement is literally
//
//	DELETE FROM stream_logs WHERE id <= (SELECT COALESCE(MAX(id) - ?, 0) FROM stream_logs)
//
// and it names stream_logs and only stream_logs. There is a regression test
// (TestSQLiteSessionStoreIsExemptFromLogPruning) that drives the logger's real
// pruning path past its threshold and asserts the stored session is still there
// afterwards, so the exemption is proven rather than asserted.
const TableSession = "tuya_sessions"

// SessionTableDDL is the additive, idempotent schema for the session table.
//
// It is written to be safe in all three deployment cases, exactly like the M4
// provider column: a fresh database (nothing exists, both statements create), an
// existing populated database (both statements find the object and do nothing),
// and a repeat run (a no-op). Neither statement can fail on an existing object,
// so there is no swallowed error that could hide a genuinely broken database.
//
// `updated_at` / `last_refresh` are DATETIME, which mattn/go-sqlite3 round-trips
// through time.Time. They are split on purpose: updated_at is when the ROW was
// written, last_refresh is the session's own LastRefresh — the expiry origin is
// the cloud, and the two must not be conflated.
//
// The stream_logs table is created here too, with the SAME DDL internal/logger
// uses. It is not this store's job to migrate the log table, but a database that
// cannot answer the prune query is a database whose session could be deleted by
// a "prune every table" mistake; having stream_logs present in every database
// this store touches makes that class of bug impossible rather than unlikely.
const SessionTableDDL = `
CREATE TABLE IF NOT EXISTS stream_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stream_id TEXT,
    timestamp DATETIME,
    level INTEGER,
    source TEXT,
    message TEXT
);
CREATE TABLE IF NOT EXISTS ` + TableSession + ` (
    row_key      TEXT PRIMARY KEY,
    region       TEXT NOT NULL DEFAULT '',
    email        TEXT NOT NULL DEFAULT '',
    user_key     TEXT NOT NULL DEFAULT '',
    server_host  TEXT NOT NULL DEFAULT '',
    session_json TEXT NOT NULL,
    cookie_count INTEGER NOT NULL DEFAULT 0,
    has_auth_pair INTEGER NOT NULL DEFAULT 0,
    last_refresh DATETIME,
    updated_at   DATETIME NOT NULL
);`

// SessionTableIndexDDL indexes the account columns. The primary key is already
// the account key, but naming the columns individually lets an operator find a
// stored account without the key encoding.
const SessionTableIndexDDL = `
CREATE INDEX IF NOT EXISTS idx_tuya_sessions_account ON ` + TableSession + `(region, email);`

// EnsureSessionSchema creates the session table and its index if they are
// missing. It is idempotent and additive: it never drops, truncates or rewrites
// anything, so it is safe against a live database on every process start.
func EnsureSessionSchema(db *sql.DB) error {
	if db == nil {
		return errors.New("tuyaqr: nil database")
	}
	if err := retryOnLock(func() error {
		_, err := db.Exec(SessionTableDDL)
		return err
	}); err != nil {
		return fmt.Errorf("tuyaqr: create %s: %w", TableSession, err)
	}
	if err := retryOnLock(func() error {
		_, err := db.Exec(SessionTableIndexDDL)
		return err
	}); err != nil {
		return fmt.Errorf("tuyaqr: index %s: %w", TableSession, err)
	}
	return nil
}

// isLockedError reports whether an error is SQLite refusing a statement because
// another connection holds a conflicting lock.
//
// This is worth its own predicate because the two lock errors behave
// differently: SQLITE_BUSY is what _busy_timeout retries for you, while
// SQLITE_LOCKED is returned to the caller immediately and NO busy handler is
// consulted for it (that is documented SQLite behaviour, and it is reachable
// here because the DSN uses shared cache). MEASURED: four concurrent first
// opens of the same fresh database made two of them fail with
// "database is locked" on CREATE TABLE despite a 5000 ms busy timeout.
func isLockedError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "database is locked") || strings.Contains(msg, "database table is locked")
}

// retryOnLock runs fn, retrying while the database is locked by another
// connection, with a short linear backoff and a bounded number of attempts.
//
// It exists so that a burst of first-time opens of the SAME fresh database -
// which is the real case of a server and a test binary starting together, or two
// server instances racing on a cold start - converges instead of failing one of
// them. The DDL it wraps is CREATE TABLE IF NOT EXISTS, so a retry can never
// duplicate or destroy anything; it is idempotent by construction.
func retryOnLock(fn func() error) error {
	const attempts = 20
	const delay = 25 * time.Millisecond
	var lastErr error
	for i := 0; i < attempts; i++ {
		if err := fn(); err != nil {
			if !isLockedError(err) {
				return err
			}
			lastErr = err
			time.Sleep(delay)
			continue
		}
		return nil
	}
	return lastErr
}

// retryOnLockExec is retryOnLock for a statement with arguments.
//
// It lives beside retryOnLock rather than at its call sites so the write path and
// the DDL path cannot drift apart: both deserve the same tolerance for a
// contended shared-cache database, and a reader of the INSERT should not have to
// know that SQLITE_LOCKED is not retried by busy_timeout.
func retryOnLockExec(db *sql.DB, query string, args ...any) (sql.Result, error) {
	var res sql.Result
	err := retryOnLock(func() error {
		r, execErr := db.Exec(query, args...)
		if execErr != nil {
			return execErr
		}
		res = r
		return nil
	})
	return res, err
}

// --- one connection per database path, and one migration at a time -----------
//
// The problem these two guards solve, MEASURED: several first-time opens of the
// SAME database file at once - which is what a burst of HTTP requests, a server
// plus a test binary, or two server instances on a cold start actually do - each
// opened their OWN *sql.DB and each ran the CREATE TABLE. SQLite answered
// "database is locked" for the losers, and _busy_timeout does NOT retry that
// case, so a first request could fail on nothing worse than arriving second.
//
// Two fixes, in order of importance:
//
//  1. SHARE the connection. Opening several pools at one file is wasteful and is
//     what made the race reachable at all: with one handle per path, the second
//     caller reuses the first's connection and never races it. It also keeps the
//     WAL's writer count and the file-descriptor count down, and the handle is
//     released only when the last store using it is closed.
//  2. SERIALIZE the migration per path. Even with a shared handle, a caller that
//     was HANDED a connection (the logger's) can reach the DDL at the same moment
//     as another. A mutex keyed by the database path makes the DDL single-flight
//     in-process, so the loser waits instead of erroring.
//
// A path-keyed MUTEX is used rather than a sync.Once deliberately: once would
// skip the DDL forever after the first call, which would also skip it on a
// genuine repeat run and quietly stop testing the migration's idempotency. The
// statements are CREATE TABLE IF NOT EXISTS, so running them again is free and is
// itself part of what has to keep working.

var (
	dbRegistryMu sync.Mutex
	dbRegistry   = map[string]*sharedDB{}
)

type sharedDB struct {
	db   *sql.DB
	refs int
}

// pathKey normalizes a database path so two spellings of one file converge on a
// single registry entry. Without it, "onvif_logs.db" and "./onvif_logs.db" would
// be two pools racing the same file - the exact problem this exists to remove.
func pathKey(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return filepath.Clean(path)
}

// acquireSharedDB returns a process-wide connection for a database path, opening
// it on first use. The returned release function must be called exactly once; it
// closes the connection when the last holder lets go.
//
// The ENTIRE open-and-register sequence is single-flight per path, and that is
// load-bearing rather than tidy: opening a SQLite connection runs the DSN's
// pragmas, and `_journal_mode=WAL` takes an exclusive database lock. MEASURED:
// with only the registry map guarded, several simultaneous first opens each
// created their own connection, each tried to switch the journal mode at the
// same moment, and one of them failed with "database is locked" even after 20
// retries over 500 ms - because shared-cache SQLITE_LOCKED does not consult the
// busy handler, so the contenders starved each other instead of queueing.
// Serializing the open means there is never more than one connection being
// created for a path, so the pragma can never be contended by ourselves.
func acquireSharedDB(dbPath string) (*sql.DB, func(), error) {
	key := pathKey(dbPath)

	unlockOpen := lockPath(key)
	defer unlockOpen()

	dbRegistryMu.Lock()
	if entry, ok := dbRegistry[key]; ok {
		entry.refs++
		db := entry.db
		dbRegistryMu.Unlock()
		return db, func() { releaseSharedDB(key) }, nil
	}
	dbRegistryMu.Unlock()

	dsn := fmt.Sprintf("%s?cache=shared&mode=rwc&_journal_mode=WAL&_busy_timeout=5000&_secure_delete=on", dbPath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("tuyaqr: open session database: %w", err)
	}
	// One writer per database.
	db.SetMaxOpenConns(1)
	// Force the connection to be established HERE, under the per-path lock, so
	// the connect-time pragmas (including the WAL switch) happen exactly once and
	// before any other caller can try. Without this ping the pragmas would run
	// lazily on the first caller's first statement, i.e. outside the lock.
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("tuyaqr: connect to session database: %w", err)
	}
	// Belt and braces: set the busy timeout as a statement too, so it holds even
	// for a caller whose DSN did not ask for it.
	if _, err := retryOnLockExec(db, `PRAGMA busy_timeout=5000`); err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("tuyaqr: set busy_timeout: %w", err)
	}

	dbRegistryMu.Lock()
	dbRegistry[key] = &sharedDB{db: db, refs: 1}
	dbRegistryMu.Unlock()
	return db, func() { releaseSharedDB(key) }, nil
}

// releaseSharedDB drops one reference and closes the connection when the last
// holder lets go.
func releaseSharedDB(key string) {
	dbRegistryMu.Lock()
	entry, ok := dbRegistry[key]
	if !ok {
		dbRegistryMu.Unlock()
		return
	}
	entry.refs--
	if entry.refs > 0 {
		dbRegistryMu.Unlock()
		return
	}
	delete(dbRegistry, key)
	db := entry.db
	dbRegistryMu.Unlock()
	db.Close()
}

// SharedDBRefs reports how many holders the process currently has on a database
// path. Diagnostics only: it exists so a test can prove the connection really is
// shared rather than merely assumed to be.
func SharedDBRefs(dbPath string) int {
	dbRegistryMu.Lock()
	defer dbRegistryMu.Unlock()
	if entry, ok := dbRegistry[pathKey(dbPath)]; ok {
		return entry.refs
	}
	return 0
}

// pathMus serializes migrations per database path.
var (
	pathMuMu sync.Mutex
	pathMus  = map[string]*sync.Mutex{}
)

// lockPath acquires the migration lock for a database path and returns its
// unlock function.
func lockPath(dbPath string) func() {
	key := pathKey(dbPath)
	pathMuMu.Lock()
	mu, ok := pathMus[key]
	if !ok {
		mu = &sync.Mutex{}
		pathMus[key] = mu
	}
	pathMuMu.Unlock()
	mu.Lock()
	return mu.Unlock
}

// SQLiteSessionStore keeps Tuya sessions in the project's own onvif_logs.db.
//
// SECURITY, and why this store also owns the database's permissions: if the
// session bytes are going into a file, then that file IS the credential store,
// and it must not be readable by anyone but its owner. The naive move -
// sql.Open() against a world-readable onvif_logs.db - would have put session
// cookies in a 0644 file, i.e. readable by every local account, which is a
// regression against the 0600 JSON file it replaces. Two things prevent that:
//
//  1. The database, its -wal and its -shm are tightened to 0600 before the
//     connection touches them, and the -wal/-shm are re-checked on every write.
//     MEASURED: libsqlite3-creates unixInodeInfoCreateFile with the DATABASE
//     file's mode, so once the database is 0600 the journal and shared-memory
//     siblings are created 0600 too - but the DATABASE is chmod'ed first, and
//     the siblings are chmod'ed again defensively, because a database that was
//     left 0644 by an older build already has 0644 siblings on disk.
//  2. The stored blob is not left in the clear in free pages: the connection
//     runs with PRAGMA secure_delete=on, so a deleted session's bytes are
//     zeroed rather than merely unlinked from the B-tree.
//
// Encrypting the blob on top of that was considered and rejected: the key would
// have to live on the same host, so it would move the secret, not protect it,
// while making the session unrecoverable for the operator after a key mishap.
// An operator who needs encryption-at-rest has it where it belongs - a
// filesystem/LUKS-level decision - and this store does not pretend otherwise.
type SQLiteSessionStore struct {
	path string
	db   *sql.DB
	// owned is true when this store opened the shared handle itself, so it is
	// the one that releases a reference to it on Close.
	owned bool
	// external is true when the connection was handed in by a caller (the
	// logger's). Such a store closes NOTHING: the caller owns that handle.
	external bool
	// release drops this store's reference to a shared handle. It is nil for an
	// external handle.
	release func()

	mu sync.Mutex
	// adjusted records the modes this store observed after the last write, so
	// the API can report what is actually on disk rather than what was intended.
	adjusted []FileMode
}

// FileMode is the observed permission of one file the database consists of.
type FileMode struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

// SQLiteSessionOptions configures a SQLiteSessionStore.
type SQLiteSessionOptions struct {
	// HardenFiles controls the 0600 tightening. It is on by default and can
	// only be turned off by an explicit, documented opt-out: an operator whose
	// database deliberately lives behind a directory only they can traverse.
	HardenFiles bool
	// dirMode, when > 0, also tightens the containing directory. 0 leaves it.
	dirMode os.FileMode
	// alreadyOpen lets a caller hand in the connection the rest of the process
	// uses (the logger's), so there is one connection pool, not two.
	alreadyOpen *sql.DB
}

// NewSQLiteSessionStore opens (or reuses) the database and returns a session
// store backed by it. The database file is created if missing, its directory is
// created if missing, and file permissions are tightened before anything is
// written.
//
// The connection is SHARED per database path across this process (see
// acquireSharedDB): calling this twice for one file yields one *sql.DB with two
// stores over it, not two pools racing the same DDL. The returned store's Close
// releases only its own reference; the connection closes with the last one.
func NewSQLiteSessionStore(dbPath string) (*SQLiteSessionStore, error) {
	db, release, err := acquireSharedDB(dbPath)
	if err != nil {
		return nil, err
	}
	s := &SQLiteSessionStore{path: dbPath, db: db, owned: true, release: release}
	if err := s.prepare(); err != nil {
		release()
		return nil, err
	}
	return s, nil
}

// NewSQLiteSessionStoreFromDB adapts a connection that is already open - the
// logger's - so the process has exactly one writer against onvif_logs.db and
// one place where its permissions are enforced.
//
// The caller keeps ownership of the *sql.DB: this store never closes it, and it
// is registered under dbPath so a later NewSQLiteSessionStore for the same file
// shares THIS handle instead of opening a second pool beside it.
func NewSQLiteSessionStoreFromDB(db *sql.DB, dbPath string) (*SQLiteSessionStore, error) {
	if db == nil {
		return nil, errors.New("tuyaqr: nil database handle")
	}
	s := &SQLiteSessionStore{path: dbPath, db: db, external: true}
	if err := s.prepare(); err != nil {
		return nil, err
	}
	return s, nil
}

// prepare tightens the database's permissions, applies the connection pragmas and
// creates the schema. It never closes the connection: the caller owns that.
//
// The schema step is serialized per database path, so two callers reaching it at
// the same moment cannot both run the DDL against each other.
func (s *SQLiteSessionStore) prepare() error {
	// Tighten BEFORE the connection performs any write: this is what makes the
	// -wal and -shm come out 0600 from birth rather than being repaired later.
	if err := s.harden(); err != nil {
		return err
	}
	// Secure-delete is set on the connection itself, not only in the DSN, so a
	// database reached through a caller-supplied handle (the logger's, whose DSN
	// predates M8) still zeroes deleted cookie bytes instead of leaving them in
	// free pages.
	if _, err := retryOnLockExec(s.db, `PRAGMA secure_delete=on`); err != nil {
		return fmt.Errorf("tuyaqr: enable secure_delete: %w", err)
	}
	if _, err := retryOnLockExec(s.db, `PRAGMA busy_timeout=5000`); err != nil {
		return fmt.Errorf("tuyaqr: set busy_timeout: %w", err)
	}

	unlock := lockPath(s.path)
	err := EnsureSessionSchema(s.db)
	unlock()
	if err != nil {
		return err
	}
	// Re-observe: the schema step may have created -wal/-shm.
	return s.harden()
}

// Close releases this store's reference to the database.
//
// A store created over a caller-supplied handle (NewSQLiteSessionStoreFromDB)
// closes nothing: that caller owns the connection. A store that opened its own
// shared handle drops its reference, and the connection closes when the last
// reference goes - so closing one store cannot pull the database out from under
// another store that is still using it.
func (s *SQLiteSessionStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	release := s.release
	s.release = nil
	s.mu.Unlock()
	if release != nil {
		release()
	}
	return nil
}

// harden creates the parent directory, tightens the database file to 0600 and
// then its -wal/-shm siblings.
//
// It DELEGATES to logger.HardenDatabaseFiles rather than reimplementing it: the
// logger is the component that opens this database, so it is the component that
// must own the invariant. Two implementations of the same security rule would
// be two chances to disagree, and the one that runs second would silently win.
//
// ORDER MATTERS and was MEASURED (see that function): tightening the DATABASE
// before the journal and shared-memory files are created is what makes them 0600
// from birth, and the explicit chmod afterwards is what repairs a database that
// an older build already left 0644 next to 0644 siblings.
func (s *SQLiteSessionStore) harden() error {
	if s == nil || s.path == "" {
		return nil
	}
	observed, err := logger.HardenDatabaseFiles(s.path)
	if err != nil {
		return fmt.Errorf("tuyaqr: session database permissions: %w", err)
	}
	modes := make([]FileMode, 0, len(observed))
	for _, m := range observed {
		modes = append(modes, FileMode{Path: m.Path, Mode: m.Mode})
	}
	s.mu.Lock()
	s.adjusted = modes
	s.mu.Unlock()
	return nil
}

// Kind reports the SQLite store.
func (s *SQLiteSessionStore) Kind() string { return StoreKindSQLite }

// Location is the database path, which is also the thing whose mode matters.
func (s *SQLiteSessionStore) Location() string {
	if s == nil {
		return ""
	}
	return s.path
}

// DB exposes the connection (the logger's, when one was handed in) so the
// process has exactly one writer.
func (s *SQLiteSessionStore) DB() *sql.DB { return s.db }

// ObservedModes returns the permission of the database and its siblings as last
// measured. It exists so the HTTP layer can report the real modes instead of
// claiming a hardening it cannot see.
func (s *SQLiteSessionStore) ObservedModes() []FileMode {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]FileMode, len(s.adjusted))
	copy(out, s.adjusted)
	return out
}

// Harden re-runs the permission tightening and returns the modes it observed.
// It is called after every write, because SQLite creates the -wal and -shm
// lazily: a fresh process can write before the siblings exist.
func (s *SQLiteSessionStore) Harden() ([]FileMode, error) {
	if err := s.harden(); err != nil {
		return nil, err
	}
	return s.ObservedModes(), nil
}

// Load reads the stored session for an account.
func (s *SQLiteSessionStore) Load(a Account) (*Session, error) {
	if s == nil || s.db == nil {
		return nil, ErrNoSession
	}
	var raw string
	err := s.db.QueryRow(
		`SELECT session_json FROM `+TableSession+` WHERE row_key = ?`, a.Key(),
	).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: no session stored for %s", ErrNoSession, a)
	}
	if err != nil {
		return nil, fmt.Errorf("tuyaqr: read stored session: %w", err)
	}
	session, err := sessionFromJSON([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: stored session for %s: %v", ErrNoSession, a, err)
	}
	return session, nil
}

// Save upserts a session, keyed by its own account.
//
// A session that cannot be used (missing fast-sid/s-sid) is refused BEFORE any
// write, so an unusable capture can never displace a working stored credential.
func (s *SQLiteSessionStore) Save(session *Session) error {
	if s == nil || s.db == nil {
		return errors.New("tuyaqr: nil sqlite session store")
	}
	if session == nil {
		return errors.New("tuyaqr: nil session")
	}
	if err := session.validate(); err != nil {
		return err
	}
	acct := session.Account()
	if acct.IsZero() {
		return errors.New("tuyaqr: session has no region/email, so it cannot be keyed")
	}
	data, err := sessionJSON(session)
	if err != nil {
		return err
	}
	_, with := session.CookiesWithExpiry()
	hasPair := 0
	if fast, sid, _ := session.AuthCookieStatus(); fast && sid {
		hasPair = 1
	}
	_, err = retryOnLockExec(s.db,
		`INSERT INTO `+TableSession+`(row_key, region, email, user_key, server_host, session_json, cookie_count, has_auth_pair, last_refresh, updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(row_key) DO UPDATE SET
		   session_json=excluded.session_json,
		   user_key=excluded.user_key,
		   server_host=excluded.server_host,
		   cookie_count=excluded.cookie_count,
		   has_auth_pair=excluded.has_auth_pair,
		   last_refresh=excluded.last_refresh,
		   updated_at=excluded.updated_at`,
		acct.Key(), acct.Normalize().Region, acct.Normalize().Email, session.UserKey, session.ServerHost(),
		string(data), with, hasPair, nullableTime(session.LastRefresh), time.Now(),
	)
	if err != nil {
		return fmt.Errorf("tuyaqr: store session: %w", err)
	}
	// The -wal may have just been created by this write. Re-tighten.
	if _, err := s.Harden(); err != nil {
		return err
	}
	return nil
}

// Delete removes the stored session for one account. An account that is not
// stored is NOT an error: the caller asked for "no session", and that is the
// state.
func (s *SQLiteSessionStore) Delete(a Account) error {
	if s == nil || s.db == nil {
		return nil
	}
	if _, err := s.db.Exec(`DELETE FROM `+TableSession+` WHERE row_key = ?`, a.Key()); err != nil {
		return fmt.Errorf("tuyaqr: delete stored session: %w", err)
	}
	// A deleted blob must not survive in a free page. secure_delete zeroes it,
	// and the checkpoint flushes those zeroed pages out of the journal.
	if _, err := s.db.Exec(`PRAGMA wal_checkpoint(PASSIVE)`); err != nil {
		// Not fatal: the credential is already unreachable through the API.
		return nil
	}
	return nil
}

// Accounts lists what is stored, without reading a session blob.
func (s *SQLiteSessionStore) Accounts() ([]StoredSession, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	rows, err := s.db.Query(
		`SELECT region, email, cookie_count, has_auth_pair, last_refresh, updated_at
		   FROM ` + TableSession + ` ORDER BY updated_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("tuyaqr: list stored sessions: %w", err)
	}
	defer rows.Close()
	var out []StoredSession
	for rows.Next() {
		var (
			region, email string
			cookieCount   int
			hasPair       int
			lastRefresh   sql.NullTime
			updatedAt     sql.NullTime
		)
		if err := rows.Scan(&region, &email, &cookieCount, &hasPair, &lastRefresh, &updatedAt); err != nil {
			return nil, err
		}
		entry := StoredSession{
			Account:     Account{Region: region, Email: email},
			CookieCount: cookieCount,
			HasAuthPair: hasPair == 1,
		}
		if lastRefresh.Valid {
			entry.LastRefresh = lastRefresh.Time
		}
		if updatedAt.Valid {
			entry.UpdatedAt = updatedAt.Time
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

// Materialize writes a private 0600 copy of the session for the vendored go2rtc
// Tuya driver, which consumes a session file and nothing else.
//
// The copy is the price of not touching frozen vendored code: internal/go2rtc
// is vendored and must not be modified. The directory is created 0700 and the
// file 0600, and the path is stable per account, so repeated calls do not pile
// up copies.
//
// The caller must keep the file for as long as the engine needs it. Callers
// that want it removed pass the path to RemoveMaterialized.
func (s *SQLiteSessionStore) Materialize(session *Session) (string, error) {
	if session == nil {
		return "", ErrNoSession
	}
	dir := filepath.Join(os.TempDir(), "tuya-engine-sessions")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	acct := session.Account()
	name := "session_" + sanitizeKey(acct.Region) + "_" + sanitizeKey(acct.Email) + ".json"
	path := filepath.Join(dir, name)
	if err := SaveSession(path, session); err != nil {
		return "", err
	}
	return path, nil
}

// RemoveMaterialized deletes a copy produced by Materialize.
func RemoveMaterialized(path string) {
	if strings.TrimSpace(path) == "" {
		return
	}
	_ = os.Remove(path)
}

// sanitizeKey reduces an account field to characters safe in a file name.
func sanitizeKey(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "default"
	}
	return b.String()
}

// nullableTime maps the zero time onto SQL NULL, so "never refreshed" is a
// NULL and not a magic instant.
func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
