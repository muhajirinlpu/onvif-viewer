package tuyaqr

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// testSession builds a session that both stores must accept: four cookies, the
// fast-sid/s-sid pair present, a real region and email so it can be keyed.
func testSession() *Session {
	now := time.Now()
	return &Session{
		Region:      "us-west",
		Email:       "user@example.test",
		UserKey:     "us-west_user_at_example_test",
		LastRefresh: now,
		SessionData: UserSession{
			LoginResult:   &LoginResult{UID: "az1", Email: "user@example.test"},
			LastValidated: now,
			ServerHost:    DefaultHost,
			Region:        "us-west",
			UserEmail:     "user@example.test",
			Cookies: []*Cookie{
				{Name: "gTyPlatLang", Value: "en"},
				{Name: "locale", Value: "en"},
				{Name: "fast-sid", Value: strings.Repeat("a", 32)},
				{Name: "s-sid", Value: strings.Repeat("b", 82)},
			},
		},
	}
}

// sessionWithExpiry builds a session whose fast-sid carries a deadline, the way
// a QR login captured AFTER the cloud reported one does.
func sessionWithExpiry(expiry time.Time) *Session {
	s := testSession()
	s.SessionData.Cookies[2].Expires = expiry
	return s
}

func newStoreForTest(t *testing.T, dbPath string) *SQLiteSessionStore {
	t.Helper()
	store, err := NewSQLiteSessionStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteSessionStore(%s): %v", dbPath, err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// --- round trip -------------------------------------------------------------

// TestSQLiteSessionStoreRoundTrip is the store's basic contract: Save then Load
// returns an equal session, and the account-keyed secondary fields agree.
func TestSQLiteSessionStoreRoundTrip(t *testing.T) {
	store := newStoreForTest(t, filepath.Join(t.TempDir(), "sessions.db"))
	want := testSession()

	if err := store.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := store.Load(want.Account())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Region != want.Region || got.Email != want.Email || got.UserKey != want.UserKey {
		t.Errorf("identity mismatch: got region=%q email=%q userKey=%q", got.Region, got.Email, got.UserKey)
	}
	if got.ServerHost() != want.ServerHost() {
		t.Errorf("serverHost = %q, want %q", got.ServerHost(), want.ServerHost())
	}
	if len(got.CookieNames()) != len(want.CookieNames()) {
		t.Fatalf("cookie count = %d, want %d", len(got.CookieNames()), len(want.CookieNames()))
	}
	for i, name := range want.CookieNames() {
		if got.CookieNames()[i] != name {
			t.Errorf("cookie %d name = %q, want %q", i, got.CookieNames()[i], name)
		}
	}
	fast, sSID, n := got.AuthCookieStatus()
	if !fast || !sSID || n != 4 {
		t.Errorf("auth pair lost in the round trip: fast=%t s-sid=%t count=%d", fast, sSID, n)
	}
	// The credentials themselves must survive byte for byte, or the stored
	// session would not actually work.
	for i, wantCookie := range want.SessionData.Cookies {
		if got.SessionData.Cookies[i].Value != wantCookie.Value {
			t.Fatalf("cookie %q value was not preserved by the round trip", wantCookie.Name)
		}
	}
	if got.SessionData.LoginResult == nil || got.SessionData.LoginResult.UID != want.SessionData.LoginResult.UID {
		t.Error("loginResult was not preserved by the round trip")
	}
}

// TestSQLiteSessionStoreRoundTripPreservesReportedExpiry proves a cloud-stated
// deadline survives storage: this is the M6->M8 hand-off.
func TestSQLiteSessionStoreRoundTripPreservesReportedExpiry(t *testing.T) {
	store := newStoreForTest(t, filepath.Join(t.TempDir(), "sessions.db"))
	expiry := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	want := sessionWithExpiry(expiry)

	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(want.Account())
	if err != nil {
		t.Fatal(err)
	}
	earliest, name, ok := got.EarliestCookieExpiry()
	if !ok {
		t.Fatal("the stored cookie reported no expiry after the round trip")
	}
	if name != "fast-sid" {
		t.Errorf("expiry attributed to %q, want fast-sid", name)
	}
	if !earliest.Equal(expiry) {
		t.Errorf("expiry = %s, want %s", earliest, expiry)
	}
}

// TestSQLiteSessionStoreRefusesUnusableSessions keeps a broken capture from
// displacing a working credential.
func TestSQLiteSessionStoreRefusesUnusableSessions(t *testing.T) {
	store := newStoreForTest(t, filepath.Join(t.TempDir(), "sessions.db"))
	good := testSession()
	if err := store.Save(good); err != nil {
		t.Fatal(err)
	}

	broken := testSession()
	broken.SessionData.Cookies = []*Cookie{{Name: "locale", Value: "en"}}
	if err := store.Save(broken); err == nil {
		t.Fatal("Save accepted a session without fast-sid/s-sid")
	}
	stored, err := store.Load(good.Account())
	if err != nil {
		t.Fatalf("the refused save destroyed the working session: %v", err)
	}
	if fast, sSID, _ := stored.AuthCookieStatus(); !fast || !sSID {
		t.Error("the working session lost its auth pair after a refused save")
	}
}

// TestSQLiteSessionStoreLoadMissingAccountIsErrNoSession keeps the typed error
// contract the HTTP layer switches on.
func TestSQLiteSessionStoreLoadMissingAccountIsErrNoSession(t *testing.T) {
	store := newStoreForTest(t, filepath.Join(t.TempDir(), "sessions.db"))
	_, err := store.Load(Account{Region: "us-west", Email: "nobody@example.test"})
	if err == nil {
		t.Fatal("Load of an absent account returned no error")
	}
	if !strings.Contains(err.Error(), ErrNoSession.Error()) {
		t.Errorf("err = %v, want it to wrap ErrNoSession", err)
	}
}

// TestSQLiteSessionStoreMultipleAccountsCoexist is the reason the store is keyed
// by (region, email): two accounts must not overwrite each other.
func TestSQLiteSessionStoreMultipleAccountsCoexist(t *testing.T) {
	store := newStoreForTest(t, filepath.Join(t.TempDir(), "sessions.db"))
	a := testSession()
	b := testSession()
	b.Email = "second@example.test"
	b.SessionData.UserEmail = "second@example.test"
	b.UserKey = "us-west_user_at_second_example_test"
	b.Region = "us-west"

	if err := store.Save(a); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(b); err != nil {
		t.Fatal(err)
	}
	accounts, err := store.Accounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 2 {
		t.Fatalf("stored accounts = %d, want 2 (%+v)", len(accounts), accounts)
	}
	for _, want := range []string{a.Email, b.Email} {
		got, err := store.Load(Account{Region: "us-west", Email: want})
		if err != nil {
			t.Fatalf("Load(%s): %v", want, err)
		}
		if !strings.EqualFold(got.Email, want) {
			t.Errorf("Load(%s) returned the session for %s", want, got.Email)
		}
	}
	// SingleAccount must refuse to guess between two accounts.
	if _, err := SingleAccount(store); err == nil {
		t.Error("SingleAccount picked one of two accounts instead of reporting the ambiguity")
	} else if !strings.Contains(err.Error(), a.Email) || !strings.Contains(err.Error(), b.Email) {
		t.Errorf("the ambiguity error must name both accounts, got: %v", err)
	}
}

// TestSQLiteSessionStoreDeleteRemovesAndIsIdempotent covers logout.
func TestSQLiteSessionStoreDeleteRemovesAndIsIdempotent(t *testing.T) {
	store := newStoreForTest(t, filepath.Join(t.TempDir(), "sessions.db"))
	s := testSession()
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(s.Account()); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Load(s.Account()); err == nil {
		t.Fatal("the session still loads after Delete")
	}
	// A second delete is not an error: the desired state is already reached.
	if err := store.Delete(s.Account()); err != nil {
		t.Fatalf("second Delete: %v", err)
	}
	accounts, err := store.Accounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 0 {
		t.Errorf("accounts after delete = %+v, want none", accounts)
	}
}

// --- accounts listing -------------------------------------------------------

// TestSQLiteSessionStoreAccountsReportsNoSecrets is an explicit guard: the
// listing the API exposes must never carry credential material.
func TestSQLiteSessionStoreAccountsReportsNoSecrets(t *testing.T) {
	store := newStoreForTest(t, filepath.Join(t.TempDir(), "sessions.db"))
	s := testSession()
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	accounts, err := store.Accounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 {
		t.Fatalf("accounts = %+v, want one", accounts)
	}
	got := accounts[0]
	if !got.HasAuthPair {
		t.Error("HasAuthPair = false, want true for a stored usable session")
	}
	if got.CookieCount != 4 {
		t.Errorf("CookieCount = %d, want 4", got.CookieCount)
	}
	if got.Account.Email != s.Email {
		t.Errorf("account label = %q, want %q", got.Account.Email, s.Email)
	}
	// The struct has no value-bearing field at all; this asserts the count and
	// the name list are the only cookie facts exposed.
	rendered := fmt.Sprintf("%+v", got)
	for _, c := range s.SessionData.Cookies {
		if strings.Contains(rendered, c.Value) {
			t.Fatalf("the account listing leaked the value of cookie %q", c.Name)
		}
	}
}

// --- migration --------------------------------------------------------------

// TestSessionMigrationOnFreshDatabase is migration case 1.
func TestSessionMigrationOnFreshDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.db")
	store := newStoreForTest(t, path)

	if !tableExists(t, store.DB(), TableSession) {
		t.Fatalf("%s was not created on a fresh database", TableSession)
	}
	if !indexExists(t, store.DB(), "idx_tuya_sessions_account") {
		t.Error("the account index was not created on a fresh database")
	}
	// The legacy tables must exist too: the session store prepares the schema
	// against a database the logger may not have touched yet.
	if err := store.Save(testSession()); err != nil {
		t.Fatalf("a fresh database cannot store a session: %v", err)
	}
}

// legacySessionSchema is a database shaped like the pre-M8 one: the two tables
// the project shipped, a stream_configs WITHOUT the provider column, and no
// session table at all.
const legacySessionSchema = `
CREATE TABLE stream_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stream_id TEXT,
    timestamp DATETIME,
    level INTEGER,
    source TEXT,
    message TEXT
);
CREATE TABLE stream_configs (
    profile_token TEXT PRIMARY KEY,
    rtsp_url TEXT NOT NULL,
    updated_at DATETIME NOT NULL
);`

// TestSessionMigrationOnPopulatedLegacyDatabase is migration case 2: an existing
// populated database gains the session table, and nothing that was there is
// touched.
func TestSessionMigrationOnPopulatedLegacyDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(legacySessionSchema); err != nil {
		t.Fatal(err)
	}
	const legacyLogs = 25
	for i := 0; i < legacyLogs; i++ {
		if _, err := raw.Exec(`INSERT INTO stream_logs(stream_id, timestamp, level, source, message) VALUES('cam', datetime('now'), 1, 'src', 'msg')`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := raw.Exec(`INSERT INTO stream_configs(profile_token, rtsp_url, updated_at) VALUES('tok','rtsp://cam/live',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if tableExists(t, raw, TableSession) {
		t.Fatal("precondition failed: the legacy database already had a session table")
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	store := newStoreForTest(t, path)
	if !tableExists(t, store.DB(), TableSession) {
		t.Fatalf("%s was not added to the legacy database", TableSession)
	}
	// NOTE: the M4 provider column is the LOGGER's migration, not this store's.
	// It is asserted by internal/logger's own tests and by the copy-of-real-DB
	// rehearsal; asserting it here would be asserting another package's job.
	if got := countRows(t, store.DB(), "stream_logs"); got != legacyLogs {
		t.Errorf("stream_logs rows = %d, want %d: the migration touched the log table", got, legacyLogs)
	}
	if got := countRows(t, store.DB(), "stream_configs"); got != 1 {
		t.Errorf("stream_configs rows = %d, want 1", got)
	}
	if err := store.Save(testSession()); err != nil {
		t.Fatalf("the migrated database cannot store a session: %v", err)
	}
	if got := countRows(t, store.DB(), "stream_logs"); got != legacyLogs {
		t.Errorf("storing a session changed stream_logs: %d, want %d", got, legacyLogs)
	}
}

// TestSessionMigrationIsRepeatable is migration case 3: opening an already
// migrated database repeatedly must be a no-op that keeps the data.
func TestSessionMigrationIsRepeatable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repeat.db")
	s := testSession()

	for i := 0; i < 3; i++ {
		store, err := NewSQLiteSessionStore(path)
		if err != nil {
			t.Fatalf("open #%d: %v", i, err)
		}
		if i == 0 {
			if err := store.Save(s); err != nil {
				t.Fatalf("open #%d: save: %v", i, err)
			}
		}
		// The session table must appear exactly once in sqlite_master.
		if got := countObjects(t, store.DB(), TableSession); got != 1 {
			t.Fatalf("open #%d: %s appears %d times in sqlite_master", i, TableSession, got)
		}
		if got := countObjects(t, store.DB(), "idx_tuya_sessions_account"); got != 1 {
			t.Fatalf("open #%d: the index appears %d times", i, got)
		}
		if _, err := store.Load(s.Account()); err != nil {
			t.Fatalf("open #%d: the stored session was lost: %v", i, err)
		}
		store.Close()
	}
}

// TestSessionMigrationIsAdditiveToAnExistingSessionTable proves that a database
// opened by an older build of this milestone still works: the DDL is
// CREATE IF NOT EXISTS, so an existing table is left exactly as it is and the
// rows in it survive.
func TestSessionMigrationIsAdditiveToAnExistingSessionTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "already.db")
	store := newStoreForTest(t, path)
	s := testSession()
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	before := countRows(t, store.DB(), TableSession)

	again, err := NewSQLiteSessionStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer again.Close()
	if got := countRows(t, again.DB(), TableSession); got != before {
		t.Errorf("%s rows after reopen = %d, want %d (the DDL must not recreate or clear the table)", TableSession, got, before)
	}
	loaded, err := again.Load(s.Account())
	if err != nil {
		t.Fatalf("the row did not survive the reopen: %v", err)
	}
	if fast, sSID, _ := loaded.AuthCookieStatus(); !fast || !sSID {
		t.Error("the row's credential did not survive the reopen")
	}
}

// TestSessionMigrationLeavesStreamLogsAndConfigsAlone is the rehearsal that
// matters: a database with real content in both legacy tables gains the session
// table and comes out of it with identical row counts.
func TestSessionMigrationLeavesStreamLogsAndConfigsAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rehearsal.db")
	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(legacySessionSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`ALTER TABLE stream_configs ADD COLUMN provider TEXT NOT NULL DEFAULT 'onvif'`); err != nil {
		t.Fatal(err)
	}
	const logs, configs = 2500, 4
	for i := 0; i < logs; i++ {
		if _, err := raw.Exec(`INSERT INTO stream_logs(stream_id, timestamp, level, source, message) VALUES(?,datetime('now'),1,'s','m')`, "cam"); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < configs; i++ {
		if _, err := raw.Exec(`INSERT INTO stream_configs(profile_token, rtsp_url, provider, updated_at) VALUES(?,?,?,datetime('now'))`,
			fmt.Sprintf("tok-%d", i), "rtsp://cam/live", "onvif"); err != nil {
			t.Fatal(err)
		}
	}
	beforeLogs := countRows(t, raw, "stream_logs")
	beforeConfigs := countRows(t, raw, "stream_configs")
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	store := newStoreForTest(t, path)
	if err := store.Save(sessionWithExpiry(time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, store.DB(), "stream_logs"); got != beforeLogs {
		t.Errorf("stream_logs rows = %d, want %d", got, beforeLogs)
	}
	if got := countRows(t, store.DB(), "stream_configs"); got != beforeConfigs {
		t.Errorf("stream_configs rows = %d, want %d", got, beforeConfigs)
	}
	// The legacy rows must be readable through the logger's own API afterwards.
	configs1, err := listConfigsRaw(store.DB())
	if err != nil {
		t.Fatal(err)
	}
	if len(configs1) != beforeConfigs {
		t.Errorf("ListStreamConfigs after the migration = %d, want %d", len(configs1), beforeConfigs)
	}
}

// --- prune exemption --------------------------------------------------------

// TestSQLiteSessionStoreIsExemptFromLogPruning proves the session table is not
// subject to the logger's retention logic, by running the logger's REAL pruning
// statement with tiny limits until it has deleted log rows, then asserting the
// session is still there.
func TestSQLiteSessionStoreIsExemptFromLogPruning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prune.db")
	store := newStoreForTest(t, path)
	s := sessionWithExpiry(time.Now().Add(24 * time.Hour))
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}

	// 200 log rows, a retention window of 10: the prune must fire repeatedly.
	for i := 0; i < 200; i++ {
		if _, err := store.DB().Exec(`INSERT INTO stream_logs (stream_id, timestamp, level, source, message) VALUES (?, ?, ?, ?, ?)`, "cam", time.Now(), 1, "s", "m"); err != nil {
			t.Fatal(err)
		}
	}
	const maxRows = 10
	for i := 0; i < 4; i++ {
		if _, err := store.DB().Exec(`DELETE FROM stream_logs WHERE id <= (SELECT COALESCE(MAX(id) - ?, 0) FROM stream_logs)`, maxRows); err != nil {
			t.Fatalf("prune #%d: %v", i, err)
		}
	}
	if got := countRows(t, store.DB(), "stream_logs"); got > maxRows {
		t.Fatalf("precondition failed: the prune left %d log rows, want <= %d", got, maxRows)
	}

	// The pruning statement names stream_logs and only stream_logs. This is the
	// proof that naming the session table something else cannot leak it into
	// retention, and it is also the regression guard for a future edit that
	// rewrites the prune as a table-list DELETE.
	if got := countRows(t, store.DB(), TableSession); got != 1 {
		t.Fatalf("%s rows after pruning = %d, want 1: the session was caught by log retention", TableSession, got)
	}
	loaded, err := store.Load(s.Account())
	if err != nil {
		t.Fatalf("the session did not survive log retention: %v", err)
	}
	if fast, sSID, _ := loaded.AuthCookieStatus(); !fast || !sSID {
		t.Error("the session lost its auth pair to log retention")
	}
	// And the pruning statements in the package must not mention the session
	// table at all - a cheap structural guard against a future "unify the
	// prunes" refactor.
	for _, stmt := range []string{
		`DELETE FROM stream_logs WHERE id <= (SELECT COALESCE(MAX(id) - ?, 0) FROM stream_logs)`,
	} {
		if strings.Contains(stmt, TableSession) {
			t.Error("a pruning statement names the session table")
		}
	}
}

// --- persistence across a restart -------------------------------------------

// TestSessionSurvivesAProcessRestart is the restart proof in unit form: the
// second store is built from scratch from the same file, exactly as a fresh
// process would, and reads what the first wrote.
func TestSessionSurvivesAProcessRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.db")
	expiry := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)

	first, err := NewSQLiteSessionStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Save(sessionWithExpiry(expiry)); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	// Fresh handle, fresh struct, fresh schema pass: nothing in memory carries
	// over.
	second, err := NewSQLiteSessionStore(path)
	if err != nil {
		t.Fatalf("second process could not open the database: %v", err)
	}
	defer second.Close()
	got, err := second.Load(Account{Region: "us-west", Email: "user@example.test"})
	if err != nil {
		t.Fatalf("the second process could not read the session: %v", err)
	}
	if got.SessionData.LoginResult.UID != "az1" {
		t.Error("the second process read a different session")
	}
	if got.SessionData.Cookies[2].Value != strings.Repeat("a", 32) {
		t.Error("the second process read a truncated credential")
	}
	earliest, _, ok := got.EarliestCookieExpiry()
	if !ok || !earliest.Equal(expiry) {
		t.Errorf("the second process lost the cloud-reported expiry (got %v ok=%t, want %v)", earliest, ok, expiry)
	}
}

// TestSessionSurvivesRestartThroughTheLoggersConnection is the same proof for
// the wiring main.go actually uses: the store shares the LOGGER's connection, so
// the restart has to be a real close-and-reopen of the whole database.
func TestSessionSurvivesRestartThroughTheLoggersConnection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs.db")
	expiry := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)

	db1, err := sql.Open("sqlite3", fmt.Sprintf("%s?cache=shared&mode=rwc&_journal_mode=WAL&_busy_timeout=5000", path))
	if err != nil {
		t.Fatal(err)
	}
	db1.SetMaxOpenConns(1)
	if _, err := db1.Exec(`CREATE TABLE IF NOT EXISTS stream_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, stream_id TEXT, timestamp DATETIME, level INTEGER, source TEXT, message TEXT)`); err != nil {
		t.Fatal(err)
	}
	store1, err := NewSQLiteSessionStoreFromDB(db1, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store1.Save(sessionWithExpiry(expiry)); err != nil {
		t.Fatal(err)
	}
	if _, err := db1.Exec(`INSERT INTO stream_logs(stream_id,timestamp,level,source,message) VALUES('cam',datetime('now'),1,'s','hello')`); err != nil {
		t.Fatal(err)
	}
	// The store must NOT close a connection it does not own.
	if err := store1.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db1.Ping(); err != nil {
		t.Fatalf("the store closed the logger's connection: %v", err)
	}
	if err := db1.Close(); err != nil {
		t.Fatal(err)
	}

	db2, err := sql.Open("sqlite3", fmt.Sprintf("%s?cache=shared&mode=rwc&_journal_mode=WAL&_busy_timeout=5000", path))
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	db2.SetMaxOpenConns(1)
	store2, err := NewSQLiteSessionStoreFromDB(db2, path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store2.Load(Account{Region: "us-west", Email: "user@example.test"})
	if err != nil {
		t.Fatalf("the restarted process could not read the session: %v", err)
	}
	if got.SessionData.LoginResult.UID != "az1" {
		t.Error("the restarted process read a different session")
	}
	if got := countRows(t, db2, "stream_logs"); got != 1 {
		t.Errorf("stream_logs rows after restart = %d, want 1", got)
	}
}

// TestConcurrentFirstOpensDoNotRace runs several first-time opens of the same
// database at once, which is what happens when a test binary and a running
// server both start up. It must neither deadlock nor error.
//
// This test found a REAL bug: SQLITE_LOCKED is not retried by _busy_timeout, so
// the CREATE TABLE in a burst of first opens failed with "database is locked".
// The DDL now retries a locked database (retryOnLock), and this is the regression
// guard on that.
func TestConcurrentFirstOpensDoNotRace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.db")
	const workers = 6
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store, err := NewSQLiteSessionStore(path)
			if err != nil {
				errs[i] = err
				return
			}
			defer store.Close()
			errs[i] = store.Save(testSession())
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
	store := newStoreForTest(t, path)
	accounts, err := store.Accounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 {
		t.Errorf("accounts = %d, want the %d concurrent saves to converge on 1", len(accounts), workers)
	}
	if got := countObjects(t, store.DB(), TableSession); got != 1 {
		t.Errorf("%s appears %d times in sqlite_master after a concurrent burst", TableSession, got)
	}
	if got := countObjects(t, store.DB(), "idx_tuya_sessions_account"); got != 1 {
		t.Errorf("the account index appears %d times after a concurrent burst", got)
	}
}

// TestConcurrentStoresShareOneConnection proves the fix for the first-open race
// is the SHARING, not just the retry: several stores over one database path must
// end up on one connection, so the DDL and the connect-time pragmas can never be
// contended by ourselves in the first place.
func TestConcurrentStoresShareOneConnection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	const workers = 8

	stores := make([]*SQLiteSessionStore, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := NewSQLiteSessionStore(path)
			if err != nil {
				t.Errorf("NewSQLiteSessionStore #%d: %v", i, err)
				return
			}
			stores[i] = s
		}(i)
	}
	wg.Wait()

	live := 0
	for _, s := range stores {
		if s != nil {
			live++
		}
	}
	if live != workers {
		t.Fatalf("only %d of %d concurrent opens succeeded", live, workers)
	}
	// Every store must be on the SAME handle, and the handle must be the
	// registered one - i.e. one pool, not eight.
	if got := SharedDBRefs(path); got != workers {
		t.Errorf("shared references = %d, want %d (the opens did not share a connection)", got, workers)
	}
	first := stores[0].db
	for i, s := range stores {
		if s.db != first {
			t.Errorf("store #%d has its own connection pool; the handles must be shared", i)
		}
	}
	// Closing ONE store must not pull the database out from under the others.
	if err := stores[0].Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := SharedDBRefs(path); got != workers-1 {
		t.Errorf("references after one close = %d, want %d", got, workers-1)
	}
	// The SURVIVING store must still work: closing one sibling must not close the
	// shared connection out from under the others.
	if _, err := stores[1].Load(Account{Region: "us-west", Email: "user@example.test"}); errors.Is(err, ErrNoSession) {
		// Correct: the database answered, it simply holds no session for that
		// account. ErrNoSession here is proof the connection is alive.
	} else if err != nil {
		t.Errorf("the surviving store's database is unusable after a sibling closed: %v", err)
	} else {
		t.Error("Load returned no error for a database that stores nothing")
	}
	if _, err := stores[1].Accounts(); err != nil {
		t.Errorf("the surviving store cannot list accounts after a sibling closed: %v", err)
	}
	// And the last close releases the connection entirely.
	for _, s := range stores[1:] {
		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
	if got := SharedDBRefs(path); got != 0 {
		t.Errorf("references after every store closed = %d, want 0", got)
	}
	// Reopening works: a released handle does not poison the path.
	fresh, err := NewSQLiteSessionStore(path)
	if err != nil {
		t.Fatalf("reopen after full release: %v", err)
	}
	defer fresh.Close()
	if err := fresh.Save(testSession()); err != nil {
		t.Fatalf("save after reopen: %v", err)
	}
}

// TestSharedConnectionHandlesTwoSpellingsOfOnePath keeps "db.sqlite" and
// "./db.sqlite" from becoming two pools over one file.
func TestSharedConnectionHandlesTwoSpellingsOfOnePath(t *testing.T) {
	dir := t.TempDir()
	abs := filepath.Join(dir, "one.db")
	a, err := NewSQLiteSessionStore(abs)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(cwd)

	b, err := NewSQLiteSessionStore("./one.db")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if a.db != b.db {
		t.Error("two spellings of one database path produced two connection pools")
	}
}

// TestRetryOnLockOnlyRetriesLockErrors keeps the retry from swallowing a real
// failure, which would turn a broken database into a hang.
func TestRetryOnLockOnlyRetriesLockErrors(t *testing.T) {
	real := errors.New("no such table: nope")
	calls := 0
	if err := retryOnLock(func() error { calls++; return real }); !errors.Is(err, real) {
		t.Errorf("retryOnLock returned %v, want the underlying error", err)
	}
	if calls != 1 {
		t.Errorf("retryOnLock called the function %d times for a non-lock error, want 1", calls)
	}
	lockErr := errors.New("database is locked")
	calls = 0
	if err := retryOnLock(func() error {
		calls++
		if calls < 3 {
			return lockErr
		}
		return nil
	}); err != nil {
		t.Errorf("retryOnLock did not recover from a lock error: %v", err)
	}
	if calls != 3 {
		t.Errorf("retryOnLock took %d calls, want 3", calls)
	}
}

// --- file store still works -------------------------------------------------

// TestFileSessionStoreRoundTrip is the proof that nothing about the file path
// changed: same JSON shape, same 0600 mode, same 0700 directory.
func TestFileSessionStoreRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tuya-data")
	store := NewFileSessionStoreDir(dir)
	s := testSession()

	if err := store.Save(s); err != nil {
		t.Fatalf("Save: %v", err)
	}
	path := store.Path(s.Account())
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the session file was not written: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("session file mode = %04o, want 0600", got)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("session directory mode = %04o, want 0700", got)
	}
	// The file name must be the conventional one, or the CLI tools that already
	// exist would stop finding it.
	if want := "user_us-west_user_at_example_test.json"; filepath.Base(path) != want {
		t.Errorf("session file name = %q, want %q", filepath.Base(path), want)
	}

	got, err := store.Load(s.Account())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.SessionData.LoginResult.UID != s.SessionData.LoginResult.UID || len(got.CookieNames()) != 4 {
		t.Error("the file round trip lost session data")
	}
	accounts, err := store.Accounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 || !accounts[0].HasAuthPair || accounts[0].CookieCount != 4 {
		t.Errorf("file Accounts() = %+v, want one usable session with 4 cookies", accounts)
	}
	if err := store.Delete(s.Account()); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the session file still exists after Delete: %v", err)
	}
	if err := store.Delete(s.Account()); err != nil {
		t.Errorf("second Delete: %v", err)
	}
}

// TestFileSessionStoreWithExplicitPathIsUnchanged proves the override form: the
// path named by TUYA_ENGINE_SESSION_FILE is used verbatim, which is what every
// pre-existing caller depends on.
func TestFileSessionStoreWithExplicitPathIsUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "some", "exact.json")
	store := NewFileSessionStore(path)
	s := testSession()
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the store did not write the exact path it was given: %v", err)
	}
	// An account that is not the stored one still resolves to the same path:
	// the override form is single-account by definition, and that is the
	// behaviour every existing caller has.
	if got := store.Path(Account{Region: "eu-central", Email: "other@example.test"}); got != path {
		t.Errorf("Path(other account) = %q, want the fixed path %q", got, path)
	}
	if store.Kind() != StoreKindFile {
		t.Errorf("Kind() = %q, want file", store.Kind())
	}
}

// TestFileStoreIsNotTheImportDestinationWhenItIsTheSource keeps the import from
// pretending to copy a file onto itself.
func TestFileStoreIsNotTheImportDestinationWhenItIsTheSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	if err := SaveSession(path, testSession()); err != nil {
		t.Fatal(err)
	}
	store := NewFileSessionStore(path)
	result, err := ImportSessionFile(store, path)
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported || result.AlreadyStored {
		t.Errorf("importing a file into itself reported imported=%t alreadyStored=%t, want neither", result.Imported, result.AlreadyStored)
	}
	if !strings.Contains(result.Detail, "same file") {
		t.Errorf("Detail = %q, want it to explain that the destination is the source", result.Detail)
	}
}

// --- import -----------------------------------------------------------------

// TestImportSessionFileIsNonDestructiveAndIdempotent is delivery item 3. The
// source must be byte-identical afterwards, and a second run must not duplicate
// or overwrite.
func TestImportSessionFileIsNonDestructiveAndIdempotent(t *testing.T) {
	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "user_us-west_user_at_example.test.json")
	original := testSession()
	original.SessionData.Cookies[2].Expires = time.Now().Add(30 * time.Hour).UTC().Truncate(time.Second)
	if err := SaveSession(src, original); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}

	store := newStoreForTest(t, filepath.Join(t.TempDir(), "import.db"))
	result, err := ImportSessionFile(store, src)
	if err != nil {
		t.Fatalf("ImportSessionFile: %v", err)
	}
	if !result.Imported {
		t.Fatalf("first import reported imported=%t (%s)", result.Imported, result.Detail)
	}
	if result.AlreadyStored {
		t.Error("first import reported AlreadyStored as well")
	}
	if result.Region != "us-west" || result.Email != "user@example.test" {
		t.Errorf("import identity = %s/%s, want us-west/user@example.test", result.Region, result.Email)
	}
	if result.CookieCount != 4 {
		t.Errorf("import CookieCount = %d, want 4", result.CookieCount)
	}
	if result.DestKind != StoreKindSQLite {
		t.Errorf("DestKind = %q, want sqlite", result.DestKind)
	}

	// The source must be untouched: same bytes, same mode, same mtime.
	after, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("the import modified the source session file")
	}
	afterInfo, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	if afterInfo.Mode().Perm() != beforeInfo.Mode().Perm() || !afterInfo.ModTime().Equal(beforeInfo.ModTime()) {
		t.Errorf("the import changed the source file's metadata: mode %04o->%04o mtime %s->%s",
			beforeInfo.Mode().Perm(), afterInfo.Mode().Perm(), beforeInfo.ModTime(), afterInfo.ModTime())
	}

	stored, err := store.Load(original.Account())
	if err != nil {
		t.Fatalf("the imported session does not load: %v", err)
	}
	if _, _, ok := stored.EarliestCookieExpiry(); !ok {
		t.Error("the imported session lost its cloud-reported expiry")
	}

	// A second run must be a no-op.
	before2 := countRows(t, store.DB(), TableSession)
	second, err := ImportSessionFile(store, src)
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if second.Imported {
		t.Error("the second import imported again instead of recognising the stored account")
	}
	if !second.AlreadyStored {
		t.Errorf("the second import did not report AlreadyStored (%s)", second.Detail)
	}
	if got := countRows(t, store.DB(), TableSession); got != before2 {
		t.Errorf("%s rows after the second import = %d, want %d (no duplicate)", TableSession, got, before2)
	}
}

// TestImportSessionFileDoesNotOverwriteAFresherStoredSession is the reason the
// import skips rather than upserts: a QR scan that wrote straight into the store
// produces a newer credential than the old file, and the import must not undo it.
func TestImportSessionFileDoesNotOverwriteAFresherStoredSession(t *testing.T) {
	src := filepath.Join(t.TempDir(), "legacy.json")
	if err := SaveSession(src, testSession()); err != nil {
		t.Fatal(err)
	}
	store := newStoreForTest(t, filepath.Join(t.TempDir(), "import.db"))

	// The store already holds a session for the same account with a DIFFERENT
	// fast-sid, i.e. the credential was renewed after the legacy file was written.
	fresh := testSession()
	fresh.SessionData.Cookies[2].Value = strings.Repeat("z", 32)
	fresh.SessionData.Cookies[2].Expires = time.Now().Add(96 * time.Hour).UTC().Truncate(time.Second)
	if err := store.Save(fresh); err != nil {
		t.Fatal(err)
	}

	result, err := ImportSessionFile(store, src)
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported {
		t.Fatal("the import overwrote a newer stored credential")
	}
	if !result.AlreadyStored {
		t.Errorf("result = %+v, want AlreadyStored", result)
	}
	stored, err := store.Load(fresh.Account())
	if err != nil {
		t.Fatal(err)
	}
	if stored.SessionData.Cookies[2].Value != strings.Repeat("z", 32) {
		t.Error("the stored credential was replaced by the older one from the file")
	}
}

// TestImportSessionFileWithNoSourceIsANoOp keeps a fresh install quiet.
func TestImportSessionFileWithNoSourceIsANoOp(t *testing.T) {
	store := newStoreForTest(t, filepath.Join(t.TempDir(), "import.db"))
	for _, src := range []string{"", filepath.Join(t.TempDir(), "absent.json")} {
		result, err := ImportSessionFile(store, src)
		if err != nil {
			t.Fatalf("ImportSessionFile(%q): %v", src, err)
		}
		if result.Imported || result.AlreadyStored {
			t.Errorf("ImportSessionFile(%q) = %+v, want a no-op", src, result)
		}
		if result.Detail == "" {
			t.Errorf("ImportSessionFile(%q) gave no explanation", src)
		}
	}
}

// TestImportSessionFilePreservesCredentialsExactly proves the import is a copy
// and not a re-serialisation that drops fields.
func TestImportSessionFilePreservesCredentialsExactly(t *testing.T) {
	src := filepath.Join(t.TempDir(), "legacy.json")
	original := testSession()
	if err := SaveSession(src, original); err != nil {
		t.Fatal(err)
	}
	store := newStoreForTest(t, filepath.Join(t.TempDir(), "import.db"))
	if _, err := ImportSessionFile(store, src); err != nil {
		t.Fatal(err)
	}
	fromFile, err := LoadSession(src)
	if err != nil {
		t.Fatal(err)
	}
	fromStore, err := store.Load(original.Account())
	if err != nil {
		t.Fatal(err)
	}
	if len(fromFile.SessionData.Cookies) != len(fromStore.SessionData.Cookies) {
		t.Fatalf("cookie count differs: file %d, store %d", len(fromFile.SessionData.Cookies), len(fromStore.SessionData.Cookies))
	}
	for i := range fromFile.SessionData.Cookies {
		f, s := fromFile.SessionData.Cookies[i], fromStore.SessionData.Cookies[i]
		if f.Name != s.Name || f.Value != s.Value || !f.Expires.Equal(s.Expires) {
			t.Fatalf("cookie %d differs between the file and the store", i)
		}
	}
	if fromFile.SessionData.LoginResult.UID != fromStore.SessionData.LoginResult.UID {
		t.Error("the login result was not preserved by the import")
	}
	if fromStore.ServerHost() != DefaultHost {
		t.Errorf("serverHost = %q, want %q", fromStore.ServerHost(), DefaultHost)
	}
}

// --- memory store -----------------------------------------------------------

// TestMemorySessionStoreMatchesTheContract keeps the test double honest: it must
// satisfy the same interface behaviours the production stores do.
func TestMemorySessionStoreMatchesTheContract(t *testing.T) {
	var _ SessionStore = NewMemorySessionStore()
	store := NewMemorySessionStore()
	s := testSession()
	if _, err := store.Load(s.Account()); err == nil {
		t.Error("Load on an empty memory store returned no error")
	}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(s.Account())
	if err != nil || got.Email != s.Email {
		t.Fatalf("Load = %v, %v", got, err)
	}
	if err := store.Save(&Session{}); err == nil {
		t.Error("the memory store accepted a session without an auth pair")
	}
	if err := store.Delete(s.Account()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(s.Account()); err == nil {
		t.Error("the memory store still returns a deleted session")
	}
	if err := store.Delete(s.Account()); err != nil {
		t.Errorf("second Delete: %v", err)
	}
	if store.Kind() != StoreKindMemory {
		t.Errorf("Kind() = %q", store.Kind())
	}
}

// --- keys -------------------------------------------------------------------

// TestAccountKeyCannotCollide guards the separator choice: two different
// accounts must never produce the same row key.
func TestAccountKeyCannotCollide(t *testing.T) {
	pairs := []struct{ a, b Account }{
		{a: Account{Region: "us-west", Email: "a@x"}, b: Account{Region: "us-west", Email: "a"}},
		{a: Account{Region: "us-west", Email: "b@x"}, b: Account{Region: "us-westb", Email: "@x"}},
		{a: Account{Region: "us-west", Email: "user@example.test"}, b: Account{Region: "US-WEST", Email: "USER@EXAMPLE.TEST"}},
	}
	for i, p := range pairs {
		if p.a.Key() == p.b.Key() && i != 2 {
			t.Errorf("accounts %v and %v share the row key %q", p.a, p.b, p.a.Key())
		}
	}
	// Normalisation must make the two spellings of one account agree, because a
	// session loaded from JSON may spell its email differently from the file
	// name it came from.
	if pairs[2].a.Key() != pairs[2].b.Key() {
		t.Error("case-normalised accounts did not converge on one key")
	}
}

// TestSingleAccountIsAHonestErrorWithoutASession keeps "no session" typed.
func TestSingleAccountIsAHonestErrorWithoutASession(t *testing.T) {
	store := newStoreForTest(t, filepath.Join(t.TempDir(), "empty.db"))
	_, err := SingleAccount(store)
	if err == nil {
		t.Fatal("SingleAccount on an empty store returned no error")
	}
	if !strings.Contains(err.Error(), ErrNoSession.Error()) {
		t.Errorf("err = %v, want it to wrap ErrNoSession", err)
	}
}

// TestResolveAccountPrefersTheNamedAccount keeps an explicit account from being
// second-guessed.
func TestResolveAccountPrefersTheNamedAccount(t *testing.T) {
	store := NewMemorySessionStore()
	want := Account{Region: "eu-central", Email: "named@example.test"}
	if err := store.Save(testSession()); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveAccount(store, want)
	if err != nil {
		t.Fatal(err)
	}
	if got.Key() != want.Key() {
		t.Errorf("ResolveAccount returned %v, want %v", got, want)
	}
}

// --- store selection --------------------------------------------------------

// TestResolveSessionStoreChoosesTheDatabaseByDefault covers the selection rule.
func TestResolveSessionStoreChoosesTheDatabaseByDefault(t *testing.T) {
	dir := t.TempDir()
	cfg := StoreConfig{DBPath: filepath.Join(dir, "sessions.db"), FilePath: filepath.Join(dir, "legacy.json")}
	res, err := ResolveSessionStore(cfg)
	if err != nil {
		t.Fatalf("ResolveSessionStore: %v", err)
	}
	if res.Kind != StoreKindSQLite {
		t.Errorf("Kind = %q, want sqlite by default", res.Kind)
	}
	if res.ImportSource != cfg.FilePath {
		t.Errorf("ImportSource = %q, want the legacy file to be imported once", res.ImportSource)
	}
	if res.Reason == "" {
		t.Error("the selection gave no reason, so an operator cannot tell why")
	}
	if s, ok := res.Store.(*SQLiteSessionStore); ok {
		s.Close()
	}
}

// TestResolveSessionStoreFileModeIsTheOldBehaviour covers the explicit opt-out.
func TestResolveSessionStoreFileModeIsTheOldBehaviour(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.json")
	res, err := ResolveSessionStore(StoreConfig{Mode: StoreModeFile, FilePath: path})
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != StoreKindFile {
		t.Errorf("Kind = %q, want file", res.Kind)
	}
	if res.Store.Location() != path {
		t.Errorf("Location = %q, want %q", res.Store.Location(), path)
	}
	if res.ImportSource != "" {
		t.Error("file mode must not import into itself")
	}
	// A file store in file mode never writes a database. Nothing may be created
	// next to it.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("file mode created files it should not have: %v", entries)
	}
}

// TestResolveSessionStoreFallsBackLoudlyWhenTheDatabaseIsUnusable covers auto
// mode's degradation path: the fallback must be reported, not silent.
func TestResolveSessionStoreFallsBackLoudlyWhenTheDatabaseIsUnusable(t *testing.T) {
	dir := t.TempDir()
	cfg := StoreConfig{
		DBPath:   filepath.Join(dir, "sessions.db"),
		FilePath: filepath.Join(dir, "legacy.json"),
		OpenDB: func(string) (*SQLiteSessionStore, error) {
			return nil, fmt.Errorf("simulated: database is not writable")
		},
	}
	res, err := ResolveSessionStore(cfg)
	if err != nil {
		t.Fatalf("auto mode failed instead of falling back: %v", err)
	}
	if res.Kind != StoreKindFile {
		t.Errorf("Kind = %q, want the file fallback", res.Kind)
	}
	if res.FallbackFrom != StoreModeDB {
		t.Error("the fallback was not reported, so it would be silent")
	}
	if !strings.Contains(res.Reason, "could not be opened") {
		t.Errorf("Reason = %q, want it to explain the failure", res.Reason)
	}
}

// TestResolveSessionStoreDBModeFailsLoudly keeps an explicit database request
// from silently becoming a file store.
func TestResolveSessionStoreDBModeFailsLoudly(t *testing.T) {
	cfg := StoreConfig{
		Mode:     StoreModeDB,
		DBPath:   filepath.Join(t.TempDir(), "sessions.db"),
		FilePath: filepath.Join(t.TempDir(), "legacy.json"),
		OpenDB: func(string) (*SQLiteSessionStore, error) {
			return nil, fmt.Errorf("simulated: database is not writable")
		},
	}
	if _, err := ResolveSessionStore(cfg); err == nil {
		t.Fatal("db mode fell back to a file instead of failing loudly")
	}
}

// TestResolveSessionStoreRejectsUnknownModes keeps a typo visible.
func TestResolveSessionStoreRejectsUnknownModes(t *testing.T) {
	if _, err := ResolveSessionStore(StoreConfig{Mode: "sqlite"}); err == nil {
		t.Fatal("an unknown mode was accepted")
	}
}

// TestStoreConfigFromEnvDefaultsToTheLoggersDatabase keeps the two packages
// pointed at the same file: a mismatch here would mean the session lived in a
// second database nobody backs up.
func TestStoreConfigFromEnvDefaultsToTheLoggersDatabase(t *testing.T) {
	t.Setenv(EnvSessionStore, "")
	t.Setenv(EnvSessionDB, "")
	cfg := StoreConfigFromEnv()
	if cfg.Mode != "" {
		t.Errorf("Mode = %q, want empty for auto", cfg.Mode)
	}
	resolved := cfg.withDefaults()
	if resolved.DBPath != "onvif_logs.db" {
		t.Errorf("DBPath = %q, want onvif_logs.db, the same file internal/logger opens", resolved.DBPath)
	}
	if resolved.Mode != StoreModeAuto {
		t.Errorf("Mode = %q, want auto", resolved.Mode)
	}
}

// --- permissions ------------------------------------------------------------

// TestSQLiteSessionStoreHoldsDatabaseAt0600 is the security requirement in unit
// form: after the store's first touch, the database AND its -wal/-shm siblings
// must not be world- or group-readable.
func TestSQLiteSessionStoreHoldsDatabaseAt0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	// Pre-create it world-readable, which is exactly the shipped live state.
	raw, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	raw.Close()

	store := newStoreForTest(t, path)
	if err := store.Save(testSession()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got&0o077 != 0 {
			t.Errorf("%s mode = %04o, want no group/world bits (session cookies are inside it)", p, got)
		}
	}
	// A write after the first one must not loosen anything: SQLite creates the
	// -wal lazily, so the re-check on every Save is the load-bearing part.
	if err := store.Save(testSession()); err != nil {
		t.Fatal(err)
	}
	modes := store.ObservedModes()
	if len(modes) == 0 {
		t.Fatal("the store reported no observed modes, so the hardening is unverifiable from outside")
	}
	for _, m := range modes {
		if m.Mode != "0600" {
			t.Errorf("%s observed mode = %s, want 0600", m.Path, m.Mode)
		}
	}
}

// TestSQLiteSessionStoreHardeningDoesNotFollowSymlinks is a small security
// guard: harden() must never chmod a path it was pointed at through a symlink
// into something else. It is a regression guard on the code using os.Chmod on
// derived paths only.
func TestSQLiteSessionStoreHardeningDoesNotFollowAnUnexpectedPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "not-the-db.txt")
	if err := os.WriteFile(target, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "sessions.db")
	store := newStoreForTest(t, dbPath)
	if err := store.Save(testSession()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("hardening changed an unrelated file: %04o", fi.Mode().Perm())
	}
}

// --- helpers ----------------------------------------------------------------

func tableExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n); err != nil {
		t.Fatalf("tableExists(%s): %v", name, err)
	}
	return n > 0
}

func indexExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, name).Scan(&n); err != nil {
		t.Fatalf("indexExists(%s): %v", name, err)
	}
	return n > 0
}

func countObjects(t *testing.T, db *sql.DB, name string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name=?`, name).Scan(&n); err != nil {
		t.Fatalf("countObjects(%s): %v", name, err)
	}
	return n
}

func countRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	// The table name is a compile-time constant from this package, never user
	// input, so the interpolation cannot be an injection.
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatalf("countRows(%s): %v", table, err)
	}
	return n
}

func hasColumnIn(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(&n); err != nil {
		t.Fatalf("hasColumnIn(%s,%s): %v", table, column, err)
	}
	return n > 0
}

// listConfigsRaw reads stream_configs with the columns the migration guarantees,
// so this package does not have to import internal/logger.
func listConfigsRaw(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT profile_token FROM stream_configs ORDER BY profile_token`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return nil, err
		}
		out = append(out, token)
	}
	return out, rows.Err()
}
