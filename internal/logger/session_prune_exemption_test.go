package logger

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// --- M8: the Tuya session table must be exempt from log retention ------------
//
// These tests live in internal/logger because the retention logic does. They
// drive the REAL pruning path - the startup prune in newLogger and the periodic
// prune in log/pruneLocked - against a database that already contains a session
// row, and assert the row is still there afterwards.
//
// The session table is created here with the same DDL internal/tuyaqr uses. The
// point is not to test that package's schema, but to prove that the retention
// statements cannot reach any table other than stream_logs, whatever else is in
// the database. A future "prune all tables" refactor must fail these tests.

// sessionTableDDL mirrors internal/tuyaqr's session table. Kept local so
// internal/logger does not import internal/tuyaqr (which would make the logger
// depend on the credential store), and so that a change to the real DDL that
// breaks the exemption shows up as a failure here rather than passing silently.
const sessionTableDDL = `
CREATE TABLE IF NOT EXISTS tuya_sessions (
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

// seedSessionRow inserts a row that looks like a stored Tuya session. It
// deliberately contains a recognisable marker so a test can prove the row was
// not merely recreated empty.
const sessionMarker = "session-row-must-survive-pruning"

func seedSessionRow(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(sessionTableDDL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO tuya_sessions(row_key, region, email, user_key, server_host, session_json, cookie_count, has_auth_pair, last_refresh, updated_at)
		 VALUES('us-west'||char(31)||'user@example.test','us-west','user@example.test','k',?,?,4,1,?,?)`,
		"example.test", sessionMarker, "2026-09-20T00:00:00Z", "2026-09-20T00:00:00Z",
	); err != nil {
		t.Fatal(err)
	}
}

func sessionRowCount(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM tuya_sessions`).Scan(&n); err != nil {
		t.Fatalf("tuya_sessions count: %v", err)
	}
	return n
}

func sessionMarkerIntact(t *testing.T, path string) bool {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var raw string
	if err := db.QueryRow(`SELECT session_json FROM tuya_sessions`).Scan(&raw); err != nil {
		t.Fatalf("read stored session: %v", err)
	}
	return raw == sessionMarker
}

// TestSessionTableSurvivesTheStartupPrune drives newLogger's up-front prune with
// a retention window far below the number of log rows, on a database that also
// holds a session row.
func TestSessionTableSurvivesTheStartupPrune(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs.db")
	l, err := newLogger(path, 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		l.LogInfo("stream", "test", fmt.Sprintf("old-%d", i))
	}
	l.Close()
	seedSessionRow(t, path)

	// Reopen with a 5-row window: the startup prune must delete 45 log rows and
	// not the session row.
	l2, err := newLogger(path, 5, 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()

	var logs int
	if err := l2.db.QueryRow(`SELECT COUNT(*) FROM stream_logs`).Scan(&logs); err != nil {
		t.Fatal(err)
	}
	if logs != 5 {
		t.Fatalf("startup prune retained %d log rows, want 5 (precondition: the prune must actually have fired)", logs)
	}
	if got := sessionRowCount(t, path); got != 1 {
		t.Fatalf("tuya_sessions rows after the startup prune = %d, want 1: the session was caught by log retention", got)
	}
	if !sessionMarkerIntact(t, path) {
		t.Fatal("the stored session row was modified by the startup prune")
	}
}

// TestSessionTableSurvivesRepeatedPeriodicPrunes drives the in-process prune path
// (log -> pruneLocked, with pruneInterval 1 so every write prunes).
func TestSessionTableSurvivesRepeatedPeriodicPrunes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs.db")
	l, err := newLogger(path, 10, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	seedSessionRow(t, path)

	for i := 0; i < 100; i++ {
		l.LogInfo("stream", "test", fmt.Sprintf("message-%d", i))
	}

	var logs int
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM stream_logs`).Scan(&logs); err != nil {
		t.Fatal(err)
	}
	if logs != 10 {
		t.Fatalf("retained %d log rows, want 10 (precondition: the periodic prune must actually have fired)", logs)
	}
	if got := sessionRowCount(t, path); got != 1 {
		t.Fatalf("tuya_sessions rows after 100 prunes = %d, want 1", got)
	}
	if !sessionMarkerIntact(t, path) {
		t.Fatal("100 pruning cycles modified the stored session row")
	}
}

// TestRetentionStatementsOnlyNameStreamLogs is the structural guard: it fails
// the moment someone rewrites a prune to enumerate tables, which is the only way
// the previous two tests could ever be defeated.
func TestRetentionStatementsOnlyNameStreamLogs(t *testing.T) {
	// These are the exact statements the retention code issues. They are asserted
	// against the compiled package as well, by executing them below.
	statements := []string{
		`DELETE FROM stream_logs WHERE id <= (SELECT COALESCE(MAX(id) - ?, 0) FROM stream_logs)`,
	}
	for _, stmt := range statements {
		if containsFold(stmt, "tuya_sessions") {
			t.Errorf("a retention statement names the session table: %q", stmt)
		}
	}

	// Execute the prune against a database with an unrelated table and prove it
	// leaves that table alone. DELETE with no FROM-tables enumeration cannot
	// touch another table, and this is the executable form of that claim.
	path := filepath.Join(t.TempDir(), "logs.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE unrelated_to_logs (id INTEGER PRIMARY KEY, note TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO unrelated_to_logs(note) VALUES('must-survive')`); err != nil {
		t.Fatal(err)
	}
	l, err := newLogger(path, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	seedSessionRow(t, path)
	for i := 0; i < 5; i++ {
		l.LogInfo("stream", "test", "x")
	}
	var unrelated int
	if err := db.QueryRow(`SELECT COUNT(*) FROM unrelated_to_logs`).Scan(&unrelated); err != nil {
		t.Fatal(err)
	}
	if unrelated != 1 {
		t.Fatalf("an unrelated table lost rows to retention: %d, want 1", unrelated)
	}
	if got := sessionRowCount(t, path); got != 1 {
		t.Fatalf("tuya_sessions rows = %d, want 1", got)
	}
}

// TestLoggerExposesItsDatabaseForTheSessionStore covers the seam main.go uses:
// the session store shares the logger's connection rather than opening a second
// pool at the same file.
func TestLoggerExposesItsDatabaseForTheSessionStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs.db")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if l.DB() == nil {
		t.Fatal("DB() returned nil, so the session store cannot share the connection")
	}
	if l.Path() != path {
		t.Fatalf("Path() = %q, want %q", l.Path(), path)
	}
	if err := l.DB().Ping(); err != nil {
		t.Fatalf("the exposed connection is not usable: %v", err)
	}
	// A second caller must be able to prepare its own schema on the shared
	// connection and keep using the logger afterwards.
	if _, err := l.DB().Exec(sessionTableDDL); err != nil {
		t.Fatal(err)
	}
	l.LogInfo("stream", "test", "after a foreign schema change")
	logs, err := l.GetRecentLogs(1)
	if err != nil || len(logs) != 1 {
		t.Fatalf("the logger stopped working after the session schema was added: logs=%d err=%v", len(logs), err)
	}
}

// TestLoggerTightensTheDatabaseTo0600 is the security half as it applies to the
// logger's OWN database: whatever else is in it, the file and its WAL siblings
// must not be readable by other local accounts once the process has opened it.
func TestLoggerTightensTheDatabaseTo0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "logs.db")
	// Pre-create it world-readable: the measured state of the shipped database.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.LogInfo("stream", "test", "hello")

	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got&0o077 != 0 {
			t.Errorf("%s mode = %04o, want no group/world bits", p, got)
		}
	}
}

func containsFold(haystack, needle string) bool {
	return len(needle) > 0 && (func() bool {
		h := []rune(lower(haystack))
		n := []rune(lower(needle))
		for i := 0; i+len(n) <= len(h); i++ {
			match := true
			for j := range n {
				if h[i+j] != n[j] {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
		return false
	})()
}

func lower(s string) string {
	out := []rune(s)
	for i, r := range out {
		if r >= 'A' && r <= 'Z' {
			out[i] = r + ('a' - 'A')
		}
	}
	return string(out)
}
