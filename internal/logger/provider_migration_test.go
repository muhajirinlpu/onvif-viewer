package logger

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// legacySchema is the exact stream_configs DDL shipped before the provider
// column existed. The migration must upgrade a database created with it.
const legacySchema = `CREATE TABLE stream_configs (
    profile_token TEXT PRIMARY KEY,
    rtsp_url TEXT NOT NULL,
    updated_at DATETIME NOT NULL
);`

func columnNames(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func hasColumn(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// Case 1: fresh database. The column must exist right after NewLogger and the
// schema must be complete.
func TestProviderMigrationOnFreshDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.db")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger on fresh DB: %v", err)
	}
	defer l.Close()

	if names := columnNames(t, l.db, "stream_configs"); !hasColumn(names, "provider") {
		t.Fatalf("fresh DB stream_configs columns = %v, want provider present", names)
	}
	// The default must be the literal onvif, applied by SQLite itself.
	var dflt sql.NullString
	if err := l.db.QueryRow(`SELECT dflt_value FROM pragma_table_info('stream_configs') WHERE name='provider'`).Scan(&dflt); err != nil {
		t.Fatal(err)
	}
	if dflt.String != "'onvif'" {
		t.Fatalf("provider default = %q, want 'onvif'", dflt.String)
	}
	if err := l.UpsertStreamConfig("tok", "rtsp://cam/live", ""); err != nil {
		t.Fatal(err)
	}
	configs, err := l.ListStreamConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 1 || configs[0].Provider != "onvif" {
		t.Fatalf("configs = %#v, want one row with provider onvif", configs)
	}
}

// Case 2: an EXISTING populated database with no provider column. This is the
// shape of the user's real onvif_logs.db. The rows must survive and be
// backfilled to onvif, and Tuya rows written afterwards must round-trip.
func TestProviderMigrationOnPopulatedLegacyDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(legacySchema); err != nil {
		t.Fatal(err)
	}
	legacyRows := []struct{ token, url string }{
		{"onvif-token-a", "rtsp://admin:secret@10.0.0.4:554/live"},
		{"onvif-token-b", "rtsp://admin:secret@10.0.0.5:554/live"},
	}
	for _, r := range legacyRows {
		if _, err := raw.Exec(`INSERT INTO stream_configs(profile_token, rtsp_url, updated_at) VALUES(?,?,datetime('now'))`, r.token, r.url); err != nil {
			t.Fatal(err)
		}
	}
	if names := columnNames(t, raw, "stream_configs"); hasColumn(names, "provider") {
		t.Fatalf("precondition failed: legacy DB already had provider (%v)", names)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	// Open it through the real constructor: this is the upgrade path a running
	// install takes on restart.
	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger on legacy DB: %v", err)
	}
	defer l.Close()

	if names := columnNames(t, l.db, "stream_configs"); !hasColumn(names, "provider") {
		t.Fatalf("post-migration columns = %v, want provider present", names)
	}
	configs, err := l.ListStreamConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != len(legacyRows) {
		t.Fatalf("migration changed the row count: got %d, want %d (%#v)", len(configs), len(legacyRows), configs)
	}
	for i, want := range legacyRows {
		if configs[i].ProfileToken != want.token || configs[i].RTSPURL != want.url {
			t.Fatalf("legacy row %d was altered: %#v", i, configs[i])
		}
		if configs[i].Provider != "onvif" {
			t.Fatalf("legacy row %d provider = %q, want onvif", i, configs[i].Provider)
		}
	}

	// A Tuya stream must persist as Tuya next to the backfilled ONVIF rows.
	if err := l.UpsertStreamConfig("tuya:eb9f1d6e677b1b39f222ag", "rtsp://127.0.0.1:8554/tuya_eb9f1d6e677b1b39f222ag", "tuya"); err != nil {
		t.Fatal(err)
	}
	configs, err = l.ListStreamConfigs()
	if err != nil {
		t.Fatal(err)
	}
	byToken := map[string]string{}
	for _, c := range configs {
		byToken[c.ProfileToken] = c.Provider
	}
	if byToken["tuya:eb9f1d6e677b1b39f222ag"] != "tuya" {
		t.Fatalf("tuya row provider = %q, want tuya", byToken["tuya:eb9f1d6e677b1b39f222ag"])
	}
	if byToken["onvif-token-a"] != "onvif" || byToken["onvif-token-b"] != "onvif" {
		t.Fatalf("legacy rows lost their default provider: %#v", byToken)
	}

	// Upserting an existing token must also update its provider.
	if err := l.UpsertStreamConfig("onvif-token-a", "rtsp://admin:secret@10.0.0.4:554/live", "tuya"); err != nil {
		t.Fatal(err)
	}
	configs, _ = l.ListStreamConfigs()
	for _, c := range configs {
		if c.ProfileToken == "onvif-token-a" && c.Provider != "tuya" {
			t.Fatalf("upsert did not update provider: %#v", c)
		}
	}
}

// Case 3: the migration runs again on an already-migrated database. It must be
// a no-op that neither errors nor duplicates the column.
func TestProviderMigrationIsRepeatable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repeat.db")
	for i := 0; i < 3; i++ {
		l, err := NewLogger(path)
		if err != nil {
			t.Fatalf("open #%d: %v", i, err)
		}
		names := columnNames(t, l.db, "stream_configs")
		count := 0
		for _, n := range names {
			if n == "provider" {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("open #%d: provider appears %d times in %v", i, count, names)
		}
		if i == 0 {
			if err := l.UpsertStreamConfig("keep-me", "rtsp://cam/live", "tuya"); err != nil {
				t.Fatal(err)
			}
		}
		l.Close()
	}

	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	configs, err := l.ListStreamConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 1 || configs[0].ProfileToken != "keep-me" || configs[0].Provider != "tuya" {
		t.Fatalf("repeated migration disturbed the data: %#v", configs)
	}
}

// A NULL/empty provider stored by some other writer must still be reported as
// ONVIF rather than as an empty string.
func TestListStreamConfigsDefaultsEmptyProviderToONVIF(t *testing.T) {
	l, err := NewLogger(filepath.Join(t.TempDir(), "empty.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.db.Exec(`INSERT INTO stream_configs(profile_token, rtsp_url, provider, updated_at) VALUES('blank','rtsp://cam/live','',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	configs, err := l.ListStreamConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 1 || configs[0].Provider != "onvif" {
		t.Fatalf("empty provider not normalised: %#v", configs)
	}
}
