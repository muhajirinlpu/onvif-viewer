package main

// A scripted, read-only-ish rehearsal of the real upgrade: the user's live
// onvif_logs.db (copied, never touched in place) is opened through NewLogger and
// then through the M8 SQLite session store. This is the exact code path a restart
// of the real install takes.
//
// It reports, with raw numbers:
//   - the stream_configs columns and row count BEFORE and AFTER,
//   - the full sqlite_master table list BEFORE and AFTER,
//   - the stream_logs row count BEFORE and AFTER,
//   - whether the M8 session table appeared and how many rows it holds,
//   - the permissions of the database and its -wal/-shm AFTER,
//   - a repeat run, which must change nothing.
//
// Run with: go run ./cmd/migration_rehearsal <path-to-copied-db> [session-file-to-import]
//
// It never prints a credential value: cookie NAMES and counts only.

import (
	"database/sql"
	"fmt"
	"os"
	"sort"

	_ "github.com/mattn/go-sqlite3"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/tuyaqr"
)

type snapshot struct {
	tables         []string
	configColumns  []string
	configRows     int
	logRows        int
	sessionRows    int
	sessionColumns []string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: migration_rehearsal <db path> [session-file-to-import]")
		os.Exit(2)
	}
	path := os.Args[1]
	importSource := ""
	if len(os.Args) > 2 {
		importSource = os.Args[2]
	}

	fmt.Println("### 1. BEFORE (the copy, untouched)")
	before := describe(path)
	printSnapshot(before)

	fmt.Println("\n### 2. open through logger.NewLogger (the M4 migration path)")
	l, err := logger.NewLogger(path)
	if err != nil {
		fmt.Printf("NewLogger FAILED: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n### 3. open the M8 SQLite session store on the SAME database")
	store, err := tuyaqr.NewSQLiteSessionStoreFromDB(l.DB(), l.Path())
	if err != nil {
		fmt.Printf("NewSQLiteSessionStoreFromDB FAILED: %v\n", err)
		l.Close()
		os.Exit(1)
	}
	fmt.Printf("session store kind=%s location=%s\n", store.Kind(), store.Location())

	fmt.Println("\n### 4. AFTER the migration")
	after := describe(path)
	printSnapshot(after)

	// --- the rehearsal's whole point ------------------------------------------
	fmt.Println("\n### 5. legacy data must be untouched")
	ok := true
	if before.logRows != after.logRows {
		fmt.Printf("FAIL stream_logs rows %d -> %d\n", before.logRows, after.logRows)
		ok = false
	} else {
		fmt.Printf("PASS stream_logs rows unchanged: %d\n", after.logRows)
	}
	if before.configRows != after.configRows {
		fmt.Printf("FAIL stream_configs rows %d -> %d\n", before.configRows, after.configRows)
		ok = false
	} else {
		fmt.Printf("PASS stream_configs rows unchanged: %d\n", after.configRows)
	}
	for _, t := range before.tables {
		if t == "sqlite_sequence" {
			continue
		}
		if !contains(after.tables, t) {
			fmt.Printf("FAIL the pre-existing table %s disappeared\n", t)
			ok = false
		}
	}
	if ok {
		fmt.Println("PASS every pre-existing table is still present")
	}
	if !contains(after.tables, tuyaqr.TableSession) {
		fmt.Printf("FAIL the M8 session table %s was not created\n", tuyaqr.TableSession)
		ok = false
	} else {
		fmt.Printf("PASS the M8 session table %s exists with columns %v\n", tuyaqr.TableSession, after.sessionColumns)
	}

	// --- files -----------------------------------------------------------------
	fmt.Println("\n### 6. permissions after the migration")
	printModes(path)

	configs, err := l.ListStreamConfigs()
	if err != nil {
		fmt.Printf("ListStreamConfigs FAILED: %v\n", err)
	} else {
		fmt.Printf("restorable stream configs: %d\n", len(configs))
		for i, c := range configs {
			if i >= 10 {
				fmt.Println("  ...")
				break
			}
			fmt.Printf("  token=%q provider=%q url_len=%d\n", c.ProfileToken, c.Provider, len(c.RTSPURL))
		}
	}
	l.Close()

	// --- the import ------------------------------------------------------------
	if importSource != "" {
		fmt.Printf("\n### 7. one-time import from %s\n", importSource)
		runImport(path, importSource)
		// Re-snapshot: the import legitimately adds session rows, so the
		// no-op comparison below must be taken from AFTER it.
		after = describe(path)
		fmt.Println("\n### 7b. AFTER the import")
		printSnapshot(after)
		printModes(path)
	}

	// --- the repeat run --------------------------------------------------------
	fmt.Println("\n### 8. repeat run (must be a no-op)")
	l2, err := logger.NewLogger(path)
	if err != nil {
		fmt.Printf("second NewLogger FAILED: %v\n", err)
		os.Exit(1)
	}
	store2, err := tuyaqr.NewSQLiteSessionStoreFromDB(l2.DB(), l2.Path())
	if err != nil {
		fmt.Printf("second session store FAILED: %v\n", err)
		l2.Close()
		os.Exit(1)
	}
	_ = store2
	second := describe(path)
	printSnapshot(second)
	if second.logRows != after.logRows || second.configRows != after.configRows || second.sessionRows != after.sessionRows {
		fmt.Printf("FAIL the repeat run changed data: logs %d->%d configs %d->%d sessions %d->%d\n",
			after.logRows, second.logRows, after.configRows, second.configRows, after.sessionRows, second.sessionRows)
		ok = false
	} else {
		fmt.Printf("PASS the repeat run was a no-op (logs=%d configs=%d sessions=%d)\n",
			second.logRows, second.configRows, second.sessionRows)
	}
	l2.Close()

	// --- a third run on the same already-migrated database ----------------------
	third, err := tuyaqr.NewSQLiteSessionStore(path)
	if err != nil {
		fmt.Printf("third open FAILED: %v\n", err)
		os.Exit(1)
	}
	third.Close()
	after3 := describe(path)
	if after3.sessionRows != second.sessionRows || after3.logRows != second.logRows {
		fmt.Printf("FAIL a third migration pass changed data\n")
		ok = false
	} else {
		fmt.Println("PASS a third migration pass was also a no-op")
	}

	fmt.Println()
	if !ok {
		fmt.Println("REHEARSAL RESULT: FAILED")
		os.Exit(1)
	}
	fmt.Println("REHEARSAL RESULT: PASSED - the legacy data is intact and the session table is additive")
}

func runImport(dbPath, src string) {
	store, err := tuyaqr.NewSQLiteSessionStore(dbPath)
	if err != nil {
		fmt.Printf("open for import FAILED: %v\n", err)
		return
	}
	defer store.Close()

	srcInfo, _ := os.Stat(src)
	if srcInfo != nil {
		fmt.Printf("import source: %s mode=%04o size=%d\n", src, srcInfo.Mode().Perm(), srcInfo.Size())
	}

	for i := 1; i <= 2; i++ {
		res, err := tuyaqr.ImportSessionFile(store, src)
		if err != nil {
			fmt.Printf("  run %d FAILED: %v\n", i, err)
			return
		}
		// Names and counts only: never a value.
		fmt.Printf("  run %d: imported=%t alreadyStored=%t account=%s/%s cookies=%d names=%v dest=%s\n",
			i, res.Imported, res.AlreadyStored, res.Region, res.Email, res.CookieCount, res.CookieNames, res.DestKind)
		if res.Imported {
			fmt.Printf("           detail: %s\n", res.Detail)
		}
		rows := sessionRowCount(dbPath)
		fmt.Printf("           %s row count now: %d\n", tuyaqr.TableSession, rows)
	}

	if srcInfo != nil {
		if after, err := os.Stat(src); err == nil {
			if after.Mode().Perm() != srcInfo.Mode().Perm() || after.Size() != srcInfo.Size() || !after.ModTime().Equal(srcInfo.ModTime()) {
				fmt.Printf("FAIL the import modified the source file (mode %04o->%04o size %d->%d mtime %s->%s)\n",
					srcInfo.Mode().Perm(), after.Mode().Perm(), srcInfo.Size(), after.Size(), srcInfo.ModTime(), after.ModTime())
			} else {
				fmt.Printf("PASS the source file is untouched (mode=%04o size=%d mtime unchanged)\n", after.Mode().Perm(), after.Size())
			}
		}
	}
	// The stored session must be usable, and no value is printed.
	accounts, err := store.Accounts()
	if err != nil {
		fmt.Printf("  Accounts FAILED: %v\n", err)
		return
	}
	for _, a := range accounts {
		fmt.Printf("  stored: account=%s cookies=%d hasAuthPair=%t updatedAt=%s\n",
			a.Account, a.CookieCount, a.HasAuthPair, a.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"))
	}
}

func printModes(path string) {
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Stat(p)
		if err != nil {
			fmt.Printf("  %s MISSING\n", p)
			continue
		}
		verdict := "owner-only"
		if fi.Mode().Perm()&0o077 != 0 {
			verdict = "GROUP/WORLD ACCESSIBLE"
		}
		fmt.Printf("  %04o %s (%s)\n", fi.Mode().Perm(), p, verdict)
	}
}

func printSnapshot(s snapshot) {
	fmt.Printf("  tables: %v\n", s.tables)
	fmt.Printf("  stream_configs columns: %v\n", s.configColumns)
	fmt.Printf("  stream_configs rows: %d\n", s.configRows)
	fmt.Printf("  stream_logs rows: %d\n", s.logRows)
	fmt.Printf("  %s rows: %d\n", tuyaqr.TableSession, s.sessionRows)
	if len(s.sessionColumns) > 0 {
		fmt.Printf("  %s columns: %v\n", tuyaqr.TableSession, s.sessionColumns)
	}
}

func describe(path string) snapshot {
	var out snapshot
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		fmt.Printf("  open: %v\n", err)
		return out
	}
	defer db.Close()

	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`)
	if err != nil {
		fmt.Printf("  tables: %v\n", err)
		return out
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err == nil {
			out.tables = append(out.tables, n)
		}
	}
	rows.Close()
	sort.Strings(out.tables)

	out.configColumns = columns(db, "stream_configs")
	out.sessionColumns = columns(db, tuyaqr.TableSession)
	out.configRows = count(db, "stream_configs")
	out.logRows = count(db, "stream_logs")
	if contains(out.tables, tuyaqr.TableSession) {
		out.sessionRows = count(db, tuyaqr.TableSession)
	}
	return out
}

func columns(db *sql.DB, table string) []string {
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func count(db *sql.DB, table string) int {
	if !safeName(table) {
		return -1
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		// A table that does not exist yet counts as zero.
		return 0
	}
	return n
}

func sessionRowCount(path string) int {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return -1
	}
	defer db.Close()
	return count(db, tuyaqr.TableSession)
}

// safeName keeps the interpolated identifiers to the fixed table names this tool
// knows about, so the COUNT query cannot become an injection.
func safeName(name string) bool {
	for _, r := range name {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && r != '_' {
			return false
		}
	}
	return name != ""
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
