package main

// A scripted, read-only-ish rehearsal of the real upgrade: the user's live
// onvif_logs.db (copied, never touched in place) is opened through NewLogger.
// This is the exact code path a restart of the real install takes.
//
// Run with: go run ./cmd/migration_rehearsal <path-to-copied-db>

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/mattn/go-sqlite3"

	"dengan.dev/camera-streamer/internal/logger"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: migration_rehearsal <db path>")
		os.Exit(2)
	}
	path := os.Args[1]

	fmt.Println("== before ==")
	describe(path)

	l, err := logger.NewLogger(path)
	if err != nil {
		fmt.Printf("NewLogger FAILED: %v\n", err)
		os.Exit(1)
	}
	defer l.Close()

	fmt.Println("== after ==")
	describe(path)

	configs, err := l.ListStreamConfigs()
	if err != nil {
		fmt.Printf("ListStreamConfigs FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("restorable stream configs: %d\n", len(configs))
	for i, c := range configs {
		if i >= 10 {
			fmt.Println("  ...")
			break
		}
		// Only the token shape and the provider: the RTSP URL is not printed.
		fmt.Printf("  token=%q provider=%q url_len=%d\n", c.ProfileToken, c.Provider, len(c.RTSPURL))
	}

	// Second open: a repeat run must be a no-op that keeps working.
	l2, err := logger.NewLogger(path)
	if err != nil {
		fmt.Printf("second NewLogger FAILED: %v\n", err)
		os.Exit(1)
	}
	defer l2.Close()
	again, err := l2.ListStreamConfigs()
	if err != nil {
		fmt.Printf("second ListStreamConfigs FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("repeat-run configs: %d (must match %d)\n", len(again), len(configs))

	// The legacy log table must still be intact: the migration must not touch it.
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		fmt.Printf("open for count FAILED: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()
	var logs int
	if err := db.QueryRow(`SELECT COUNT(*) FROM stream_logs`).Scan(&logs); err != nil {
		fmt.Printf("stream_logs count FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("stream_logs rows preserved: %d\n", logs)
}

func describe(path string) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		fmt.Printf("  open: %v\n", err)
		return
	}
	defer db.Close()

	rows, err := db.Query(`SELECT name FROM pragma_table_info('stream_configs')`)
	if err != nil {
		fmt.Printf("  schema: %v\n", err)
		return
	}
	var cols []string
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		cols = append(cols, n)
	}
	rows.Close()
	fmt.Printf("  stream_configs columns: %v\n", cols)

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM stream_configs`).Scan(&n); err != nil {
		fmt.Printf("  count: %v\n", err)
		return
	}
	fmt.Printf("  stream_configs rows: %d\n", n)
}
