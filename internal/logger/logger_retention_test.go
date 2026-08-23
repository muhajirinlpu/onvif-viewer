package logger

import (
	"fmt"
	"path/filepath"
	"testing"
)

func TestLoggerRetainsOnlyConfiguredNumberOfRows(t *testing.T) {
	l, err := newLogger(filepath.Join(t.TempDir(), "logs.db"), 10, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	for i := 0; i < 25; i++ {
		l.LogInfo("stream", "test", fmt.Sprintf("message-%d", i))
	}

	var count int
	if err := l.db.QueryRow("SELECT COUNT(*) FROM stream_logs").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 10 {
		t.Fatalf("retained %d rows, want 10", count)
	}

	logs, err := l.GetRecentLogs(10)
	if err != nil {
		t.Fatal(err)
	}
	if logs[0].Message != "message-24" || logs[len(logs)-1].Message != "message-15" {
		t.Fatalf("unexpected retained range: newest=%q oldest=%q", logs[0].Message, logs[len(logs)-1].Message)
	}
}

func TestLoggerPrunesExistingDatabaseOnOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs.db")
	l, err := newLogger(path, 100, 100)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		l.LogInfo("stream", "test", fmt.Sprintf("old-%d", i))
	}
	l.Close()

	l, err = newLogger(path, 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var count int
	if err := l.db.QueryRow("SELECT COUNT(*) FROM stream_logs").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 10 {
		t.Fatalf("startup retained %d rows, want 10", count)
	}
}

func TestLoggerInvalidRetentionUsesDefaultBeforeStartupPrune(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs.db")
	l, err := newLogger(path, 100, 100)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		l.LogInfo("stream", "test", fmt.Sprintf("old-%d", i))
	}
	l.Close()
	l, err = newLogger(path, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var count int
	if err := l.db.QueryRow("SELECT COUNT(*) FROM stream_logs").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 25 {
		t.Fatalf("invalid retention unexpectedly pruned to %d rows", count)
	}
}
