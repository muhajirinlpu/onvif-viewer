package logger

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// LogLevel defines the level of a log message
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR

	defaultMaxRows       = 100000
	defaultPruneInterval = 1000
)

// StreamLog represents a log entry in the database
type StreamLog struct {
	ID        int       `json:"id"`
	StreamID  string    `json:"streamId"`
	Timestamp time.Time `json:"timestamp"`
	Level     LogLevel  `json:"level"`
	Source    string    `json:"source"`
	Message   string    `json:"message"`
}

// StreamConfig is the minimal persisted configuration needed to restore a stream.
type StreamConfig struct {
	ProfileToken string
	RTSPURL      string
	Provider     string
}

// defaultProvider is the provider value applied to legacy rows and used when a
// caller does not name one.
const defaultProvider = "onvif"

// Logger handles database logging
type Logger struct {
	db            *sql.DB
	path          string
	mutex         sync.Mutex
	maxRows       int
	pruneInterval int
	writes        int
}

// FileMode is the observed permission of one file the database consists of.
// It is a label for an operator, never a secret.
type FileMode struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

// HardenDatabaseFiles tightens a SQLite database and its -wal/-shm companions to
// 0600, creating the parent directory 0700 if needed.
//
// WHY THIS EXISTS, MEASURED: the shipped database was
// `-rw-r--r-- ... onvif_logs.db` — mode 0644, i.e. readable by every local
// account. That was harmless while the database held only logs and stream
// configs, and it stops being harmless the moment session cookies live in it.
// Rather than making the whole database secret-by-obscurity (the logs are not
// secret, and denying them to a co-operating local admin is not the goal), the
// file is tightened to owner-only, which is exactly the protection the session
// had as a 0600 JSON file and no more.
//
// ORDER MATTERS and was MEASURED: libsqlite3 creates the journal and the
// shared-memory file with the DATABASE's permission bits. Tightening the
// database first therefore makes -wal and -shm come out 0600 from birth. The
// explicit chmod of the siblings afterwards is the belt to that braces, because
// a database left 0644 by an older build already HAS 0644 siblings on disk, and
// this is what fixes those in place without a checkpoint or a restart.
//
// Returning the observed modes lets the caller report what is actually on disk
// rather than what was intended.
func HardenDatabaseFiles(dbPath string) ([]FileMode, error) {
	if strings.TrimSpace(dbPath) == "" {
		return nil, nil
	}
	if dir := filepath.Dir(dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}
	// A database that does not exist yet must be CREATED 0600, not created by
	// SQLite under the process umask and then tightened: between those two
	// moments the file would be world-readable with the session already in it.
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		f, createErr := os.OpenFile(dbPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if createErr != nil && !os.IsExist(createErr) {
			return nil, fmt.Errorf("create database %s: %w", dbPath, createErr)
		}
		if createErr == nil {
			f.Close()
		}
	}
	var observed []FileMode
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("tighten %s: %w", p, err)
		}
		if fi, statErr := os.Stat(p); statErr == nil {
			observed = append(observed, FileMode{Path: p, Mode: fmt.Sprintf("%04o", fi.Mode().Perm())})
		}
	}
	return observed, nil
}

// NewLogger creates a new logger and initializes the database.
func NewLogger(dbPath string) (*Logger, error) {
	return newLogger(dbPath, defaultMaxRows, defaultPruneInterval)
}

func newLogger(dbPath string, maxRows, pruneInterval int) (*Logger, error) {
	// The database is a credential-bearing store now (internal/tuyaqr keeps Tuya
	// sessions in it), so it and its journal siblings are held at 0600 BEFORE
	// anything opens them. This is also what fixes an already-deployed 0644
	// onvif_logs.db: the next restart tightens it in place.
	if _, err := HardenDatabaseFiles(dbPath); err != nil {
		return nil, fmt.Errorf("failed to secure the database file: %w", err)
	}
	// Enable WAL mode and shared cache to massively accelerate concurrent read/writes
	dsn := fmt.Sprintf("%s?cache=shared&mode=rwc&_journal_mode=WAL&_busy_timeout=5000", dbPath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Create table if it doesn't exist
	query := `
    CREATE TABLE IF NOT EXISTS stream_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stream_id TEXT,
        timestamp DATETIME,
        level INTEGER,
        source TEXT,
        message TEXT
    );
    CREATE TABLE IF NOT EXISTS stream_configs (
        profile_token TEXT PRIMARY KEY,
        rtsp_url TEXT NOT NULL,
        updated_at DATETIME NOT NULL
    );`
	if _, err := db.Exec(query); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create table: %w", err)
	}
	if maxRows < 1 {
		maxRows = defaultMaxRows
	}
	if pruneInterval < 1 {
		pruneInterval = defaultPruneInterval
	}
	// Enforce retention before index creation so an oversized legacy database does not
	// require expensive full-table index builds at startup.
	if _, err := db.Exec(`DELETE FROM stream_logs WHERE id <= (SELECT COALESCE(MAX(id) - ?, 0) FROM stream_logs)`, maxRows); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to prune existing log entries: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_stream_logs_stream_time ON stream_logs(stream_id, timestamp DESC)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create stream log index: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_stream_logs_time ON stream_logs(timestamp DESC)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create log time index: %w", err)
	}
	// Additive, idempotent provider column. Safe in all three deployment cases:
	// a fresh database (the column is added right after CREATE TABLE), an
	// existing populated database (ALTER TABLE ADD COLUMN with a constant
	// default backfills every row in place), and a repeat run (the PRAGMA
	// check finds the column and skips the DDL entirely).
	if err := ensureProviderColumn(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Logger{db: db, path: dbPath, maxRows: maxRows, pruneInterval: pruneInterval}, nil
}

// ensureProviderColumn adds stream_configs.provider when it is missing.
//
// It is deliberately written as "inspect then alter" rather than
// "ALTER TABLE ... " with an error swallow, because a swallowed error would
// also hide a genuinely broken database. The default is a constant, which
// SQLite applies to existing rows without a table rewrite, so a populated
// production onvif_logs.db is upgraded in place.
func ensureProviderColumn(db *sql.DB) error {
	var present bool
	if err := db.QueryRow(
		`SELECT COUNT(*) > 0 FROM pragma_table_info('stream_configs') WHERE name = 'provider'`,
	).Scan(&present); err != nil {
		return fmt.Errorf("failed to inspect stream_configs schema: %w", err)
	}
	if present {
		return nil
	}
	if _, err := db.Exec(
		`ALTER TABLE stream_configs ADD COLUMN provider TEXT NOT NULL DEFAULT '` + defaultProvider + `'`,
	); err != nil {
		return fmt.Errorf("failed to add stream_configs.provider: %w", err)
	}
	return nil
}

// UpsertStreamConfig persists a profile token, its RTSP URL and the provider it
// belongs to. The provider is normalised to "onvif" when empty, so existing
// call sites keep working unchanged and never write a blank provider.
func (l *Logger) UpsertStreamConfig(profileToken, rtspURL, provider string) error {
	if provider == "" {
		provider = defaultProvider
	}
	_, err := l.db.Exec(`INSERT INTO stream_configs(profile_token, rtsp_url, provider, updated_at) VALUES(?,?,?,?)
		ON CONFLICT(profile_token) DO UPDATE SET rtsp_url=excluded.rtsp_url, provider=excluded.provider, updated_at=excluded.updated_at`, profileToken, rtspURL, provider, time.Now())
	return err
}

func (l *Logger) DeleteStreamConfig(profileToken string) error {
	_, err := l.db.Exec(`DELETE FROM stream_configs WHERE profile_token=?`, profileToken)
	return err
}

func (l *Logger) ListStreamConfigs() ([]StreamConfig, error) {
	// COALESCE + NULLIF keeps a row that somehow holds NULL or an empty
	// provider from surfacing as "unknown": such rows are ONVIF by definition,
	// because ONVIF was the only provider when they were written.
	rows, err := l.db.Query(`SELECT profile_token, rtsp_url, COALESCE(NULLIF(provider, ''), '` + defaultProvider + `') FROM stream_configs ORDER BY profile_token`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []StreamConfig
	for rows.Next() {
		var config StreamConfig
		if err := rows.Scan(&config.ProfileToken, &config.RTSPURL, &config.Provider); err != nil {
			return nil, err
		}
		result = append(result, config)
	}
	return result, rows.Err()
}

// Close closes the database connection
func (l *Logger) Close() {
	if l.db != nil {
		l.db.Close()
	}
}

// DB exposes the underlying connection.
//
// It exists so the rest of the process shares the ONE writer this constructor
// opened against the database, rather than opening a second pool at the same
// file. internal/tuyaqr's SQLite session store is the caller that needs it: the
// session belongs in this database, and two connections would also mean two
// places where the file's permissions have to be enforced.
//
// The caller must not close it; Close does, and it owns the handle.
func (l *Logger) DB() *sql.DB { return l.db }

// Path is the database file this logger opened. It is reported so a caller can
// point another store at the same file without re-deriving the name.
func (l *Logger) Path() string { return l.path }

// log inserts a new log entry into the database
func (l *Logger) log(streamID string, level LogLevel, source, message string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	query := `INSERT INTO stream_logs (stream_id, timestamp, level, source, message) VALUES (?, ?, ?, ?, ?)`
	if _, err := l.db.Exec(query, streamID, time.Now(), level, source, message); err != nil {
		log.Printf("Failed to insert log into database: %v", err)
		return
	}
	l.writes++
	if l.writes%l.pruneInterval == 0 {
		l.pruneLocked()
	}
}

func (l *Logger) pruneLocked() {
	query := `DELETE FROM stream_logs WHERE id <= (SELECT COALESCE(MAX(id) - ?, 0) FROM stream_logs)`
	if _, err := l.db.Exec(query, l.maxRows); err != nil {
		log.Printf("Failed to prune old log entries: %v", err)
	}
}

// LogDebug logs a debug message
func (l *Logger) LogDebug(streamID, source, message string) {
	l.log(streamID, DEBUG, source, message)
}

// LogInfo logs an info message
func (l *Logger) LogInfo(streamID, source, message string) {
	l.log(streamID, INFO, source, message)
}

// LogWarn logs a warning message
func (l *Logger) LogWarn(streamID, source, message string) {
	l.log(streamID, WARN, source, message)
}

// LogError logs an error message
func (l *Logger) LogError(streamID, source, message string) {
	l.log(streamID, ERROR, source, message)
}

// GetStreamLogs retrieves all logs for a specific stream
func (l *Logger) GetStreamLogs(streamID string, limit int) ([]StreamLog, error) {
	query := `SELECT id, stream_id, timestamp, level, source, message FROM stream_logs WHERE stream_id = ? ORDER BY timestamp DESC LIMIT ?`
	rows, err := l.db.Query(query, streamID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query logs: %w", err)
	}
	defer rows.Close()

	return scanLogs(rows)
}

// GetRecentLogs retrieves the most recent logs from all streams
func (l *Logger) GetRecentLogs(limit int) ([]StreamLog, error) {
	query := `SELECT id, stream_id, timestamp, level, source, message FROM stream_logs ORDER BY timestamp DESC LIMIT ?`
	rows, err := l.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query recent logs: %w", err)
	}
	defer rows.Close()

	return scanLogs(rows)
}

// scanLogs is a helper to scan rows into a slice of StreamLog
func scanLogs(rows *sql.Rows) ([]StreamLog, error) {
	var logs []StreamLog
	for rows.Next() {
		var logEntry StreamLog
		if err := rows.Scan(&logEntry.ID, &logEntry.StreamID, &logEntry.Timestamp, &logEntry.Level, &logEntry.Source, &logEntry.Message); err != nil {
			return nil, fmt.Errorf("failed to scan log row: %w", err)
		}
		logs = append(logs, logEntry)
	}
	return logs, nil
}
