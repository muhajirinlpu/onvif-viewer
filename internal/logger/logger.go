package logger

import (
	"database/sql"
	"fmt"
	"log"
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
	mutex         sync.Mutex
	maxRows       int
	pruneInterval int
	writes        int
}

// NewLogger creates a new logger and initializes the database.
func NewLogger(dbPath string) (*Logger, error) {
	return newLogger(dbPath, defaultMaxRows, defaultPruneInterval)
}

func newLogger(dbPath string, maxRows, pruneInterval int) (*Logger, error) {
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
	return &Logger{db: db, maxRows: maxRows, pruneInterval: pruneInterval}, nil
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
