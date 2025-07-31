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

// Logger handles database logging
type Logger struct {
	db    *sql.DB
	mutex sync.Mutex
}

// NewLogger creates a new logger and initializes the database
func NewLogger(dbPath string) (*Logger, error) {
	db, err := sql.Open("sqlite3", dbPath)
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
    );`
	if _, err := db.Exec(query); err != nil {
		return nil, fmt.Errorf("failed to create table: %w", err)
	}

	return &Logger{db: db}, nil
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
	_, err := l.db.Exec(query, streamID, time.Now(), level, source, message)
	if err != nil {
		log.Printf("Failed to insert log into database: %v", err)
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
	l.mutex.Lock()
	defer l.mutex.Unlock()

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
	l.mutex.Lock()
	defer l.mutex.Unlock()

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
