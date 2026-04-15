package fencelog

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// EnvVar propagates the configured Fence log file to helper re-execs.
const EnvVar = "FENCE_LOG_FILE"

// Logger routes Fence-owned log lines to stderr or, when configured, to a log
// file instead.
//
// The logger holds a mutex so concurrent goroutines emit complete log writes
// without interleaving in the file output.
type Logger struct {
	mu     sync.Mutex
	stderr io.Writer
	file   *os.File
}

// New creates a logger that always writes to stderr.
func New(stderr io.Writer) *Logger {
	if stderr == nil {
		stderr = io.Discard
	}
	return &Logger{stderr: stderr}
}

// Write sends log output to the configured log file when present; otherwise it
// falls back to stderr.
func (l *Logger) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Write(p)
	}

	return l.stderr.Write(p)
}

// Printf writes a formatted Fence log line to the shared logger.
func Printf(format string, args ...interface{}) {
	_, _ = fmt.Fprintf(defaultLogger, format, args...)
}

// Println writes a line to the shared logger.
func Println(args ...interface{}) {
	_, _ = fmt.Fprintln(defaultLogger, args...)
}

// SetLogFile truncates or creates the log file and mirrors future writes to it.
func (l *Logger) SetLogFile(path string) error {
	return l.openLogFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC)
}

// AppendLogFile reopens an existing log file without truncating prior content.
func (l *Logger) AppendLogFile(path string) error {
	return l.openLogFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND)
}

func (l *Logger) openLogFile(path string, flags int) error {
	file, err := os.OpenFile(path, flags, 0o600) //nolint:gosec // path comes from an explicit user-provided CLI flag/env var
	if err != nil {
		return err
	}

	l.mu.Lock()
	prev := l.file
	l.file = file
	l.mu.Unlock()

	if prev != nil {
		_ = prev.Close()
	}

	return nil
}

// CloseLogFile stops mirroring to the log file.
func (l *Logger) CloseLogFile() error {
	l.mu.Lock()
	file := l.file
	l.file = nil
	l.mu.Unlock()

	if file == nil {
		return nil
	}

	return file.Close()
}

var defaultLogger = New(os.Stderr)

// Stderr returns the shared Fence log writer.
func Stderr() io.Writer {
	return defaultLogger
}

// SetLogFile configures the shared Fence log file.
func SetLogFile(path string) error {
	return defaultLogger.SetLogFile(path)
}

// AppendLogFile reopens the shared Fence log file without truncating it.
func AppendLogFile(path string) error {
	return defaultLogger.AppendLogFile(path)
}

// CloseLogFile closes the shared Fence log file.
func CloseLogFile() error {
	return defaultLogger.CloseLogFile()
}
