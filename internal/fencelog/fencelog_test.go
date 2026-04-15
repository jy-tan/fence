package fencelog

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLoggerSetLogFileWritesOnlyToFile(t *testing.T) {
	var stderr bytes.Buffer
	logger := New(&stderr)

	logPath := filepath.Join(t.TempDir(), "fence.log")
	if err := logger.SetLogFile(logPath); err != nil {
		t.Fatalf("SetLogFile() error = %v", err)
	}
	defer func() {
		if err := logger.CloseLogFile(); err != nil {
			t.Fatalf("CloseLogFile() error = %v", err)
		}
	}()

	msg := []byte("[fence] test log line\n")
	if _, err := logger.Write(msg); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	if stderr.Len() != 0 {
		t.Fatalf("stderr should stay empty when log file is configured, got %q", stderr.String())
	}

	data, err := os.ReadFile(logPath) //nolint:gosec // reading a temp test file created by this test
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if string(data) != string(msg) {
		t.Fatalf("log file = %q, want %q", string(data), string(msg))
	}
}

func TestLoggerWithoutLogFileWritesToStderr(t *testing.T) {
	var stderr bytes.Buffer
	logger := New(&stderr)

	msg := []byte("[fence] stderr only\n")
	if _, err := logger.Write(msg); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	if stderr.String() != string(msg) {
		t.Fatalf("stderr = %q, want %q", stderr.String(), string(msg))
	}
}

func TestLoggerAppendLogFilePreservesExistingContents(t *testing.T) {
	var stderr bytes.Buffer
	logger := New(&stderr)

	logPath := filepath.Join(t.TempDir(), "fence.log")
	if err := os.WriteFile(logPath, []byte("existing\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	if err := logger.AppendLogFile(logPath); err != nil {
		t.Fatalf("AppendLogFile() error = %v", err)
	}
	defer func() {
		if err := logger.CloseLogFile(); err != nil {
			t.Fatalf("CloseLogFile() error = %v", err)
		}
	}()

	msg := []byte("next\n")
	if _, err := logger.Write(msg); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	data, err := os.ReadFile(logPath) //nolint:gosec // reading a temp test file created by this test
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if string(data) != "existing\nnext\n" {
		t.Fatalf("log file = %q, want %q", string(data), "existing\nnext\n")
	}
}

func TestLoggerCloseLogFileRestoresStderr(t *testing.T) {
	var stderr bytes.Buffer
	logger := New(&stderr)

	logPath := filepath.Join(t.TempDir(), "fence.log")
	if err := logger.SetLogFile(logPath); err != nil {
		t.Fatalf("SetLogFile() error = %v", err)
	}

	if err := logger.CloseLogFile(); err != nil {
		t.Fatalf("CloseLogFile() error = %v", err)
	}

	msg := []byte("[fence] stderr only\n")
	if _, err := logger.Write(msg); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	if stderr.String() != string(msg) {
		t.Fatalf("stderr = %q, want %q", stderr.String(), string(msg))
	}

	data, err := os.ReadFile(logPath) //nolint:gosec // reading a temp test file created by this test
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if len(data) != 0 {
		t.Fatalf("log file should remain empty after CloseLogFile(), got %q", string(data))
	}
}
