package sandbox

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/Use-Tusk/fence/internal/fencelog"
	"github.com/Use-Tusk/fence/internal/platform"
)

// LogMonitor monitors sandbox violations via macOS log stream.
type LogMonitor struct {
	sessionSuffix string
	cmd           *exec.Cmd
	cancel        context.CancelFunc
	running       bool
}

// NewLogMonitor creates a new log monitor for the given session suffix.
// Returns nil on non-macOS platforms.
func NewLogMonitor(sessionSuffix string) *LogMonitor {
	if platform.Detect() != platform.MacOS {
		return nil
	}
	return &LogMonitor{
		sessionSuffix: sessionSuffix,
	}
}

// Start begins monitoring the macOS unified log for sandbox violations.
func (m *LogMonitor) Start() error {
	if m == nil {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	// Build predicate to filter for this session's violations only
	predicate := fmt.Sprintf(`eventMessage ENDSWITH "%s"`, m.sessionSuffix)

	m.cmd = exec.CommandContext(ctx, "log", "stream", //nolint:gosec // predicate is constructed from trusted session suffix
		"--predicate", predicate,
		"--style", "compact",
	)

	stdout, err := m.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start log stream: %w", err)
	}

	m.running = true

	// Parse log output in background
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if violation := parseViolation(line); violation != "" {
				fencelog.Printf("%s\n", violation)
			}
		}
	}()

	// Give log stream a moment to initialize
	time.Sleep(100 * time.Millisecond)

	return nil
}

// Stop stops the log monitor.
func (m *LogMonitor) Stop() {
	if m == nil || !m.running {
		return
	}

	// Give a moment for any pending events to be processed
	time.Sleep(500 * time.Millisecond)

	if m.cancel != nil {
		m.cancel()
	}

	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
		_ = m.cmd.Wait()
	}

	m.running = false
}

// violationPattern matches sandbox denial log entries
var violationPattern = regexp.MustCompile(`Sandbox: (\w+)\((\d+)\) deny\(\d+\) (\S+)(.*)`)

// parseViolation extracts and formats a sandbox violation from a log line.
// Returns empty string if the line should be filtered out.
func parseViolation(line string) string {
	if strings.HasPrefix(line, "Filtering") || strings.HasPrefix(line, "Timestamp") {
		return ""
	}

	if strings.Contains(line, "duplicate report") {
		return ""
	}

	if strings.HasPrefix(line, "CMD64_") {
		return ""
	}

	// Match violation pattern
	matches := violationPattern.FindStringSubmatch(line)
	if matches == nil {
		return ""
	}

	process := matches[1]
	pid := matches[2]
	operation := matches[3]
	details := strings.TrimSpace(matches[4])

	if !shouldShowViolation(operation) {
		return ""
	}

	if isNoisyViolation(details) {
		return ""
	}

	timestamp := time.Now().Format("15:04:05")

	if details != "" {
		return fmt.Sprintf("[fence:logstream] %s ✗ %s %s (%s:%s)", timestamp, operation, details, process, pid)
	}
	return fmt.Sprintf("[fence:logstream] %s ✗ %s (%s:%s)", timestamp, operation, process, pid)
}

// shouldShowViolation returns true if this violation type should be displayed.
func shouldShowViolation(operation string) bool {
	if strings.HasPrefix(operation, "network-") {
		return true
	}

	if strings.HasPrefix(operation, "file-read") ||
		strings.HasPrefix(operation, "file-write") {
		return true
	}

	if strings.HasPrefix(operation, "mach-") {
		return true
	}

	// Filter out everything else (file-ioctl, etc.)
	return false
}

// isNoisyViolation returns true if this violation is system noise that should be filtered.
func isNoisyViolation(details string) bool {
	// Filter out TTY/terminal writes (very noisy from any process that prints output)
	if strings.HasPrefix(details, "/dev/tty") ||
		strings.HasPrefix(details, "/dev/pts") {
		return true
	}

	// Filter out mDNSResponder (system DNS resolution socket)
	if strings.Contains(details, "mDNSResponder") {
		return true
	}

	// Filter out other system sockets that are typically noise
	if strings.HasPrefix(details, "/private/var/run/syslog") {
		return true
	}

	return false
}

// GetSessionSuffix returns the session suffix used for filtering.
// This is the same suffix used in macOS sandbox-exec profiles.
func GetSessionSuffix() string {
	return sessionSuffix
}
