//go:build linux

package sandbox

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Use-Tusk/fence/internal/fencelog"
)

// EBPFMonitor monitors sandbox violations using eBPF tracing.
// This requires CAP_BPF or root privileges.
type EBPFMonitor struct {
	pid        int
	debug      bool
	cancel     context.CancelFunc
	running    bool
	cmd        *exec.Cmd
	scriptPath string // Path to bpftrace script (for cleanup)
}

// NewEBPFMonitor creates a new eBPF-based violation monitor.
func NewEBPFMonitor(pid int, debug bool) *EBPFMonitor {
	return &EBPFMonitor{
		pid:   pid,
		debug: debug,
	}
}

// Start begins eBPF-based monitoring of filesystem and network violations.
func (m *EBPFMonitor) Start() error {
	features := DetectLinuxFeatures()
	if !features.HasEBPF {
		if m.debug {
			fencelog.Printf("[fence:ebpf] eBPF monitoring not available (need CAP_BPF or root)\n")
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.running = true

	// Try multiple eBPF tracing approaches
	if err := m.tryBpftrace(ctx); err != nil {
		if m.debug {
			fencelog.Printf("[fence:ebpf] bpftrace not available: %v\n", err)
		}
		// Fall back to other methods
		go m.traceWithPerfEvents()
	}

	if m.debug {
		fencelog.Printf("[fence:ebpf] Started eBPF monitoring for PID %d\n", m.pid)
	}

	return nil
}

// Stop stops the eBPF monitor.
func (m *EBPFMonitor) Stop() {
	if !m.running {
		return
	}

	// Give a moment for pending events
	time.Sleep(200 * time.Millisecond)

	if m.cancel != nil {
		m.cancel()
	}

	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
		_ = m.cmd.Wait()
	}

	// Clean up the script file
	if m.scriptPath != "" {
		_ = os.Remove(m.scriptPath)
	}

	m.running = false
}

// tryBpftrace attempts to use bpftrace for monitoring.
func (m *EBPFMonitor) tryBpftrace(ctx context.Context) error {
	bpftracePath, err := exec.LookPath("bpftrace")
	if err != nil {
		return fmt.Errorf("bpftrace not found: %w", err)
	}

	// Create a bpftrace script that monitors file operations and network syscalls
	script := m.generateBpftraceScript()

	// Write script to temp file
	tmpFile, err := os.CreateTemp("", "fence-ebpf-*.bt")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	scriptPath := tmpFile.Name()
	m.scriptPath = scriptPath // Store for cleanup later

	if _, err := tmpFile.WriteString(script); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(scriptPath)
		return fmt.Errorf("failed to write script: %w", err)
	}
	_ = tmpFile.Close()

	m.cmd = exec.CommandContext(ctx, bpftracePath, tmpFile.Name()) //nolint:gosec // bpftracePath from LookPath
	stdout, err := m.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create pipe: %w", err)
	}

	stderr, err := m.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start bpftrace: %w", err)
	}

	// Parse bpftrace output in background
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if m.debug {
				fencelog.Printf("[fence:ebpf:trace] %s\n", line)
			}
			if violation := m.parseBpftraceOutput(line); violation != "" {
				fencelog.Printf("%s\n", violation)
			}
		}
	}()

	// Also show stderr in debug mode
	if m.debug {
		go func() {
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				line := scanner.Text()
				fencelog.Printf("[fence:ebpf:err] %s\n", line)
			}
		}()
	}

	return nil
}

// generateBpftraceScript generates a bpftrace script for monitoring.
// The script filters events to only show processes that are descendants of the sandbox.
func (m *EBPFMonitor) generateBpftraceScript() string {
	// This script traces syscalls that return EACCES or EPERM
	// It tracks the sandbox PID and its descendants using a map
	//
	// Note: bpftrace can't directly check process ancestry, so we track
	// child PIDs via fork/clone and check against the tracked set.

	// Filter by PID range: only show events from processes spawned after the sandbox started
	// This isn't perfect but filters out pre-existing system processes
	// PID tracking via fork doesn't work because bpftrace attaches after the command starts
	script := fmt.Sprintf(`
BEGIN
{
    printf("fence:ebpf monitoring started for sandbox PID %%d (filtering pid >= %%d)\n", %d, %d);
}

// Monitor filesystem errors (EPERM=-1, EACCES=-13, EROFS=-30)
// Filter: pid >= SANDBOX_PID to exclude pre-existing processes
tracepoint:syscalls:sys_exit_openat
/(args->ret == -13 || args->ret == -1 || args->ret == -30) && pid >= %d/
{
    printf("DENIED:open pid=%%d comm=%%s ret=%%d\n", pid, comm, args->ret);
}

tracepoint:syscalls:sys_exit_unlinkat
/(args->ret == -13 || args->ret == -1 || args->ret == -30) && pid >= %d/
{
    printf("DENIED:unlink pid=%%d comm=%%s ret=%%d\n", pid, comm, args->ret);
}

tracepoint:syscalls:sys_exit_mkdirat
/(args->ret == -13 || args->ret == -1 || args->ret == -30) && pid >= %d/
{
    printf("DENIED:mkdir pid=%%d comm=%%s ret=%%d\n", pid, comm, args->ret);
}

tracepoint:syscalls:sys_exit_connect
/(args->ret == -13 || args->ret == -1 || args->ret == -111) && pid >= %d/
{
    printf("DENIED:connect pid=%%d comm=%%s ret=%%d\n", pid, comm, args->ret);
}
`, m.pid, m.pid, m.pid, m.pid, m.pid, m.pid)
	return script
}

// parseBpftraceOutput parses bpftrace output and formats violations.
func (m *EBPFMonitor) parseBpftraceOutput(line string) string {
	if !strings.HasPrefix(line, "DENIED:") {
		return ""
	}

	// Parse: DENIED:syscall pid=X comm=Y ret=Z
	pattern := regexp.MustCompile(`DENIED:(\w+) pid=(\d+) comm=(\S+) ret=(-?\d+)`)
	matches := pattern.FindStringSubmatch(line)
	if matches == nil {
		return ""
	}

	syscall := matches[1]
	pid, _ := strconv.Atoi(matches[2])
	comm := matches[3]
	ret, _ := strconv.Atoi(matches[4])

	// Format the violation
	errorName := getErrnoName(ret)
	timestamp := time.Now().Format("15:04:05")

	return fmt.Sprintf("[fence:ebpf] %s ✗ %s: %s (%s, pid=%d)",
		timestamp, syscall, errorName, comm, pid)
}

// traceWithPerfEvents uses perf events for tracing (fallback when bpftrace unavailable).
func (m *EBPFMonitor) traceWithPerfEvents() {
	// This is a fallback that uses the audit subsystem or trace-cmd
	// For now, we'll just monitor the trace pipe if available

	tracePipe := "/sys/kernel/debug/tracing/trace_pipe"
	if _, err := os.Stat(tracePipe); err != nil {
		if m.debug {
			fencelog.Printf("[fence:ebpf] trace_pipe not available\n")
		}
		return
	}

	f, err := os.Open(tracePipe)
	if err != nil {
		if m.debug {
			fencelog.Printf("[fence:ebpf] Failed to open trace_pipe: %v\n", err)
		}
		return
	}
	defer func() { _ = f.Close() }()

	// We'd need to set up tracepoints first, which requires additional setup
	// For now, this is a placeholder for the full implementation
}

// getErrnoName returns a human-readable description of an errno value.
func getErrnoName(errno int) string {
	names := map[int]string{
		-1:   "Operation not permitted",
		-2:   "No such file",
		-13:  "Permission denied",
		-17:  "File exists",
		-20:  "Not a directory",
		-21:  "Is a directory",
		-30:  "Read-only file system",
		-22:  "Invalid argument",
		-111: "Connection refused",
	}

	if name, ok := names[errno]; ok {
		return name
	}
	return fmt.Sprintf("errno=%d", errno)
}

// IsEBPFAvailable checks if eBPF monitoring can be used.
func IsEBPFAvailable() bool {
	features := DetectLinuxFeatures()
	return features.HasEBPF
}

// RequiredCapabilities returns the capabilities needed for eBPF monitoring.
func RequiredCapabilities() []string {
	return []string{"CAP_BPF", "CAP_PERFMON"}
}

// CheckBpftraceAvailable checks if bpftrace is installed and usable.
func CheckBpftraceAvailable() bool {
	path, err := exec.LookPath("bpftrace")
	if err != nil {
		return false
	}

	// Verify it can run (needs permissions)
	cmd := exec.Command(path, "--version") //nolint:gosec // path from LookPath
	return cmd.Run() == nil
}

// ViolationEvent represents a sandbox violation detected by eBPF.
type ViolationEvent struct {
	Timestamp time.Time
	Type      string // "file", "network", "syscall"
	Operation string // "open", "write", "connect", etc.
	Path      string
	PID       int
	Comm      string // Process name
	Errno     int
}

// FormatViolation formats a violation event for display.
func (v *ViolationEvent) FormatViolation() string {
	timestamp := v.Timestamp.Format("15:04:05")
	errName := getErrnoName(-v.Errno)

	if v.Path != "" {
		return fmt.Sprintf("[fence:ebpf] %s ✗ %s: %s (%s, %s:%d)",
			timestamp, v.Operation, v.Path, errName, v.Comm, v.PID)
	}
	return fmt.Sprintf("[fence:ebpf] %s ✗ %s: %s (%s:%d)",
		timestamp, v.Operation, errName, v.Comm, v.PID)
}

// EnsureTracingSetup ensures the kernel tracing infrastructure is available.
func EnsureTracingSetup() error {
	// Check if debugfs is mounted
	debugfs := "/sys/kernel/debug"
	if _, err := os.Stat(filepath.Join(debugfs, "tracing")); os.IsNotExist(err) {
		return fmt.Errorf("debugfs tracing not available at %s/tracing", debugfs)
	}
	return nil
}
