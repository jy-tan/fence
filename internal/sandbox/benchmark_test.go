package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Use-Tusk/fence/internal/config"
)

// ============================================================================
// Baseline Benchmarks (unsandboxed)
// ============================================================================

// BenchmarkBaseline_True measures the cost of spawning a minimal process.
func BenchmarkBaseline_True(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cmd := exec.Command("true")
		_ = cmd.Run()
	}
}

// BenchmarkBaseline_Echo measures echo command without sandbox.
func BenchmarkBaseline_Echo(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cmd := exec.Command("sh", "-c", "echo hello")
		_ = cmd.Run()
	}
}

// BenchmarkBaseline_Python measures Python startup without sandbox.
func BenchmarkBaseline_Python(b *testing.B) {
	if _, err := exec.LookPath("python3"); err != nil {
		b.Skip("python3 not found")
	}
	for i := 0; i < b.N; i++ {
		cmd := exec.Command("python3", "-c", "pass")
		_ = cmd.Run()
	}
}

// BenchmarkBaseline_Node measures Node.js startup without sandbox.
func BenchmarkBaseline_Node(b *testing.B) {
	if _, err := exec.LookPath("node"); err != nil {
		b.Skip("node not found")
	}
	for i := 0; i < b.N; i++ {
		cmd := exec.Command("node", "-e", "")
		_ = cmd.Run()
	}
}

// BenchmarkBaseline_GitStatus measures git status without sandbox.
func BenchmarkBaseline_GitStatus(b *testing.B) {
	if _, err := exec.LookPath("git"); err != nil {
		b.Skip("git not found")
	}
	// Find a git repo to run in
	repoDir := findGitRepo()
	if repoDir == "" {
		b.Skip("no git repo found")
	}

	for i := 0; i < b.N; i++ {
		cmd := exec.Command("git", "status", "--porcelain")
		cmd.Dir = repoDir
		cmd.Stdout = nil // discard
		_ = cmd.Run()
	}
}

// ============================================================================
// Component Benchmarks (isolate overhead sources)
// ============================================================================

// BenchmarkManagerInitialize measures cold initialization cost (proxies + bridges).
func BenchmarkManagerInitialize(b *testing.B) {
	skipBenchIfSandboxed(b)

	workspace := b.TempDir()
	cfg := benchConfig(workspace)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager := NewManager(cfg, false, false)
		if err := manager.Initialize(); err != nil {
			b.Fatalf("failed to initialize: %v", err)
		}
		manager.Cleanup()
	}
}

// BenchmarkWrapCommand measures the cost of command wrapping (string construction only).
func BenchmarkWrapCommand(b *testing.B) {
	skipBenchIfSandboxed(b)

	workspace := b.TempDir()
	cfg := benchConfig(workspace)

	manager := NewManager(cfg, false, false)
	if err := manager.Initialize(); err != nil {
		b.Fatalf("failed to initialize: %v", err)
	}
	defer manager.Cleanup()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.WrapCommand("echo hello")
		if err != nil {
			b.Fatalf("wrap failed: %v", err)
		}
	}
}

// ============================================================================
// Cold Sandbox Benchmarks (full init + wrap + exec each iteration)
// ============================================================================

// BenchmarkColdSandbox_True measures full cold-start sandbox cost.
func BenchmarkColdSandbox_True(b *testing.B) {
	skipBenchIfSandboxed(b)

	workspace := b.TempDir()
	cfg := benchConfig(workspace)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager := NewManager(cfg, false, false)
		if err := manager.Initialize(); err != nil {
			b.Fatalf("init failed: %v", err)
		}

		wrappedCmd, err := manager.WrapCommand("true")
		if err != nil {
			manager.Cleanup()
			b.Fatalf("wrap failed: %v", err)
		}

		execBenchCommand(b, wrappedCmd, workspace)
		manager.Cleanup()
	}
}

// ============================================================================
// Warm Sandbox Benchmarks (Manager.Initialize once, repeat WrapCommand + exec)
// ============================================================================

// BenchmarkWarmSandbox_True measures sandbox cost with pre-initialized manager.
func BenchmarkWarmSandbox_True(b *testing.B) {
	skipBenchIfSandboxed(b)

	workspace := b.TempDir()
	cfg := benchConfig(workspace)

	manager := NewManager(cfg, false, false)
	if err := manager.Initialize(); err != nil {
		b.Fatalf("init failed: %v", err)
	}
	defer manager.Cleanup()

	wrappedCmd, err := manager.WrapCommand("true")
	if err != nil {
		b.Fatalf("wrap failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		execBenchCommand(b, wrappedCmd, workspace)
	}
}

// BenchmarkWarmSandbox_Echo measures echo command with pre-initialized manager.
func BenchmarkWarmSandbox_Echo(b *testing.B) {
	skipBenchIfSandboxed(b)

	workspace := b.TempDir()
	cfg := benchConfig(workspace)

	manager := NewManager(cfg, false, false)
	if err := manager.Initialize(); err != nil {
		b.Fatalf("init failed: %v", err)
	}
	defer manager.Cleanup()

	wrappedCmd, err := manager.WrapCommand("echo hello")
	if err != nil {
		b.Fatalf("wrap failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		execBenchCommand(b, wrappedCmd, workspace)
	}
}

// BenchmarkWarmSandbox_Python measures Python startup with pre-initialized manager.
func BenchmarkWarmSandbox_Python(b *testing.B) {
	skipBenchIfSandboxed(b)
	if _, err := exec.LookPath("python3"); err != nil {
		b.Skip("python3 not found")
	}

	workspace := b.TempDir()
	cfg := benchConfig(workspace)

	manager := NewManager(cfg, false, false)
	if err := manager.Initialize(); err != nil {
		b.Fatalf("init failed: %v", err)
	}
	defer manager.Cleanup()

	wrappedCmd, err := manager.WrapCommand("python3 -c 'pass'")
	if err != nil {
		b.Fatalf("wrap failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		execBenchCommand(b, wrappedCmd, workspace)
	}
}

// BenchmarkWarmSandbox_FileWrite measures file write with pre-initialized manager.
func BenchmarkWarmSandbox_FileWrite(b *testing.B) {
	skipBenchIfSandboxed(b)

	workspace := b.TempDir()
	cfg := benchConfig(workspace)

	manager := NewManager(cfg, false, false)
	if err := manager.Initialize(); err != nil {
		b.Fatalf("init failed: %v", err)
	}
	defer manager.Cleanup()

	testFile := filepath.Join(workspace, "bench.txt")
	wrappedCmd, err := manager.WrapCommand("echo 'benchmark data' > " + testFile)
	if err != nil {
		b.Fatalf("wrap failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		execBenchCommand(b, wrappedCmd, workspace)
		_ = os.Remove(testFile)
	}
}

// BenchmarkWarmSandbox_GitStatus measures git status with pre-initialized manager.
func BenchmarkWarmSandbox_GitStatus(b *testing.B) {
	skipBenchIfSandboxed(b)
	if _, err := exec.LookPath("git"); err != nil {
		b.Skip("git not found")
	}

	repoDir := findGitRepo()
	if repoDir == "" {
		b.Skip("no git repo found")
	}

	cfg := benchConfig(repoDir)

	manager := NewManager(cfg, false, false)
	if err := manager.Initialize(); err != nil {
		b.Fatalf("init failed: %v", err)
	}
	defer manager.Cleanup()

	wrappedCmd, err := manager.WrapCommand("git status --porcelain")
	if err != nil {
		b.Fatalf("wrap failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		execBenchCommand(b, wrappedCmd, repoDir)
	}
}

// ============================================================================
// Comparison Sub-benchmarks
// ============================================================================

// BenchmarkOverhead runs baseline vs sandbox comparisons for easy diffing.
func BenchmarkOverhead(b *testing.B) {
	b.Run("Baseline/True", BenchmarkBaseline_True)
	b.Run("Baseline/Echo", BenchmarkBaseline_Echo)
	b.Run("Baseline/Python", BenchmarkBaseline_Python)

	b.Run("Warm/True", BenchmarkWarmSandbox_True)
	b.Run("Warm/Echo", BenchmarkWarmSandbox_Echo)
	b.Run("Warm/Python", BenchmarkWarmSandbox_Python)

	b.Run("Cold/True", BenchmarkColdSandbox_True)
}

// ============================================================================
// Helpers
// ============================================================================

func skipBenchIfSandboxed(b *testing.B) {
	b.Helper()
	if os.Getenv("FENCE_SANDBOX") == "1" {
		b.Skip("already running inside Fence sandbox")
	}
}

func benchConfig(workspace string) *config.Config {
	return &config.Config{
		Network: config.NetworkConfig{
			AllowedDomains: []string{},
		},
		Filesystem: config.FilesystemConfig{
			AllowWrite: []string{workspace},
		},
		Command: config.CommandConfig{
			UseDefaults: boolPtr(false),
		},
	}
}

func execBenchCommand(b *testing.B, command string, workDir string) {
	b.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	shell := "/bin/sh"
	if runtime.GOOS == "darwin" {
		shell = "/bin/bash"
	}

	cmd := exec.CommandContext(ctx, shell, "-c", command)
	cmd.Dir = workDir
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &bytes.Buffer{}

	if err := cmd.Run(); err != nil {
		// Don't fail on command errors - we're measuring timing, not correctness
		// (e.g., git status might fail if not in a repo)
		_ = err
	}
}

func findGitRepo() string {
	// Try current directory and parents
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return ""
}
