package sandbox

import (
	"bytes"
	"context"
	"fmt"
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
// Amortized Sandbox Benchmarks (N inner commands per outer sandbox)
// ============================================================================
//
// These measure the "parent fence wrapping N child tool calls" scenario that
// approximates how long-running agents (Claude Code, Cursor, Codex) consume
// fence. The relevant per-tool-call overhead is:
//
//	(amortized_sandboxed_time - amortized_unsandboxed_time) / N
//
// which is meaningfully smaller than the cold-start overhead reported by
// BenchmarkColdSandbox_*.

// benchmarkAmortized runs N inner sh -c invocations under a single, already
// initialized sandbox manager. This is the Go-level analogue of the
// "amortized-*" workloads in scripts/benchmark.sh.
func benchmarkAmortized(b *testing.B, innerCmd string, n int) {
	skipBenchIfSandboxed(b)

	workspace := b.TempDir()
	cfg := benchConfig(workspace)

	manager := NewManager(cfg, false, false)
	if err := manager.Initialize(); err != nil {
		b.Fatalf("init failed: %v", err)
	}
	defer manager.Cleanup()

	// Build a shell loop that runs the inner command N times.
	loopCmd := fmt.Sprintf("i=0; while [ $i -lt %d ]; do %s; i=$((i+1)); done", n, innerCmd)
	wrappedCmd, err := manager.WrapCommand(loopCmd)
	if err != nil {
		b.Fatalf("wrap failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		execBenchCommand(b, wrappedCmd, workspace)
	}
}

// BenchmarkAmortized_True_10 measures 10 true invocations per outer sandbox.
func BenchmarkAmortized_True_10(b *testing.B) { benchmarkAmortized(b, "true", 10) }

// BenchmarkAmortized_True_100 measures 100 true invocations per outer sandbox.
func BenchmarkAmortized_True_100(b *testing.B) { benchmarkAmortized(b, "true", 100) }

// BenchmarkAmortized_Echo_10 measures 10 echo invocations per outer sandbox.
func BenchmarkAmortized_Echo_10(b *testing.B) {
	benchmarkAmortized(b, "echo hello >/dev/null", 10)
}

// ============================================================================
// Runtime Exec Deny Benchmarks
// ============================================================================
//
// These exercise the code path PR #98 optimized (bounded alias probing with
// device bucketing). They are the first-line benchmarks to catch regressions
// in the runtime-deny startup cost, especially on WSL where the previous
// implementation stalled on /mnt/* mounts.

// BenchmarkGetRuntimeDeniedExecutablePaths measures resolution cost for a
// realistic agent deny list. Parameterized by deny-list shape so regressions
// in either the happy path or the shared-binary collision path show up.
func BenchmarkGetRuntimeDeniedExecutablePaths(b *testing.B) {
	b.Run("Empty", func(b *testing.B) {
		cfg := &config.Config{
			Command: config.CommandConfig{
				UseDefaults: boolPtr(false),
			},
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = GetRuntimeDeniedExecutablePaths(cfg)
		}
	})

	b.Run("DefaultsOnly", func(b *testing.B) {
		cfg := &config.Config{
			Command: config.CommandConfig{
				UseDefaults: boolPtr(true),
			},
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = GetRuntimeDeniedExecutablePaths(cfg)
		}
	})

	b.Run("SmallDeny", func(b *testing.B) {
		cfg := &config.Config{
			Command: config.CommandConfig{
				UseDefaults: boolPtr(false),
				Deny:        []string{"curl", "wget", "nc", "ssh", "scp"},
			},
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = GetRuntimeDeniedExecutablePaths(cfg)
		}
	})

	b.Run("LargeDeny", func(b *testing.B) {
		cfg := &config.Config{
			Command: config.CommandConfig{
				UseDefaults: boolPtr(true),
				Deny: []string{
					"curl", "wget", "nc", "ncat", "ssh", "scp", "sftp",
					"rsync", "ftp", "telnet", "git", "npm", "yarn", "pnpm",
					"pip", "pip3", "poetry", "cargo", "go", "docker", "kubectl",
					"helm", "terraform", "ansible", "vagrant", "aws", "gcloud",
					"az", "gh", "glab", "sudo", "su", "doas", "mount", "umount",
					"systemctl", "service", "journalctl", "dmesg", "iptables",
					"nft", "ip", "tc", "tcpdump", "nmap", "ping",
				},
			},
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = GetRuntimeDeniedExecutablePaths(cfg)
		}
	})

	// SharedBinaryHeavy denies names that commonly collide with busybox /
	// coreutils multicall binaries. This is the path PR #98 specifically
	// addressed on WSL.
	b.Run("SharedBinaryHeavy", func(b *testing.B) {
		cfg := &config.Config{
			Command: config.CommandConfig{
				UseDefaults: boolPtr(false),
				Deny:        []string{"ls", "cat", "cp", "mv", "rm", "chmod"},
			},
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = GetRuntimeDeniedExecutablePaths(cfg)
		}
	})
}

// BenchmarkSharedExecutableSearch measures the construction cost of the
// alias search structure that PR #98 replaced the exhaustive PATH scan with.
func BenchmarkSharedExecutableSearch(b *testing.B) {
	// Resolve a few realistic deny paths up front so the bench reflects the
	// actual post-resolution cost rather than PATH lookup.
	var paths []string
	for _, name := range []string{"ls", "cat", "curl", "git"} {
		if p, err := exec.LookPath(name); err == nil {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		b.Skip("no probe paths resolved on this system")
	}

	b.Run("DefaultProbeSet", func(b *testing.B) {
		probeNames := []string{"ls", "cat", "echo", "cp", "mv"}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = newSharedExecutableSearch(paths, probeNames)
		}
	})

	b.Run("LargeProbeSet", func(b *testing.B) {
		probeNames := []string{
			"ls", "cat", "echo", "cp", "mv", "rm", "chmod", "head", "tail",
			"sort", "wc", "cut", "tr", "uniq", "basename", "dirname", "env",
			"id", "mkdir", "mktemp", "printf", "pwd", "readlink", "realpath",
			"rmdir", "tee", "test", "touch", "true", "uname", "whoami",
			"grep", "sed", "awk", "find", "xargs",
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = newSharedExecutableSearch(paths, probeNames)
		}
	})
}

// ============================================================================
// CheckCommand Benchmarks (preflight policy check, runs on every WrapCommand)
// ============================================================================

// BenchmarkCheckCommand measures the cost of the preflight policy check.
func BenchmarkCheckCommand(b *testing.B) {
	cases := []struct {
		name    string
		cfg     *config.Config
		command string
	}{
		{
			name: "NoRules",
			cfg: &config.Config{
				Command: config.CommandConfig{UseDefaults: boolPtr(false)},
			},
			command: "echo hello",
		},
		{
			name: "DefaultsOnly/Allowed",
			cfg: &config.Config{
				Command: config.CommandConfig{UseDefaults: boolPtr(true)},
			},
			command: "git status --porcelain",
		},
		{
			name: "LargeDeny/Allowed",
			cfg: &config.Config{
				Command: config.CommandConfig{
					UseDefaults: boolPtr(true),
					Deny: []string{
						"curl", "wget", "nc", "ssh", "scp", "sftp", "rsync",
						"git push", "git reset --hard", "npm publish",
						"yarn publish", "pnpm publish", "cargo publish",
						"docker push", "kubectl delete", "terraform destroy",
						"aws s3 rm", "gh release delete", "rm -rf /",
					},
				},
			},
			command: "git status --porcelain",
		},
		{
			name: "LargeDeny/PipelineAllowed",
			cfg: &config.Config{
				Command: config.CommandConfig{
					UseDefaults: boolPtr(true),
					Deny: []string{
						"curl", "wget", "nc", "ssh", "scp",
						"git push", "npm publish", "docker push",
					},
				},
			},
			command: "git log --oneline | head -20 | awk '{print $1}' | sort",
		},
	}

	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = CheckCommand(c.command, c.cfg)
			}
		})
	}
}

// ============================================================================
// WrapCommand with non-trivial configs
// ============================================================================
//
// The existing BenchmarkWrapCommand uses a minimal config (empty deny,
// empty allowed domains, empty writable paths). These sub-benches measure
// WrapCommand under configs that exercise real code paths: runtime exec
// deny resolution, domain filter compilation, strict deny read mount
// planning, and the Linux-only allowLocalOutbound port bridge path.

func BenchmarkWrapCommandConfigs(b *testing.B) {
	b.Run("AgentDefaultDeny", func(b *testing.B) {
		skipBenchIfSandboxed(b)
		workspace := b.TempDir()
		cfg := &config.Config{
			Network: config.NetworkConfig{AllowedDomains: []string{}},
			Filesystem: config.FilesystemConfig{
				AllowWrite: []string{workspace},
			},
			Command: config.CommandConfig{
				UseDefaults: boolPtr(true),
				Deny:        []string{"curl", "wget", "git push"},
			},
		}
		manager := NewManager(cfg, false, false)
		if err := manager.Initialize(); err != nil {
			b.Fatalf("init failed: %v", err)
		}
		defer manager.Cleanup()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := manager.WrapCommand("echo hello"); err != nil {
				b.Fatalf("wrap failed: %v", err)
			}
		}
	})

	b.Run("ManyAllowedDomains", func(b *testing.B) {
		skipBenchIfSandboxed(b)
		workspace := b.TempDir()
		domains := make([]string, 0, 50)
		for _, d := range []string{
			"github.com", "api.github.com", "raw.githubusercontent.com",
			"pypi.org", "files.pythonhosted.org", "registry.npmjs.org",
			"crates.io", "proxy.golang.org", "sum.golang.org",
			"hub.docker.com", "registry-1.docker.io", "auth.docker.io",
			"anthropic.com", "api.anthropic.com", "openai.com", "api.openai.com",
		} {
			domains = append(domains, d)
			domains = append(domains, "*."+d)
		}
		cfg := &config.Config{
			Network: config.NetworkConfig{AllowedDomains: domains},
			Filesystem: config.FilesystemConfig{
				AllowWrite: []string{workspace},
			},
			Command: config.CommandConfig{UseDefaults: boolPtr(false)},
		}
		manager := NewManager(cfg, false, false)
		if err := manager.Initialize(); err != nil {
			b.Fatalf("init failed: %v", err)
		}
		defer manager.Cleanup()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := manager.WrapCommand("echo hello"); err != nil {
				b.Fatalf("wrap failed: %v", err)
			}
		}
	})

	b.Run("StrictDenyRead", func(b *testing.B) {
		skipBenchIfSandboxed(b)
		workspace := b.TempDir()
		cfg := &config.Config{
			Network: config.NetworkConfig{AllowedDomains: []string{}},
			Filesystem: config.FilesystemConfig{
				DefaultDenyRead: true,
				StrictDenyRead:  true,
				AllowRead:       []string{workspace, "/usr/bin", "/bin"},
				AllowWrite:      []string{workspace},
			},
			Command: config.CommandConfig{UseDefaults: boolPtr(false)},
		}
		manager := NewManager(cfg, false, false)
		if err := manager.Initialize(); err != nil {
			b.Fatalf("init failed: %v", err)
		}
		defer manager.Cleanup()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := manager.WrapCommand("echo hello"); err != nil {
				b.Fatalf("wrap failed: %v", err)
			}
		}
	})

	// AllowLocalOutboundPorts only has an effect on Linux, but WrapCommand
	// must still handle the config shape cleanly on macOS.
	b.Run("AllowLocalOutboundPorts", func(b *testing.B) {
		skipBenchIfSandboxed(b)
		workspace := b.TempDir()
		yes := true
		cfg := &config.Config{
			Network: config.NetworkConfig{
				AllowedDomains:          []string{},
				AllowLocalOutbound:      &yes,
				AllowLocalOutboundPorts: []int{5432, 6379, 8080},
			},
			Filesystem: config.FilesystemConfig{
				AllowWrite: []string{workspace},
			},
			Command: config.CommandConfig{UseDefaults: boolPtr(false)},
		}
		manager := NewManager(cfg, false, false)
		if err := manager.Initialize(); err != nil {
			b.Fatalf("init failed: %v", err)
		}
		defer manager.Cleanup()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := manager.WrapCommand("echo hello"); err != nil {
				b.Fatalf("wrap failed: %v", err)
			}
		}
	})
}

// ============================================================================
// Manager init/cleanup split
// ============================================================================
//
// BenchmarkManagerInitialize stops and starts proxies (and on Linux, socat
// bridges) per iteration. Running it under -count=N can exhaust ephemeral
// ports. Splitting init and cleanup lets us see which half is expensive
// and makes the numbers more stable.

// BenchmarkManagerInit measures only initialization, with cleanup moved
// outside the timing window.
func BenchmarkManagerInit(b *testing.B) {
	skipBenchIfSandboxed(b)

	workspace := b.TempDir()
	cfg := benchConfig(workspace)

	managers := make([]*Manager, 0, b.N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := NewManager(cfg, false, false)
		if err := m.Initialize(); err != nil {
			b.StopTimer()
			for _, prev := range managers {
				prev.Cleanup()
			}
			b.Fatalf("failed to initialize: %v", err)
		}
		managers = append(managers, m)
	}
	b.StopTimer()

	for _, m := range managers {
		m.Cleanup()
	}
}

// BenchmarkManagerCleanup measures only cleanup, with initialization moved
// outside the timing window.
func BenchmarkManagerCleanup(b *testing.B) {
	skipBenchIfSandboxed(b)

	workspace := b.TempDir()
	cfg := benchConfig(workspace)

	managers := make([]*Manager, b.N)
	for i := 0; i < b.N; i++ {
		m := NewManager(cfg, false, false)
		if err := m.Initialize(); err != nil {
			for j := 0; j < i; j++ {
				managers[j].Cleanup()
			}
			b.Fatalf("failed to initialize: %v", err)
		}
		managers[i] = m
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		managers[i].Cleanup()
	}
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
