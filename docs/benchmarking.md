# Benchmarking

This document describes how to run, interpret, and compare sandbox performance benchmarks for Fence.

## Quick Start

```bash
# Install dependencies
brew install hyperfine   # macOS
# apt install hyperfine  # Linux

go install golang.org/x/perf/cmd/benchstat@latest

# Run CLI benchmarks
./scripts/benchmark.sh

# Run Go microbenchmarks
go test -run=^$ -bench=. -benchmem ./internal/sandbox/...
```

## Goals

1. Quantify sandbox overhead on each platform (`sandboxed / unsandboxed` ratio)
2. Compare macOS (Seatbelt) vs Linux (bwrap+Landlock) overhead fairly
3. Attribute overhead to specific components (proxy startup, bridge setup, wrap generation)
4. Track regressions over time

## Benchmark Types

### Layer 1: CLI Benchmarks (`scripts/benchmark.sh`)

**What it measures**: Real-world agent cost - full `fence` invocation including proxy startup, socat bridges (Linux), and sandbox-exec/bwrap setup.

This is the most realistic benchmark for understanding the cost of running agent commands through Fence.

```bash
# Full benchmark suite
./scripts/benchmark.sh

# Quick mode (fewer runs)
./scripts/benchmark.sh -q

# Custom output directory
./scripts/benchmark.sh -o ./my-results

# Include network benchmarks (requires local server)
./scripts/benchmark.sh --network
```

#### Options

| Option | Description |
|--------|-------------|
| `-b, --binary PATH` | Path to fence binary (default: ./fence) |
| `-o, --output DIR` | Output directory (default: ./benchmarks) |
| `-n, --runs N` | Minimum runs per benchmark (default: 30) |
| `-q, --quick` | Quick mode: fewer runs, skip slow benchmarks |
| `--network` | Include network benchmarks |

### Layer 2: Go Microbenchmarks (`internal/sandbox/benchmark_test.go`)

**What it measures**: Component-level overhead - isolates Manager initialization, WrapCommand generation, and execution.

```bash
# Run all benchmarks
go test -run=^$ -bench=. -benchmem ./internal/sandbox/...

# Run specific benchmark
go test -run=^$ -bench=BenchmarkWarmSandbox -benchmem ./internal/sandbox/...

# Multiple runs for statistical analysis
go test -run=^$ -bench=. -benchmem -count=10 ./internal/sandbox/... > bench.txt
benchstat bench.txt
```

#### Available Benchmarks

| Benchmark | Description |
|-----------|-------------|
| `BenchmarkBaseline_*` | Unsandboxed command execution |
| `BenchmarkManagerInitialize` | Cold initialization (proxies + bridges) |
| `BenchmarkWrapCommand` | Command string construction only |
| `BenchmarkColdSandbox_*` | Full init + wrap + exec per iteration |
| `BenchmarkWarmSandbox_*` | Pre-initialized manager, just exec |
| `BenchmarkOverhead` | Grouped comparison of baseline vs sandbox |

### Layer 3: OS-Level Profiling

**What it measures**: Kernel/system overhead - context switches, syscalls, page faults.

#### Linux

```bash
# Quick syscall cost breakdown
strace -f -c ./fence -- true

# Context switches, page faults
perf stat -- ./fence -- true

# Full profiling (flamegraph-ready)
perf record -F 99 -g -- ./fence -- git status
perf report
```

#### macOS

```bash
# Time Profiler via Instruments
xcrun xctrace record --template 'Time Profiler' --launch -- ./fence -- true

# Quick call-stack snapshot
./fence -- sleep 5 &
sample $! 5 -file sample.txt
```

## Interpreting Results

### Key Metric: Overhead Factor

```text
Overhead Factor = time(sandboxed) / time(unsandboxed)
```

Compare overhead factors across platforms, not absolute times, because hardware differences swamp absolute timings.

### Example Output

```text
Benchmark                      Unsandboxed    Sandboxed    Overhead
true                           1.2 ms         45 ms        37.5x
git status                     15 ms          62 ms        4.1x
python -c 'pass'               25 ms          73 ms        2.9x
```

### What to Expect

| Workload | Linux Overhead | macOS Overhead | Notes |
|----------|----------------|----------------|-------|
| `true` | 180-360x | 8-10x | Dominated by cold start |
| `echo` | 150-300x | 6-8x | Similar to true |
| `python3 -c 'pass'` | 10-12x | 2-3x | Interpreter startup dominates |
| `git status` | 50-60x | 4-5x | Real I/O helps amortize |
| `rg` | 40-50x | 3-4x | Search I/O helps amortize |

The overhead factor decreases as the actual workload increases (because sandbox setup is fixed cost). Linux overhead is significantly higher due to bwrap/socat setup.

## Cross-Platform Comparison

### Fair Comparison Approach

1. Run benchmarks on each platform independently
2. Compare overhead factors, not absolute times
3. Use the same fence version and workloads

```bash
# On macOS
go test -run=^$ -bench=. -count=10 ./internal/sandbox/... > bench_macos.txt

# On Linux
go test -run=^$ -bench=. -count=10 ./internal/sandbox/... > bench_linux.txt

# Compare
benchstat bench_macos.txt bench_linux.txt
```

### Caveats

- macOS uses Seatbelt (sandbox-exec) - built-in, lightweight kernel sandbox
- Linux uses bwrap + Landlock, this creates socat bridges for network, incurring significant setup cost
- Linux cold start is ~10x slower than macOS due to bwrap/socat bridge setup
- Linux warm path is still ~5x slower than macOS - bwrap execution itself has overhead
- For long-running agents, this difference is negligible (one-time startup cost)

> [!TIP]
> Running Linux benchmarks inside a VM (Colima, Docker Desktop, etc.) inflates overhead due to virtualization. Use native Linux (bare metal or CI) for fair cross-platform comparison.

## GitHub Actions

Benchmarks can be run in CI via the workflow at `.github/workflows/benchmark.yml`:

```bash
# Trigger manually from GitHub UI: Actions > Benchmarks > Run workflow

# Or via gh CLI
gh workflow run benchmark.yml
```

Results are uploaded as artifacts and summarized in the workflow summary.

## Tips

### Reducing Variance

- Run with `--min-runs 50` or higher
- Close other applications
- Pin CPU frequency if possible (Linux: `cpupower frequency-set --governor performance`)
- Run multiple times and use benchstat for statistical analysis

### Profiling Hotspots

```bash
# CPU profile
go test -run=^$ -bench=BenchmarkWarmSandbox -cpuprofile=cpu.out ./internal/sandbox/...
go tool pprof -http=:8080 cpu.out

# Memory profile
go test -run=^$ -bench=BenchmarkWarmSandbox -memprofile=mem.out ./internal/sandbox/...
go tool pprof -http=:8080 mem.out
```

### Tracking Regressions

1. Run benchmarks before and after changes
2. Save results to files
3. Compare with benchstat

```bash
# Before
go test -run=^$ -bench=. -count=10 ./internal/sandbox/... > before.txt

# Make changes...

# After
go test -run=^$ -bench=. -count=10 ./internal/sandbox/... > after.txt

# Compare
benchstat before.txt after.txt
```

## Workload Categories

| Category | Commands | What it Stresses |
|----------|----------|------------------|
| **Spawn-only** | `true`, `echo` | Process spawn, wrapper overhead |
| **Interpreter** | `python3 -c`, `node -e` | Runtime startup under sandbox |
| **FS-heavy** | file creation, `rg` | Landlock/Seatbelt FS rules |
| **Network (local)** | `curl localhost` | Proxy forwarding overhead |
| **Real tools** | `git status` | Practical agent workloads |

## Benchmark Findings (12/28/2025)

Results from GitHub Actions CI runners (Linux: AMD EPYC 7763, macOS: Apple M1 Virtual).

### Manager Initialization

| Platform | `Manager.Initialize()` |
|----------|------------------------|
| Linux | 101.9 ms |
| macOS | 27.5 µs |

Linux initialization is ~3,700x slower because it must:

- Start HTTP + SOCKS proxies
- Create Unix socket bridges for socat
- Set up bwrap namespace configuration

macOS only generates a Seatbelt profile string (very cheap).

### Cold Start Overhead (one `fence` invocation per command)

| Workload | Linux | macOS |
|----------|-------|-------|
| `true` | 215 ms | 22 ms |
| Python | 124 ms | 33 ms |
| Git status | 114 ms | 25 ms |

This is the realistic cost for scripts running `fence -c "command"` repeatedly.

### Warm Path Overhead (pre-initialized manager)

| Workload | Linux | macOS |
|----------|-------|-------|
| `true` | 112 ms | 20 ms |
| Python | 124 ms | 33 ms |
| Git status | 114 ms | 25 ms |

Even with proxies already running, Linux bwrap execution adds ~110ms overhead per command.

### Overhead Factors

| Workload | Linux Overhead | macOS Overhead |
|----------|----------------|----------------|
| `true` (cold) | ~360x | ~10x |
| `true` (warm) | ~187x | ~8x |
| Python (warm) | ~11x | ~2x |
| Git status (warm) | ~54x | ~4x |

Overhead decreases as the actual workload increases (sandbox setup is fixed cost).

## Impact on Agent Usage

### Long-Running Agents (`fence claude`, `fence codex`)

For agents that run as a child process under fence:

| Phase | Cost |
|-------|------|
| Startup (once) | Linux: ~215ms, macOS: ~22ms |
| Per tool call | Negligible (baseline fork+exec only) |

Child processes inherit the sandbox - no re-initialization, no WrapCommand overhead. The per-command cost is just normal process spawning:

| Command | Linux | macOS |
|---------|-------|-------|
| `true` | 0.6 ms | 2.3 ms |
| `git status` | 2.1 ms | 5.9 ms |
| Python script | 11 ms | 15 ms |

**Bottom line**: For `fence <agent>` usage, sandbox overhead is a one-time startup cost. Tool calls inside the agent run at native speed.

### Per-Command Invocation (`fence -c "command"`)

For scripts or CI running fence per command:

| Session | Linux Cost | macOS Cost |
|---------|------------|------------|
| 1 command | 215 ms | 22 ms |
| 10 commands | 2.15 s | 220 ms |
| 50 commands | 10.75 s | 1.1 s |

Consider keeping the manager alive (daemon mode) or batching commands to reduce overhead.

## Additional Notes

- `Manager.Initialize()` starts HTTP + SOCKS proxies; on Linux also creates socat bridges
- Cold start includes all initialization; hot path is just `WrapCommand + exec`
- `-m` (monitor mode) spawns additional monitoring processes, so we'll have to benchmark separately
- Keep workloads under the repo - avoid `/tmp` since Linux bwrap does `--tmpfs /tmp`
- `debug` mode changes logging, so always benchmark with debug off
