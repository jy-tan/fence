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
| `BenchmarkManagerInitialize` | Combined init + cleanup per iteration |
| `BenchmarkManagerInit` | Initialization only (cleanup outside timing) |
| `BenchmarkManagerCleanup` | Cleanup only (initialization outside timing) |
| `BenchmarkWrapCommand` | Command string construction only (minimal config) |
| `BenchmarkWrapCommandConfigs` | WrapCommand under realistic configs (default deny, many allowed domains, strictDenyRead, allowLocalOutboundPorts) |
| `BenchmarkCheckCommand` | Preflight policy check, parameterized by deny-list size |
| `BenchmarkGetRuntimeDeniedExecutablePaths` | Runtime exec deny resolution — the path PR #98 optimized. Includes `SharedBinaryHeavy` sub-bench that exercises alias probing on busybox/coreutils multicall names |
| `BenchmarkSharedExecutableSearch` | Alias search construction (device-bucketed probing) |
| `BenchmarkColdSandbox_*` | Full init + wrap + exec per iteration |
| `BenchmarkWarmSandbox_*` | Pre-initialized manager, just exec |
| `BenchmarkAmortized_*` | N inner commands per outer sandbox — approximates how agents actually consume fence |
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

## Amortized vs Cold Overhead

The cold-start numbers below are the worst case: one `fence` invocation per
command, paying full initialization every time. That's not how long-running
agents actually use fence.

For agent-style usage (`fence -- <agent>` or `fence -c "<script that runs
many commands>"`), the relevant metric is **per-tool-call overhead**:

```text
per_call_overhead = (sandboxed_total - unsandboxed_total) / N
```

where `N` is the number of inner commands run under one outer fence. The
`BenchmarkAmortized_*` Go benches and the `amortized-*` hyperfine workloads
in `scripts/benchmark.sh` measure exactly this.

Per-call overhead is expected to be significantly smaller than cold-start
overhead because initialization is paid once. See the reading guide below
for which bench answers which question.

## Reading the Benchmarks

Rather than publish fixed-point-in-time findings that quickly go stale,
this section documents which bench answers which question. Re-run the
benches yourself (`workflow_dispatch` on the Benchmarks workflow, or
locally per the Quick Start) whenever you need current numbers.

### The five numbers that matter

For any run, these are the rows to look at first:

| Question | Look at | Why |
|----------|---------|-----|
| "How much does `fence` cost to start up?" | `BenchmarkManagerInit` | Pure init cost (proxies, Linux bridges). Cleanup is separated into `BenchmarkManagerCleanup` for cleaner numbers. |
| "How expensive is wrapping a command under a realistic agent config?" | `BenchmarkWrapCommandConfigs/AgentDefaultDeny` | Default deny list + runtime-deny resolution, which is what real users configure. The original `BenchmarkWrapCommand` uses an empty config and underestimates. |
| "What's the per-tool-call cost once fence is running?" | `BenchmarkAmortized_True_100` minus `BenchmarkAmortized_True_10`, divided by 90 | Differential eliminates the one-time wrap cost, leaving the marginal cost of one extra inner command. This is the number that matters for agent usage. |
| "Did PR #98 regress on runtime exec deny?" | `BenchmarkGetRuntimeDeniedExecutablePaths/{LargeDeny,SharedBinaryHeavy}` | These exercise the alias-probing code path PR #98 optimized. On WSL they are the canary. |
| "What's the user-observable cost of `fence -- cmd` invocation?" | `cold-*` rows in the hyperfine markdown, or `BenchmarkColdSandbox_True` | Real cold-start invocation, including Go runtime startup, config load, and exec teardown. |

### Cross-referencing hyperfine rows and Go benches

The hyperfine CLI benches and Go microbenches measure overlapping things.
When in doubt, prefer the Go numbers - they are more reproducible because
they skip the fence binary's Go runtime startup and CLI parsing.

| hyperfine row | Closest Go bench | Notes |
|---------------|------------------|-------|
| `true` (cold) | `BenchmarkColdSandbox_True` + Go runtime startup | Hyperfine row is typically ~15-25 ms higher due to binary startup on Linux. |
| `amortized-true-10` | `BenchmarkAmortized_True_10` | Should match closely on the same machine. |
| `amortized-true-100` | `BenchmarkAmortized_True_100` | Ditto. |
| `runtime-deny-startup` | `BenchmarkGetRuntimeDeniedExecutablePaths/SharedBinaryHeavy` plus fence startup | The end-to-end row includes fence's full startup cost; the Go bench isolates just the resolver. |

### What's going on underneath

A full cold `fence -- true` on Linux decomposes roughly into:

| Component | Typical cost |
|-----------|--------------|
| Go runtime startup + config load + flag parse | ~15-20 ms |
| `Manager.Initialize()` (HTTP + SOCKS proxies, socat bridges) | dominant on Linux, near-zero on macOS |
| `WrapCommand` (including runtime-deny resolution) | single-digit ms on modest configs |
| `sh -c "<bwrap ...> true"` exec + bwrap namespace setup | double-digit ms on Linux, low-single-digit on macOS |
| Cleanup (proxy stop, bridge teardown) | <1 ms |

On macOS the sandbox-exec path doesn't create proxies or bridges, so init
is effectively free and the wrap path is the dominant cost. On Linux, init
dominates cold-start overhead and the wrap path is a small fraction. That's
why the amortized benches exist - for agent usage, you pay init once and
then the per-call cost is roughly just the bwrap exec overhead.

For a fresh comparison against your own hardware, run:

```bash
go test -run=^$ -bench='BenchmarkManagerInit|BenchmarkWrapCommand|BenchmarkAmortized|BenchmarkGetRuntimeDeniedExecutablePaths' \
    -benchmem -count=5 ./internal/sandbox/...
```

and `./scripts/benchmark.sh` for the end-to-end hyperfine view.

## Reference Numbers (2026-04-24)

Snapshot from one Benchmarks workflow run at `-count=5`, plus a separate
local WSL run. Kept for orientation only - rerun for current numbers
whenever you need them. Do not treat these as performance guarantees.

Platforms:

- **Linux CI** — `ubuntu-latest` GitHub-hosted runner, AMD EPYC 7763 64-Core.
- **macOS CI** — `macos-latest` GitHub-hosted runner, Apple M1 (Virtual).
- **WSL** — local laptop, Intel Core i5-1345U, WSL2 kernel 6.6.87,
  `/mnt/c` interop enabled. Different hardware from the CI runners, so
  compare shapes rather than absolute numbers.

### Go microbenches

Means rounded from 5 samples per row. Rows are grouped by what they
measure so the reading guide above maps onto them.

| Bench | Linux CI | macOS CI | WSL |
|-------|----------|----------|-----|
| **Manager lifecycle** | | | |
| `BenchmarkManagerInit` | 101 ms | 58 µs | 93 ms |
| `BenchmarkManagerCleanup` | 0.58 ms | 22 µs | 1.98 ms |
| **Wrap path** | | | |
| `BenchmarkWrapCommand` (minimal config) | 1.77 ms | 2.72 ms | **1,649 ms** [¹] |
| `BenchmarkWrapCommandConfigs/AgentDefaultDeny` | 3.96 ms | 4.21 ms | **1,731 ms** [¹] |
| `BenchmarkWrapCommandConfigs/ManyAllowedDomains` | 1.08 ms | 3.10 ms | 1,545 ms [¹] |
| `BenchmarkWrapCommandConfigs/StrictDenyRead` | 1.05 ms | 3.31 ms | 1,540 ms [¹] |
| **Runtime exec deny** | | | |
| `BenchmarkGetRuntimeDeniedExecutablePaths/Empty` | 1.10 ms | 1.12 ms | **1,698 ms** [¹] |
| `BenchmarkGetRuntimeDeniedExecutablePaths/DefaultsOnly` | 2.96 ms | 2.58 ms | 2,109 ms [¹] |
| `BenchmarkGetRuntimeDeniedExecutablePaths/SmallDeny` | 1.66 ms | 1.60 ms | 1,542 ms [¹] |
| `BenchmarkGetRuntimeDeniedExecutablePaths/SharedBinaryHeavy` | 1.55 ms | 1.76 ms | 551 ms [¹] |
| `BenchmarkGetRuntimeDeniedExecutablePaths/LargeDeny` (45 entries) | 8.79 ms | 8.41 ms | 6,602 ms [¹] |
| **Amortized and baseline** | | | |
| `BenchmarkBaseline_True` (unsandboxed, per iter) [²] | 0.59 ms | 2.33 ms | 0.78 ms |
| `BenchmarkAmortized_True_10` (10 inner, sandboxed) | 20.3 ms | 25.8 ms | 27.3 ms |
| `BenchmarkAmortized_True_100` (100 inner, sandboxed) | 21.3 ms | 22.3 ms | 27.9 ms |
| Per-inner-call amortized overhead [³] | ~11 µs | ≈ 0 µs | ~6 µs |

[¹] Known WSL slowdown. `WrapCommand` calls
`GetRuntimeDeniedExecutablePaths` on every invocation, which does
filesystem lookups under `/usr/bin`, `/bin`, etc. On WSL2 each of those
lookups takes ~20 ms (vs microseconds on native Linux), likely because
WSL's interop layer serializes `stat` / `EvalSymlinks` calls across the
`/mnt/*` device boundary. [PR #98](https://github.com/Use-Tusk/fence/pull/98)
reduced the worst shared-binary collision case from ~4.5s to ~1.5s by
bounding the probe set, but the non-collision path still pays the full
per-lookup cost. Noted as a known issue; amortized usage is unaffected
because the cost is paid once at startup and inherited by child
processes.

[²] Baseline reflects Go's `exec.Command` + runner VM overhead, not raw
`true` exec time. Use only as a reference point for the amortized
comparison.

[³] Computed as `(BenchmarkAmortized_True_100 − BenchmarkAmortized_True_10) / 90`.
Isolates the marginal cost of one extra inner command once
initialization has been amortized away. Near-zero on all platforms —
once inside the sandbox, tool calls run at native speed.

### End-to-end hyperfine (WSL only)

For cross-platform hyperfine numbers, download the artifacts from the
Benchmarks workflow run. The WSL numbers below are included because they
illustrate what a user would actually feel on WSL today:

| Workload | Unsandboxed | Sandboxed |
|----------|-------------|-----------|
| `true` | 0.004 ms | 2,784 ms [¹] |
| `runtime-deny-startup` (sentinel) | 0.13 ms | 4,622 ms [¹] |
| `amortized-true-10` | 3.00 ms | 2,829 ms |
| `amortized-gitstatus-10` | 32.2 ms | 2,745 ms |
| `git-status` | 2.33 ms | 1,149 ms |
| `python` | 20.5 ms | 1,119 ms |

The sandboxed column for `true`, `echo`, and the other trivial workloads
is dominated by fence's own startup on WSL (same [¹] mechanism as the Go
table). `runtime-deny-startup` uses a deny list chosen to stress the PR #98 code path - it is the worst case, not a typical case.

## Running on WSL

Windows Subsystem for Linux is a first-class fence target and has
historically been the environment where the runtime exec deny resolver
misbehaves worst.

The benchmark scripts work on WSL without changes. Setup:

```bash
# Inside your WSL distro
sudo apt-get update
sudo apt-get install -y hyperfine bubblewrap socat ripgrep jq bc

go install golang.org/x/perf/cmd/benchstat@latest
```

Run the suite:

```bash
# Quick CLI run
./scripts/benchmark.sh -q

# Go microbenchmarks (includes the runtime-deny surface that PR #98 fixed)
go test -run=^$ -bench=. -benchmem -count=5 ./internal/sandbox/...
```

The benches most relevant to WSL regressions:

- `BenchmarkGetRuntimeDeniedExecutablePaths/SharedBinaryHeavy` — the Go-level
  sentinel for PR #98. Measures the alias-probing cost for deny rules that
  collide with busybox/coreutils multicall binaries.
- `runtime-deny-startup` (in `scripts/benchmark.sh`) — end-to-end sentinel
  for the same code path. Runs on any Linux but is most meaningful on WSL
  because that's where the original stall manifested.
- `BenchmarkAmortized_True_100` — catches per-tool-call regressions once
  initialization is amortized away.

If you have a WSL workspace on `/mnt/c/...`, run the benchmarks from there
too: the PR #98 bug only showed up when the resolver encountered the slow
`/mnt/*` filesystem device, so running on the rootfs alone can mask a
regression.

There is no CI coverage for WSL today (hosted Windows + WSL runners are
noisy because of nested virtualization). Run these benches manually on a
WSL machine when you touch the runtime exec deny or path-resolution code
paths.

**Practical guidance for WSL users today:**

- Prefer long-running agent mode (`fence -- <agent>`) over
  per-invocation mode (`fence -c "cmd"` in a loop). The amortized rows
  above show that per-tool-call overhead is near-zero on WSL once
  initialization is done.
- If you benchmark on WSL, expect init to take 1-3 seconds of wall
  clock even on idle hardware. That's the baseline to compare against,
  not native Linux's ~100ms.
- The pathology is filesystem-lookup-heavy. Workloads that avoid the
  runtime-deny resolver (for example, the `BenchmarkCheckCommand` and
  `BenchmarkAmortized_*` benches) look similar to native Linux on WSL.

## Additional Notes

- `Manager.Initialize()` starts HTTP + SOCKS proxies; on Linux also creates socat bridges
- Cold start includes all initialization; hot path is just `WrapCommand + exec`
- `BenchmarkManagerInitialize` measures init + cleanup per iteration; for tighter numbers on one half, use `BenchmarkManagerInit` or `BenchmarkManagerCleanup`
- `-m` (monitor mode) spawns additional monitoring processes, so we'll have to benchmark separately
- Keep workloads under the repo - avoid `/tmp` since Linux bwrap does `--tmpfs /tmp`
- `debug` mode changes logging, so always benchmark with debug off
