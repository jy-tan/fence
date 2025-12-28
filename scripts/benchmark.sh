#!/bin/bash
# benchmark.sh - Comprehensive sandbox benchmarking
#
# This script compares sandbox overhead between:
#   - Unsandboxed (baseline)
#   - Sandboxed (default mode)
#   - Sandboxed with monitor (-m)
#
# Usage:
#   ./scripts/benchmark.sh [options]
#
# Options:
#   -b, --binary PATH    Path to fence binary (default: ./fence or builds one)
#   -o, --output DIR     Output directory for results (default: ./benchmarks)
#   -n, --runs N         Minimum runs per benchmark (default: 30)
#   -q, --quick          Quick mode: fewer runs, skip slow benchmarks
#   --network            Include network benchmarks (requires local server)
#   -h, --help           Show this help
#
# Requirements:
#   - hyperfine (brew install hyperfine / apt install hyperfine)
#   - go (for building fence if needed)
#   - Optional: python3 (for local-server.py network benchmarks)

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Defaults
FENCE_BIN=""
OUTPUT_DIR="./benchmarks"
MIN_RUNS=30
WARMUP=3
QUICK=false
NETWORK=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -b|--binary)
            FENCE_BIN="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -n|--runs)
            MIN_RUNS="$2"
            shift 2
            ;;
        -q|--quick)
            QUICK=true
            MIN_RUNS=10
            WARMUP=1
            shift
            ;;
        --network)
            NETWORK=true
            shift
            ;;
        -h|--help)
            head -30 "$0" | tail -28
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Find or build fence binary
if [[ -z "$FENCE_BIN" ]]; then
    if [[ -x "./fence" ]]; then
        FENCE_BIN="./fence"
    elif [[ -x "./dist/fence" ]]; then
        FENCE_BIN="./dist/fence"
    else
        echo -e "${BLUE}Building fence...${NC}"
        go build -o ./fence ./cmd/fence
        FENCE_BIN="./fence"
    fi
fi

if [[ ! -x "$FENCE_BIN" ]]; then
    echo -e "${RED}Error: fence binary not found at $FENCE_BIN${NC}"
    exit 1
fi

# Check for hyperfine
if ! command -v hyperfine &> /dev/null; then
    echo -e "${RED}Error: hyperfine not found. Install with:${NC}"
    echo "  brew install hyperfine   # macOS"
    echo "  apt install hyperfine    # Linux"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Create workspace in current directory (not /tmp, which bwrap overlays)
WORKSPACE=$(mktemp -d -p .)
trap 'rm -rf "$WORKSPACE"' EXIT

# Create settings file for sandbox
SETTINGS_FILE="$WORKSPACE/fence.json"
cat > "$SETTINGS_FILE" << EOF
{
  "filesystem": {
    "allowWrite": ["$WORKSPACE", "."]
  }
}
EOF

# Platform info
OS=$(uname -s)
ARCH=$(uname -m)
KERNEL=$(uname -r)
DATE=$(date +%Y-%m-%d)
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Results file
RESULTS_JSON="$OUTPUT_DIR/${OS,,}-${ARCH}-${TIMESTAMP}.json"
RESULTS_MD="$OUTPUT_DIR/${OS,,}-${ARCH}-${TIMESTAMP}.md"

echo ""
echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}Fence Sandbox Benchmarks${NC}"
echo -e "${BLUE}==========================================${NC}"
echo ""
echo "Platform:     $OS $ARCH"
echo "Kernel:       $KERNEL"
echo "Date:         $DATE"
echo "Fence:        $FENCE_BIN"
echo "Output:       $OUTPUT_DIR"
echo "Min runs:     $MIN_RUNS"
echo ""

# Helper to run hyperfine with consistent options
run_bench() {
    local name="$1"
    shift
    local json_file="$WORKSPACE/${name}.json"
    
    echo -e "${GREEN}Benchmarking: $name${NC}"
    
    hyperfine \
        --warmup "$WARMUP" \
        --min-runs "$MIN_RUNS" \
        --export-json "$json_file" \
        --style basic \
        "$@"
    
    echo ""
}

# ============================================================================
# Spawn-only benchmarks (minimal process overhead)
# ============================================================================

echo -e "${YELLOW}=== Spawn-Only Benchmarks ===${NC}"
echo ""

run_bench "true" \
    --command-name "unsandboxed" "true" \
    --command-name "sandboxed" "$FENCE_BIN -s $SETTINGS_FILE -- true"

run_bench "echo" \
    --command-name "unsandboxed" "echo hello >/dev/null" \
    --command-name "sandboxed" "$FENCE_BIN -s $SETTINGS_FILE -c 'echo hello' >/dev/null"

# ============================================================================
# Tool compatibility benchmarks
# ============================================================================

echo -e "${YELLOW}=== Tool Compatibility Benchmarks ===${NC}"
echo ""

if command -v python3 &> /dev/null; then
    run_bench "python" \
        --command-name "unsandboxed" "python3 -c 'pass'" \
        --command-name "sandboxed" "$FENCE_BIN -s $SETTINGS_FILE -c \"python3 -c 'pass'\""
else
    echo -e "${YELLOW}Skipping python3 (not found)${NC}"
fi

if command -v node &> /dev/null && [[ "$QUICK" == "false" ]]; then
    run_bench "node" \
        --command-name "unsandboxed" "node -e ''" \
        --command-name "sandboxed" "$FENCE_BIN -s $SETTINGS_FILE -c \"node -e ''\""
else
    echo -e "${YELLOW}Skipping node (not found or quick mode)${NC}"
fi

# ============================================================================
# Real workload benchmarks
# ============================================================================

echo -e "${YELLOW}=== Real Workload Benchmarks ===${NC}"
echo ""

if command -v git &> /dev/null && [[ -d .git ]]; then
    run_bench "git-status" \
        --command-name "unsandboxed" "git status --porcelain >/dev/null" \
        --command-name "sandboxed" "$FENCE_BIN -s $SETTINGS_FILE -- git status --porcelain >/dev/null"
else
    echo -e "${YELLOW}Skipping git status (not in a git repo)${NC}"
fi

if command -v rg &> /dev/null && [[ "$QUICK" == "false" ]]; then
    run_bench "ripgrep" \
        --command-name "unsandboxed" "rg -n 'package' -S . >/dev/null 2>&1 || true" \
        --command-name "sandboxed" "$FENCE_BIN -s $SETTINGS_FILE -c \"rg -n 'package' -S . >/dev/null 2>&1\" || true"
else
    echo -e "${YELLOW}Skipping ripgrep (not found or quick mode)${NC}"
fi

# ============================================================================
# File I/O benchmarks
# ============================================================================

echo -e "${YELLOW}=== File I/O Benchmarks ===${NC}"
echo ""

run_bench "file-write" \
    --command-name "unsandboxed" "echo 'test' > $WORKSPACE/test.txt" \
    --command-name "sandboxed" "$FENCE_BIN -s $SETTINGS_FILE -c \"echo 'test' > $WORKSPACE/test.txt\""

run_bench "file-read" \
    --command-name "unsandboxed" "cat $WORKSPACE/test.txt >/dev/null" \
    --command-name "sandboxed" "$FENCE_BIN -s $SETTINGS_FILE -c 'cat $WORKSPACE/test.txt' >/dev/null"

# ============================================================================
# Monitor mode benchmarks (optional)
# ============================================================================

if [[ "$QUICK" == "false" ]]; then
    echo -e "${YELLOW}=== Monitor Mode Benchmarks ===${NC}"
    echo ""
    
    run_bench "monitor-true" \
        --command-name "sandboxed" "$FENCE_BIN -s $SETTINGS_FILE -- true" \
        --command-name "sandboxed+monitor" "$FENCE_BIN -m -s $SETTINGS_FILE -- true"
fi

# ============================================================================
# Network benchmarks (optional, requires local server)
# ============================================================================

if [[ "$NETWORK" == "true" ]]; then
    echo -e "${YELLOW}=== Network Benchmarks ===${NC}"
    echo ""
    
    # Start local server
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "$SCRIPT_DIR/local-server.py" ]]; then
        python3 "$SCRIPT_DIR/local-server.py" &
        SERVER_PID=$!
        trap 'kill $SERVER_PID 2>/dev/null || true; rm -rf "$WORKSPACE"' EXIT
        sleep 1
        
        # Create network settings
        NET_SETTINGS="$WORKSPACE/fence-net.json"
        cat > "$NET_SETTINGS" << EOF
{
  "network": {
    "allowedDomains": ["127.0.0.1", "localhost"]
  },
  "filesystem": {
    "allowWrite": ["$WORKSPACE"]
  }
}
EOF
        
        if command -v curl &> /dev/null; then
            run_bench "network-curl" \
                --command-name "unsandboxed" "curl -s http://127.0.0.1:8765/ >/dev/null" \
                --command-name "sandboxed" "$FENCE_BIN -s $NET_SETTINGS -c 'curl -s http://127.0.0.1:8765/' >/dev/null"
        fi
        
        kill $SERVER_PID 2>/dev/null || true
    else
        echo -e "${YELLOW}Skipping network benchmarks (local-server.py not found)${NC}"
    fi
fi

# ============================================================================
# Combine results and generate report
# ============================================================================

echo -e "${YELLOW}=== Generating Report ===${NC}"
echo ""

# Combine all JSON results
echo "{" > "$RESULTS_JSON"
echo "  \"platform\": \"$OS\"," >> "$RESULTS_JSON"
echo "  \"arch\": \"$ARCH\"," >> "$RESULTS_JSON"
echo "  \"kernel\": \"$KERNEL\"," >> "$RESULTS_JSON"
echo "  \"date\": \"$DATE\"," >> "$RESULTS_JSON"
echo "  \"fence_version\": \"$($FENCE_BIN --version 2>/dev/null || echo unknown)\"," >> "$RESULTS_JSON"
echo "  \"benchmarks\": {" >> "$RESULTS_JSON"

first=true
for json_file in "$WORKSPACE"/*.json; do
    [[ -f "$json_file" ]] || continue
    name=$(basename "$json_file" .json)
    if [[ "$first" == "true" ]]; then
        first=false
    else
        echo "," >> "$RESULTS_JSON"
    fi
    echo "    \"$name\": $(cat "$json_file")" >> "$RESULTS_JSON"
done

echo "" >> "$RESULTS_JSON"
echo "  }" >> "$RESULTS_JSON"
echo "}" >> "$RESULTS_JSON"

# Generate Markdown report
cat > "$RESULTS_MD" << EOF
# Fence Benchmark Results

**Platform:** $OS $ARCH  
**Kernel:** $KERNEL  
**Date:** $DATE  
**Fence:** $($FENCE_BIN --version 2>/dev/null || echo unknown)

## Summary

| Benchmark | Unsandboxed | Sandboxed | Overhead |
|-----------|-------------|-----------|----------|
EOF

# Parse results and add to markdown (run in subshell to prevent failures from stopping script)
if command -v jq &> /dev/null; then
    for json_file in "$WORKSPACE"/*.json; do
        [[ -f "$json_file" ]] || continue
        name=$(basename "$json_file" .json)
        
        # Extract mean times, defaulting to empty if not found
        unsandboxed=$(jq -r '.results[] | select(.command == "unsandboxed") | .mean // empty' "$json_file" 2>/dev/null) || true
        sandboxed=$(jq -r '.results[] | select(.command == "sandboxed") | .mean // empty' "$json_file" 2>/dev/null) || true
        
        # Skip if values are missing, null, or zero
        if [[ -z "$unsandboxed" || -z "$sandboxed" || "$unsandboxed" == "null" || "$sandboxed" == "null" ]]; then
            continue
        fi
        
        # Calculate values, catching any bc errors
        overhead=$(echo "scale=1; $sandboxed / $unsandboxed" | bc 2>/dev/null) || continue
        unsandboxed_ms=$(echo "scale=2; $unsandboxed * 1000" | bc 2>/dev/null) || continue
        sandboxed_ms=$(echo "scale=2; $sandboxed * 1000" | bc 2>/dev/null) || continue
        
        if [[ -n "$overhead" && -n "$unsandboxed_ms" && -n "$sandboxed_ms" ]]; then
            echo "| $name | ${unsandboxed_ms}ms | ${sandboxed_ms}ms | ${overhead}x |" >> "$RESULTS_MD"
        fi
    done
fi

echo ""
echo -e "${GREEN}Results saved to:${NC}"
echo "  JSON: $RESULTS_JSON"
echo "  Markdown: $RESULTS_MD"
echo ""

# Print quick summary (errors in this section should not fail the script)
if command -v jq &> /dev/null; then
    echo -e "${BLUE}Quick Summary (overhead factors):${NC}"
    for json_file in "$WORKSPACE"/*.json; do
        (
            [[ -f "$json_file" ]] || exit 0
            name=$(basename "$json_file" .json)
            
            # Extract values, defaulting to empty if not found
            unsandboxed=$(jq -r '.results[] | select(.command == "unsandboxed") | .mean // empty' "$json_file" 2>/dev/null) || exit 0
            sandboxed=$(jq -r '.results[] | select(.command == "sandboxed") | .mean // empty' "$json_file" 2>/dev/null) || exit 0
            
            # Skip if either value is missing or null
            [[ -z "$unsandboxed" || -z "$sandboxed" || "$unsandboxed" == "null" || "$sandboxed" == "null" ]] && exit 0
            
            # Calculate overhead, catching any bc errors
            overhead=$(echo "scale=1; $sandboxed / $unsandboxed" | bc 2>/dev/null) || exit 0
            
            [[ -n "$overhead" ]] && printf "  %-15s %sx\n" "$name:" "$overhead"
        ) || true  # Ignore errors from subshell
    done
fi

echo ""
echo -e "${GREEN}Done!${NC}"
