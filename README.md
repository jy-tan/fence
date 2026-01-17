# Fence

![GitHub Release](https://img.shields.io/github/v/release/Use-Tusk/fence)

A Go implementation of process sandboxing with network and filesystem restrictions.

Fence wraps commands in a sandbox that blocks network access by default and restricts filesystem operations based on configurable rules. It's most useful for running semi-trusted code (package installs, build scripts, CI jobs, unfamiliar repos) with controlled side effects, and it can also complement AI coding agents as defense-in-depth.

You can also think of Fence as a permission manager for your CLI coding agents.

## Features

- **Network Isolation**: All network access blocked by default
- **Domain Allowlisting**: Configure which domains are allowed
- **Filesystem Restrictions**: Control read/write access to paths
- **Command Blocking**: Block dangerous commands (e.g., `shutdown`, `rm -rf`) with configurable deny/allow lists
- **SSH Command Filtering**: Control which hosts and commands are allowed over SSH
- **Violation Monitoring**: Real-time logging of blocked requests and sandbox denials
- **Cross-Platform**: macOS (sandbox-exec) and Linux (bubblewrap)
- **HTTP/SOCKS5 Proxies**: Built-in filtering proxies for domain control
- **Permission Import**: Using Claude Code? Import your Claude permissions as Fence configs with `fence import --claude -o ~/.fence.json`

Fence can be used as a Go package or CLI tool.

## Documentation

- [Documentation index](docs/)
- [Configuration](docs/configuration.md)
- [Security model](docs/security-model.md)
- [Architecture](ARCHITECTURE.md)
- [Examples](examples/)

## Installation

At the moment, we only support macOS and Linux. For Windows users, we recommend using WSL.

### Quick Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/Use-Tusk/fence/main/install.sh | sh
```

To install a specific version:

```bash
curl -fsSL https://raw.githubusercontent.com/Use-Tusk/fence/main/install.sh | sh -s -- v0.1.0
```

### Install via Go

If you have Go installed:

```bash
go install github.com/Use-Tusk/fence/cmd/fence@latest
```

<details>
<summary>Build from source</summary>

```bash
git clone https://github.com/Use-Tusk/fence
cd fence
go build -o fence ./cmd/fence
```

</details>

**Additional requirements for Linux:**

- `bubblewrap` (for sandboxing)
- `socat` (for network bridging)
- `bpftrace` (optional, for filesystem violation visibility with when monitoring with `-m`)

## Quick Start

```bash
# This will be blocked (no domains allowed by default)
fence curl https://example.com

# Run with shell expansion
fence -c "echo hello && ls"

# Enable debug logging
fence -d curl https://example.com
```

For a more detailed introduction, see the [Quickstart Guide](docs/quickstart.md).

## CLI Usage

```text
fence [flags] -- [command...]

Flags:
  -c string        Run command string directly (like sh -c)
  -d, --debug      Enable debug logging (shows sandbox command, proxy activity, filter rules)
  -m, --monitor    Monitor mode (shows blocked requests and violations only)
  -p, --port       Expose port for inbound connections (can be repeated)
  -s, --settings   Path to settings file (default: ~/.fence.json)
  -t, --template   Use built-in template (e.g., code, local-dev-server)
  -v, --version    Show version information
  -h, --help       Help for fence

Subcommands:
  import           Import settings from other tools (e.g., --claude for Claude Code)
```

### Examples

```bash
# Block all network (default behavior)
fence curl https://example.com
# Output: curl: (56) CONNECT tunnel failed, response 403

# Use a built-in template
fence -t code -- claude

# Extend a template in your config (adds private registry to 'code' template)
# ~/.fence.json: {"extends": "code", "network": {"allowedDomains": ["private.company.com"]}}
fence npm install

# Use a custom config
fence --settings ./my-config.json npm install

# Block specific commands (via config file)
# ~/.fence.json: {"command": {"deny": ["git push", "npm publish"]}}
fence -c "git push"  # blocked
fence -c "git status"  # allowed

# Run a shell command
fence -c "git clone https://github.com/user/repo && cd repo && npm install"

# Debug mode shows proxy activity
fence -d wget https://example.com

# Monitor mode shows violations/blocked requests only
fence -m npm install

# Expose a port for inbound connections
fence -p 3000 -c "npm run dev"

# Import settings from Claude Code
fence import --claude -o .fence.json
```

## Library Usage

```go
package main

import (
    "fmt"
    "github.com/Use-Tusk/fence/pkg/fence"
)

func main() {
    // Check if platform supports sandboxing (macOS/Linux)
    if !fence.IsSupported() {
        fmt.Println("Sandboxing not supported on this platform")
        return
    }

    // Create config
    cfg := &fence.Config{
        Network: fence.NetworkConfig{
            AllowedDomains: []string{"api.example.com"},
        },
        Filesystem: fence.FilesystemConfig{
            AllowWrite: []string{"."},
        },
        Command: fence.CommandConfig{
            Deny: []string{"git push", "npm publish"},
        },
    }

    // Create manager (debug=false, monitor=false)
    manager := fence.NewManager(cfg, false, false)
    defer manager.Cleanup()

    // Initialize (starts proxies)
    if err := manager.Initialize(); err != nil {
        panic(err)
    }

    // Wrap a command
    wrapped, err := manager.WrapCommand("curl https://api.example.com/data")
    if err != nil {
        panic(err)
    }

    fmt.Println("Sandboxed command:", wrapped)
}
```

## Attribution

This project was inspired by Anthropic's [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime).
