![Fence Banner](assets/fence-banner.png)

<div align="center">

![GitHub Release](https://img.shields.io/github/v/release/Use-Tusk/fence)

</div>

Fence wraps commands in a sandbox that blocks network access by default and restricts filesystem operations based on configurable rules. It's most useful for running semi-trusted code (package installs, build scripts, CI jobs, unfamiliar repos) with controlled side effects, and it can also complement AI coding agents as defense-in-depth.

```bash
# Block all network access (default)
fence curl https://example.com  # → 403 Forbidden

# Allow specific domains
fence -t code npm install  # → uses 'code' template with npm/pypi/etc allowed

# Block dangerous commands
fence -c "rm -rf /"  # → blocked by command deny rules
```

You can also think of Fence as a permission manager for your CLI agents. **Fence works with popular coding agents like Claude Code, Codex, Gemini CLI, Cursor Agent, OpenCode, Factory (Droid) CLI, etc.** See [agents.md](./docs/agents.md) for more details.

## Install

**macOS / Linux:**

```bash
curl -fsSL https://raw.githubusercontent.com/Use-Tusk/fence/main/install.sh | sh
```

<details>
<summary>Other installation methods</summary>

**Go install:**

```bash
go install github.com/Use-Tusk/fence/cmd/fence@latest
```

**Build from source:**

```bash
git clone https://github.com/Use-Tusk/fence
cd fence
go build -o fence ./cmd/fence
```

</details>

**Additional requirements for Linux:**

- `bubblewrap` (for sandboxing)
- `socat` (for network bridging)
- `bpftrace` (optional, for filesystem violation visibility when monitoring with `-m`)

## Usage

### Basic

```bash
# Run command with all network blocked (no domains allowed by default)
fence curl https://example.com

# Run with shell expansion
fence -c "echo hello && ls"

# Enable debug logging
fence -d curl https://example.com

# Use a template
fence -t code -- claude  # Runs Claude Code using `code` template config

# Monitor mode (shows violations)
fence -m npm install

# Show all commands and options
fence --help
```

### Configuration

Fence reads from `~/.config/fence/fence.json` by default (or `~/Library/Application Support/fence/fence.json` on macOS).

```json
{
  "extends": "code",
  "network": { "allowedDomains": ["private.company.com"] },
  "filesystem": { "allowWrite": ["."] },
  "command": { "deny": ["git push", "npm publish"] }
}
```

Use `fence --settings ./custom.json` to specify a different config.

Create a starter config with sensible defaults:

```bash
# Creates config at the default path with:
# { "extends": "code" }
fence config init

# Include scaffold arrays as editable hints
fence config init --scaffold
```

### Import from Claude Code

```bash
fence import --claude --save
```

## Features

- **Network isolation** - All outbound blocked by default; allowlist domains via config
- **Filesystem restrictions** - Control read/write access paths
- **Command blocking** - Deny dangerous commands like `rm -rf /`, `git push`
- **SSH Command Filtering** - Control which hosts and commands are allowed over SSH
- **Built-in templates** - Pre-configured rulesets for common workflows
- **Violation monitoring** - Real-time logging of blocked requests (`-m`)
- **Cross-platform** - macOS (sandbox-exec) + Linux (bubblewrap)

Fence can be used as a Go package or CLI tool.

## Documentation

- [Index](/docs/README.md)
- [Quickstart Guide](docs/quickstart.md)
- [Configuration Reference](docs/configuration.md)
- [Security Model](docs/security-model.md)
- [Architecture](ARCHITECTURE.md)
- [Library Usage (Go)](docs/library.md)
- [Examples](examples/)

## Attribution

Inspired by Anthropic's [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime).
