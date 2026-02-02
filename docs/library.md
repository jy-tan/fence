# Library Usage (Go)

Fence can be used as a Go library to sandbox commands programmatically.

## Installation

```bash
go get github.com/Use-Tusk/fence
```

## Quick Start

```go
package main

import (
    "fmt"
    "os/exec"

    "github.com/Use-Tusk/fence/pkg/fence"
)

func main() {
    // Check platform support
    if !fence.IsSupported() {
        fmt.Println("Sandboxing not supported on this platform")
        return
    }

    // Create config
    cfg := &fence.Config{
        Network: fence.NetworkConfig{
            AllowedDomains: []string{"api.example.com"},
        },
    }

    // Create and initialize manager
    manager := fence.NewManager(cfg, false, false)
    defer manager.Cleanup()

    if err := manager.Initialize(); err != nil {
        panic(err)
    }

    // Wrap the command
    wrapped, err := manager.WrapCommand("curl https://api.example.com/data")
    if err != nil {
        panic(err)
    }

    // Execute it
    cmd := exec.Command("sh", "-c", wrapped)
    output, _ := cmd.CombinedOutput()
    fmt.Println(string(output))
}
```

## API Reference

### Functions

#### `IsSupported() bool`

Returns `true` if the current platform supports sandboxing (macOS or Linux).

```go
if !fence.IsSupported() {
    log.Fatal("Platform not supported")
}
```

#### `DefaultConfig() *Config`

Returns a default configuration with all network blocked.

```go
cfg := fence.DefaultConfig()
cfg.Network.AllowedDomains = []string{"example.com"}
```

#### `LoadConfig(path string) (*Config, error)`

Loads configuration from a JSON file. Supports JSONC (comments allowed).

```go
cfg, err := fence.LoadConfig(fence.DefaultConfigPath())
if err != nil {
    log.Fatal(err)
}
if cfg == nil {
    cfg = fence.DefaultConfig() // File doesn't exist
}
```

#### `DefaultConfigPath() string`

Returns the default config file path (`~/.config/fence/fence.json` on Linux, `~/Library/Application Support/fence/fence.json` on macOS, with fallback to legacy `~/.fence.json`).

#### `NewManager(cfg *Config, debug, monitor bool) *Manager`

Creates a new sandbox manager.

| Parameter | Description |
|-----------|-------------|
| `cfg` | Configuration for the sandbox |
| `debug` | Enable verbose logging (proxy activity, sandbox commands) |
| `monitor` | Log only violations (blocked requests) |

### Manager Methods

#### `Initialize() error`

Sets up sandbox infrastructure (starts HTTP and SOCKS proxies). Called automatically by `WrapCommand` if not already initialized.

```go
manager := fence.NewManager(cfg, false, false)
defer manager.Cleanup()

if err := manager.Initialize(); err != nil {
    log.Fatal(err)
}
```

#### `WrapCommand(command string) (string, error)`

Wraps a shell command with sandbox restrictions. Returns an error if:

- The command is blocked by policy (`command.deny`)
- The platform is unsupported
- Initialization fails

```go
wrapped, err := manager.WrapCommand("npm install")
if err != nil {
    // Command may be blocked by policy
    log.Fatal(err)
}
```

#### `SetExposedPorts(ports []int)`

Sets ports to expose for inbound connections (e.g., dev servers).

```go
manager.SetExposedPorts([]int{3000, 8080})
```

#### `Cleanup()`

Stops proxies and releases resources. Always call via `defer`.

#### `HTTPPort() int` / `SOCKSPort() int`

Returns the ports used by the filtering proxies.

## Configuration Types

### Config

```go
type Config struct {
    Extends    string           // Template to extend (e.g., "code")
    Network    NetworkConfig
    Filesystem FilesystemConfig
    Command    CommandConfig
    SSH        SSHConfig
    AllowPty   bool             // Allow PTY allocation
}
```

### NetworkConfig

```go
type NetworkConfig struct {
    AllowedDomains      []string // Domains to allow (supports *.example.com)
    DeniedDomains       []string // Domains to explicitly deny
    AllowUnixSockets    []string // Specific Unix socket paths to allow
    AllowAllUnixSockets bool     // Allow all Unix socket connections
    AllowLocalBinding   bool     // Allow binding to localhost ports
    AllowLocalOutbound  *bool    // Allow outbound to localhost (defaults to AllowLocalBinding)
    HTTPProxyPort       int      // Override HTTP proxy port (0 = auto)
    SOCKSProxyPort      int      // Override SOCKS proxy port (0 = auto)
}
```

### FilesystemConfig

```go
type FilesystemConfig struct {
    DenyRead       []string // Paths to deny read access
    AllowWrite     []string // Paths to allow write access
    DenyWrite      []string // Paths to explicitly deny write access
    AllowGitConfig bool     // Allow read access to ~/.gitconfig
}
```

### CommandConfig

```go
type CommandConfig struct {
    Deny        []string // Command patterns to block
    Allow       []string // Exceptions to deny rules
    UseDefaults *bool    // Use default deny list (true if nil)
}
```

### SSHConfig

```go
type SSHConfig struct {
    AllowedHosts     []string // Host patterns to allow (supports wildcards)
    DeniedHosts      []string // Host patterns to deny
    AllowedCommands  []string // Commands allowed over SSH
    DeniedCommands   []string // Commands denied over SSH
    AllowAllCommands bool     // Use denylist mode instead of allowlist
    InheritDeny      bool     // Apply global command.deny rules to SSH
}
```

## Examples

### Allow specific domains

```go
cfg := &fence.Config{
    Network: fence.NetworkConfig{
        AllowedDomains: []string{
            "registry.npmjs.org",
            "*.github.com",
            "api.openai.com",
        },
    },
}
```

### Restrict filesystem access

```go
cfg := &fence.Config{
    Filesystem: fence.FilesystemConfig{
        AllowWrite: []string{".", "/tmp"},
        DenyRead:   []string{"~/.ssh", "~/.aws"},
    },
}
```

### Block dangerous commands

```go
cfg := &fence.Config{
    Command: fence.CommandConfig{
        Deny: []string{
            "rm -rf /",
            "git push",
            "npm publish",
        },
    },
}
```

### Expose dev server port

```go
manager := fence.NewManager(cfg, false, false)
manager.SetExposedPorts([]int{3000})
defer manager.Cleanup()

wrapped, _ := manager.WrapCommand("npm run dev")
```

### Load and extend config

```go
cfg, err := fence.LoadConfig(fence.DefaultConfigPath())
if err != nil {
    log.Fatal(err)
}
if cfg == nil {
    cfg = fence.DefaultConfig()
}

// Add additional restrictions
cfg.Command.Deny = append(cfg.Command.Deny, "dangerous-cmd")
```

## Error Handling

`WrapCommand` returns an error when a command is blocked:

```go
wrapped, err := manager.WrapCommand("git push origin main")
if err != nil {
    // err.Error() = "command blocked by policy: git push origin main"
    fmt.Println("Blocked:", err)
    return
}
```

## Platform Differences

| Feature | macOS | Linux |
|---------|-------|-------|
| Sandbox mechanism | sandbox-exec | bubblewrap |
| Network isolation | HTTP/SOCKS proxy | Network namespace + proxy |
| Filesystem restrictions | Seatbelt profiles | Bind mounts |
| Requirements | None | `bubblewrap`, `socat` |

## Thread Safety

- `Manager` instances are **not** thread-safe
- Create one manager per goroutine, or synchronize access
- Proxies are shared and handle concurrent connections
