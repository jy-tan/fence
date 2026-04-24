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

Loads configuration from a JSON or JSONC file. The extension is not
inspected: comments and trailing commas are accepted regardless of whether
the file is named `fence.json` or `fence.jsonc`.

This is a low-level loader and does not resolve `extends` entries relative to
the config file location. Use `LoadConfigResolved` if your config may use
relative `extends` paths.

#### `LoadConfigResolved(path string) (*Config, error)`

Loads configuration from a JSON file and resolves `extends` entries relative to
that file's parent directory. This matches the CLI's behavior.

```go
path := fence.ResolveDefaultConfigPath()

cfg, err := fence.LoadConfigResolved(path)
if err != nil {
    log.Fatal(err)
}
if cfg == nil {
    cfg = fence.DefaultConfig() // File doesn't exist
}
```

#### `DefaultConfigPath() string`

Returns the canonical config file path for new configs (`$XDG_CONFIG_HOME/fence/fence.json` on Linux, typically `~/.config/fence/fence.json`; `~/.config/fence/fence.json` on macOS).

#### `ResolveDefaultConfigPath() string`

Returns the config path fence should load by default. It uses the canonical path (`$XDG_CONFIG_HOME/fence/fence.json` on Linux, typically `~/.config/fence/fence.json`; `~/.config/fence/fence.json` on macOS) when that file exists, and otherwise falls back to legacy macOS `~/Library/Application Support/fence/fence.json` and legacy `~/.fence.json` when those files exist.

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

#### `SetService(opts ServiceOptions)`

Configures the sandboxed service's inbound-connectivity model. Must be called
before `Initialize`.

```go
manager.SetService(fence.ServiceOptions{
    ExposedPorts:   []int{3000, 8080},
    ExecutionModel: fence.ServiceBindsInSandbox, // default
})
```

For services whose start command delegates port binding to an external daemon
(e.g. `docker compose up`, `podman run`, `systemctl start …`) set
`ExecutionModel: fence.ServiceBindsOnHost`. Fence then skips setting up the
reverse bridge, which would otherwise collide with the daemon's own bind on
the host port.

```go
manager.SetService(fence.ServiceOptions{
    ExposedPorts:   []int{8000},
    ExecutionModel: fence.ServiceBindsOnHost, // dockerd binds 8000 on the host
})
```

#### `ExposeHostPath(path string, writable bool) error`

Registers a host file or directory that must be visible inside the sandbox at
the same path. Use this when you need to hand a host file (e.g. a
caller-generated config or temp file) to the sandboxed process.

This decouples callers from fence's internal mount plan — in particular from
the fact that fence tmpfs-overmounts `/tmp` on Linux, which would otherwise
hide any file the caller wrote via `os.CreateTemp("", ...)`. You don't need
to know where fence overmounts to pick a valid path; just call
`ExposeHostPath` with the path you already chose.

```go
f, _ := os.CreateTemp("", "compose-override-*.yml")
_ = os.WriteFile(f.Name(), overrideYaml, 0o600)

manager.ExposeHostPath(f.Name(), false /* read-only */)
```

Must be called before `WrapCommand`. The path must exist at call time.

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
    MacOS      MacOSConfig
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

### MacOSConfig

```go
type MacOSConfig struct {
    Mach MachConfig
}

type MachConfig struct {
    Lookup   []string // Additional Mach/XPC services allowed for mach-lookup
    Register []string // Additional Mach/XPC services allowed for mach-register
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
manager.SetService(fence.ServiceOptions{ExposedPorts: []int{3000}})
defer manager.Cleanup()

wrapped, _ := manager.WrapCommand("npm run dev")
```

### Expose a docker-compose stack (host-bound ports)

```go
manager := fence.NewManager(cfg, false, false)
manager.SetService(fence.ServiceOptions{
    ExposedPorts:   []int{8000},
    ExecutionModel: fence.ServiceBindsOnHost,
})
defer manager.Cleanup()

wrapped, _ := manager.WrapCommand("docker compose up")
```

### Hand a host-generated file to the sandboxed process

```go
f, _ := os.CreateTemp("", "override-*.yml")
_ = os.WriteFile(f.Name(), overrideYaml, 0o600)

manager.ExposeHostPath(f.Name(), false)
wrapped, _ := manager.WrapCommand("docker compose -f base.yml -f " + f.Name() + " up")
```

### Load and extend config

```go
path := fence.ResolveDefaultConfigPath()

cfg, err := fence.LoadConfigResolved(path)
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
