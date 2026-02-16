# Configuration

Fence reads settings from `~/.config/fence/fence.json` by default (or `~/Library/Application Support/fence/fence.json` on macOS). Legacy `~/.fence.json` is also supported. Pass `--settings ./fence.json` to use a custom path. Config files support JSONC.

Example config:

```json
{
  "$schema": "https://raw.githubusercontent.com/Use-Tusk/fence/main/docs/schema/fence.schema.json",
  "network": {
    "allowedDomains": ["github.com", "*.npmjs.org", "registry.yarnpkg.com"],
    "deniedDomains": ["evil.com"]
  },
  "filesystem": {
    "denyRead": ["/etc/passwd"],
    "allowWrite": [".", "/tmp"],
    "denyWrite": [".git/hooks"]
  },
  "command": {
    "deny": ["git push", "npm publish"]
  },
  "ssh": {
    "allowedHosts": ["*.example.com"],
    "allowedCommands": ["ls", "cat", "grep", "tail", "head"]
  }
}
```

> [!TIP]
> The `$schema` key is optional and is only used by editors for IntelliSense/validation.
> For the latest development schema, use the `main` URL shown above. You may also pin this URL to your installed version tag (for example, replace `main` with `v0.1.25`) so editor validation matches runtime behavior.

## Config Inheritance

You can extend built-in templates or other config files using the `extends` field. This reduces boilerplate by inheriting settings from a base and only specifying your overrides.

### Extending a template

```json
{
  "extends": "code",
  "network": {
    "allowedDomains": ["private-registry.company.com"]
  }
}
```

This config:

- Inherits all settings from the `code` template (LLM providers, package registries, filesystem protections, command restrictions)
- Adds `private-registry.company.com` to the allowed domains list

### Extending a file

You can also extend other config files using absolute or relative paths:

```json
{
  "extends": "./base-config.json",
  "network": {
    "allowedDomains": ["extra-domain.com"]
  }
}
```

```json
{
  "extends": "/etc/fence/company-base.json",
  "filesystem": {
    "denyRead": ["~/company-secrets/**"]
  }
}
```

Relative paths are resolved relative to the config file's directory. The extended file is validated before merging.

### Detection

The `extends` value is treated as a file path if it contains `/` or `\`, or starts with `.`. Otherwise it's treated as a template name.

### Merge behavior

- Slice fields (domains, paths, commands) are appended and deduplicated
- Boolean fields use OR logic (true if either base or override enables it)
- Integer fields (ports) use override-wins semantics (0 keeps base value)

### Chaining

Extends chains are supported—a file can extend a template, and another file can extend that file. Circular extends are detected and rejected. Maximum chain depth is 10.

See [templates.md](templates.md) for available templates.

## Network Configuration

| Field | Description |
|-------|-------------|
| `allowedDomains` | List of allowed domains. Supports wildcards like `*.example.com` |
| `deniedDomains` | List of denied domains (checked before allowed) |
| `allowUnixSockets` | List of allowed Unix socket paths (macOS) |
| `allowAllUnixSockets` | Allow all Unix sockets |
| `allowLocalBinding` | Allow binding to local ports |
| `allowLocalOutbound` | Allow outbound connections to localhost, e.g., local DBs (defaults to `allowLocalBinding` if not set) |
| `httpProxyPort` | Fixed port for HTTP proxy (default: random available port) |
| `socksProxyPort` | Fixed port for SOCKS5 proxy (default: random available port) |

### Wildcard Domain Access

Setting `allowedDomains: ["*"]` enables **relaxed network mode**:

- Direct network connections are allowed (sandbox doesn't block outbound)
- Proxy still runs for apps that respect `HTTP_PROXY`
- `deniedDomains` is only enforced for apps using the proxy

> [!WARNING]
> **Security tradeoff**: Apps that ignore `HTTP_PROXY` will bypass `deniedDomains` filtering entirely.

Use this when you need to support apps that don't respect proxy environment variables.

## Filesystem Configuration

| Field | Description |
|-------|-------------|
| `wslInterop` | WSL interop support. `null` (default) = auto-detect, `true` = force on, `false` = force off. When active, auto-allows execute on `/init`. |
| `allowRead` | Paths to allow reading and directory listing (Landlock: `READ_FILE + READ_DIR + EXECUTE`) |
| `allowExecute` | Paths to allow executing only (Landlock: `READ_FILE + EXECUTE`, no directory listing) |
| `denyRead` | Paths to deny reading (deny-only pattern) |
| `allowWrite` | Paths to allow writing (also grants read and execute) |
| `denyWrite` | Paths to deny writing (takes precedence) |
| `allowGitConfig` | Allow writes to `.git/config` files |

### Permission Tiers

Fence provides three levels of filesystem access, from most restrictive to least:

| Config field | Landlock rights | Use case |
|---|---|---|
| `allowExecute` | `READ_FILE + EXECUTE` | Specific binaries you need to run |
| `allowRead` | `READ_FILE + READ_DIR + EXECUTE` | Directories you need to browse and read |
| `allowWrite` | All read rights + all write rights | Directories that need file creation/modification |

> [!NOTE]
> Both `allowRead` and `allowExecute` grant `READ_FILE + EXECUTE`. The difference is that `allowRead` also grants `READ_DIR` (directory listing), while `allowExecute` does not. For individual files there is no practical difference; the distinction matters for directories where `allowExecute` prevents listing contents while still allowing execution of known paths within.
> [!TIP]
> **Best practice**: prefer pointing `allowExecute` at specific files (e.g., `/mnt/c/.../powershell.exe`) rather than directories. When Landlock is not active (kernel < 5.13 or wrapper skipped), directory-scoped `allowExecute` behaves like `allowRead` because bwrap only enforces read-only mounts without distinguishing execute from read permissions.

System paths like `/usr`, `/lib`, `/bin`, `/etc` are always readable — you don't need to add them.

### WSL (Windows Subsystem for Linux) Example

On WSL2, fence auto-detects the environment and allows `/init` (the WSL binfmt_misc interpreter) automatically. You only need to add the specific Windows executables and paths you use:

```json
{
  "extends": "code",
  "filesystem": {
    "allowExecute": [
      "/mnt/c/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe"
    ],
    "allowWrite": [
      "/mnt/c/temp"
    ]
  }
}
```

- `/init` is handled automatically by `wslInterop` (auto-detected). It's WSL's init binary — a statically-linked ELF executable used as the binfmt_misc interpreter for all `.exe` execution. `/usr/bin/wslpath` is a symlink to it.
- `powershell.exe` — Specific Windows binary allowed by exact path (not the whole directory).
- `/mnt/c/temp` — Writable temp directory on the Windows filesystem (needed when Windows programs must access the files).

To disable WSL interop explicitly: `"wslInterop": false`.

## Command Configuration

Block specific commands from being executed, even within command chains.

| Field | Description |
|-------|-------------|
| `deny` | List of command prefixes to block (e.g., `["git push", "rm -rf"]`) |
| `allow` | List of command prefixes to allow, overriding `deny` |
| `useDefaults` | Enable default deny list of dangerous system commands (default: `true`) |

Example:

```json
{
  "command": {
    "deny": ["git push", "npm publish"],
    "allow": ["git push origin docs"]
  }
}
```

### Default Denied Commands

When `useDefaults` is `true` (the default), fence blocks these dangerous commands:

- System control: `shutdown`, `reboot`, `halt`, `poweroff`, `init 0/6`
- Kernel manipulation: `insmod`, `rmmod`, `modprobe`, `kexec`
- Disk operations: `mkfs*`, `fdisk`, `parted`, `dd if=`
- Container escape: `docker run -v /:/`, `docker run --privileged`
- Namespace escape: `chroot`, `unshare`, `nsenter`

To disable defaults: `"useDefaults": false`

### Command Detection

Fence detects blocked commands in:

- Direct commands: `git push origin main`
- Command chains: `ls && git push` or `ls; git push`
- Pipelines: `echo test | git push`
- Shell invocations: `bash -c "git push"` or `sh -lc "ls && git push"`

## SSH Configuration

Control which SSH commands are allowed. By default, SSH uses **allowlist mode** for security - only explicitly allowed hosts and commands can be used.

| Field | Description |
|-------|-------------|
| `allowedHosts` | Host patterns to allow SSH connections to (supports wildcards like `*.example.com`, `prod-*`) |
| `deniedHosts` | Host patterns to deny SSH connections to (checked before allowed) |
| `allowedCommands` | Commands allowed over SSH (allowlist mode) |
| `deniedCommands` | Commands denied over SSH (checked before allowed) |
| `allowAllCommands` | If `true`, use denylist mode instead of allowlist (allow all commands except denied) |
| `inheritDeny` | If `true`, also apply global `command.deny` rules to SSH commands |

### Basic Example (Allowlist Mode)

```json
{
  "ssh": {
    "allowedHosts": ["*.example.com"],
    "allowedCommands": ["ls", "cat", "grep", "tail", "head", "find"]
  }
}
```

This allows:

- SSH to any `*.example.com` host
- Only the listed commands (and their arguments)
- Interactive sessions (no remote command)

### Denylist Mode Example

```json
{
  "ssh": {
    "allowedHosts": ["dev-*.example.com"],
    "allowAllCommands": true,
    "deniedCommands": ["rm -rf", "shutdown", "chmod"]
  }
}
```

This allows:

- SSH to any `dev-*.example.com` host
- Any command except the denied ones

### Inheriting Global Denies

```json
{
  "command": {
    "deny": ["shutdown", "reboot", "rm -rf /"]
  },
  "ssh": {
    "allowedHosts": ["*.example.com"],
    "allowAllCommands": true,
    "inheritDeny": true
  }
}
```

With `inheritDeny: true`, SSH commands also check against:

- Global `command.deny` list
- Default denied commands (if `command.useDefaults` is true)

### Host Pattern Matching

SSH host patterns support wildcards anywhere:

| Pattern | Matches |
|---------|---------|
| `server1.example.com` | Exact match only |
| `*.example.com` | Any subdomain of example.com |
| `prod-*` | Any hostname starting with `prod-` |
| `prod-*.us-east.*` | Multiple wildcards |
| `*` | All hosts |

### Evaluation Order

1. Check if host matches `deniedHosts` → **DENY**
2. Check if host matches `allowedHosts` → continue (else **DENY**)
3. If no remote command (interactive session) → **ALLOW**
4. Check if command matches `deniedCommands` → **DENY**
5. If `inheritDeny`, check global `command.deny` → **DENY**
6. If `allowAllCommands` → **ALLOW**
7. Check if command matches `allowedCommands` → **ALLOW**
8. Default → **DENY**

## Other Options

| Field | Description |
|-------|-------------|
| `allowPty` | Allow pseudo-terminal (PTY) allocation in the sandbox (for MacOS) |

## Importing from Claude Code

If you've been using Claude Code and have already built up permission rules, you can import them into fence:

```bash
# Preview import (prints JSON to stdout)
fence import --claude

# Save to the default config path
fence import --claude --save

# Import from a specific file
fence import --claude -f ~/.claude/settings.json --save

# Save to a specific output file
fence import --claude -o ./fence.json

# Import without extending any template (minimal config)
fence import --claude --no-extend --save

# Import and extend a different template
fence import --claude --extend local-dev-server --save
```

### Default Template

By default, imports extend the `code` template which provides sensible defaults:

- Network access for npm, GitHub, LLM providers, etc.
- Filesystem protections for secrets and sensitive paths
- Command restrictions for dangerous operations

Use `--no-extend` if you want a minimal config without these defaults, or `--extend <template>` to choose a different base template.

### Permission Mapping

| Claude Code | Fence |
|-------------|-------|
| `Bash(xyz)` allow | `command.allow: ["xyz"]` |
| `Bash(xyz:*)` deny | `command.deny: ["xyz"]` |
| `Read(path)` deny | `filesystem.denyRead: [path]` |
| `Write(path)` allow | `filesystem.allowWrite: [path]` |
| `Write(path)` deny | `filesystem.denyWrite: [path]` |
| `Edit(path)` | Same as `Write(path)` |
| `ask` rules | Converted to deny (fence doesn't support interactive prompts) |

Global tool permissions (e.g., bare `Read`, `Write`, `Grep`) are skipped since fence uses path/command-based rules.

## See Also

- Config templates: [`docs/templates/`](docs/templates/)
- Workflow guides: [`docs/recipes/`](docs/recipes/)
