# Configuration

Fence reads settings from:

- The nearest `fence.jsonc` or `fence.json` in the current directory or any parent directory
- Otherwise, Linux: `$XDG_CONFIG_HOME/fence/fence.{jsonc,json}` (typically `~/.config/fence/fence.json`)
- Otherwise, macOS: `~/.config/fence/fence.{jsonc,json}`
- Legacy paths still supported: macOS `~/Library/Application Support/fence/fence.{jsonc,json}` and `~/.fence.{jsonc,json}`
- Custom path: pass `--settings ./fence.json` (or `./fence.jsonc`)

Config files support JSONC (comments and trailing commas) regardless of
extension. When both `fence.jsonc` and `fence.json` exist in the same
directory, the `.jsonc` file wins.

Example config:

```json
{
  "$schema": "https://raw.githubusercontent.com/fencesandbox/fence/main/docs/schema/fence.schema.json",
  "network": {
    "allowedDomains": ["github.com", "*.npmjs.org", "registry.yarnpkg.com"],
    "deniedDomains": ["evil.com"]
  },
  "filesystem": {
    "denyRead": ["/etc/passwd"],
    "allowWrite": [".", "/tmp"],
    "denyWrite": [".git/hooks"]
  },
  "devices": {
    "mode": "minimal",
    "allow": ["/dev/dri"]
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

### Extending your default user config

Use the reserved `@base` keyword to layer project-specific overrides on top of the same user config file that Fence would normally load by default:

```json
{
  "extends": "@base",
  "network": {
    "allowedDomains": ["private-registry.company.com"]
  },
  "filesystem": {
    "allowWrite": ["."]
  }
}
```

This is useful for checked-in repo configs that should inherit each developer's normal Fence setup and then add project-specific rules.

If the user does not have a default Fence config file yet, `@base` falls back to Fence's built-in default config before applying the override file.

When Fence auto-discovers a project `fence.json`, `@base` is the recommended way to keep inheriting the user's normal config while adding project-specific overrides.

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

- `@base` is a reserved keyword for the user's default Fence config
- A value containing `/` or `\`, or starting with `.`, is treated as a file path
- Any other value is treated as a template name

### Merge behavior

- Slice fields (domains, paths, commands) are appended and deduplicated
- Boolean fields use OR logic (true if either base or override enables it)
- Optional boolean fields (`useDefaults`) use override-wins semantics: the child value wins when set, otherwise the parent value is inherited
- Enum/string fields use override-wins semantics when the override is non-empty (for example, `devices.mode`)
- Integer fields (ports) use override-wins semantics (0 keeps base value)

### Chaining

Extends chains are supported—a file can extend `@base`, a template, or another file, and another file can extend that result. Circular extends are detected and rejected. Maximum chain depth is 10.

### Inspecting the active config

Use `fence config show` to inspect the exact config Fence would apply without running a command:

```bash
fence config show
fence config show --settings ./custom.json
fence config show --template code
```

`fence config show` prints the config resolution chain to `stderr` and the fully resolved config to `stdout` as plain JSON. That means you can pipe the JSON to tools like `jq` without losing the human-readable chain:

```bash
fence config show | jq '.network'
```

See [templates.md](templates.md) for available templates.

## Network Configuration

| Field | Description |
|-------|-------------|
| `allowedDomains` | List of allowed domains. Supports wildcards like `*.example.com` |
| `deniedDomains` | List of denied domains (checked before allowed) |
| `allowUnixSockets` | List of allowed Unix socket paths (macOS) |
| `allowAllUnixSockets` | Allow all Unix sockets |
| `allowLocalBinding` | Allow binding to local ports |
| `allowLocalOutbound` | Allow outbound connections to localhost, e.g., local DBs (defaults to `allowLocalBinding` if not set). **Linux** also requires `allowLocalOutboundPorts` to list which host loopback ports to bridge. |
| `allowLocalOutboundPorts` | **Linux only.** TCP ports on the host's `127.0.0.1` that the sandbox may reach when `allowLocalOutbound` is true (e.g. `[5432, 6379]`). Each listed port is forwarded from sandbox loopback to host loopback via an internal socat bridge. Ignored on macOS, which allows any localhost port when `allowLocalOutbound` is true. |
| `httpProxyPort` | Fixed port for HTTP proxy (default: random available port) |
| `socksProxyPort` | Fixed port for SOCKS5 proxy (default: random available port) |
| `upstreamProxy` | Optional upstream HTTP proxy URL (e.g. `http://127.0.0.1:8080`). Used with `defaultAction: "proxy"` to forward grey-zone traffic for inspection. Only `http://` scheme is supported. See [Upstream Proxy / mitmproxy](#upstream-proxy--mitmproxy). |
| `defaultAction` | What to do with traffic that matches neither `allowedDomains` nor `deniedDomains`. `"deny"` (default): block it. `"proxy"`: forward to `upstreamProxy` (requires `upstreamProxy`). |

### Upstream Proxy / mitmproxy

Setting `network.upstreamProxy` together with `defaultAction: "proxy"` connects fence's internal HTTP proxy to an external upstream HTTP proxy for grey-zone traffic. This is designed for interactive inspection workflows such as [mitmproxy](https://mitmproxy.org/).

**Routing logic (in priority order):**

| Traffic | Result |
|---------|--------|
| Matches `deniedDomains` | Hard 403 — never forwarded upstream |
| Matches `allowedDomains` | Connected directly to target |
| Everything else (grey zone) | `defaultAction: "proxy"` → forwarded to `upstreamProxy`; `"deny"` (default) → 403 |

**Example — fence + mitmproxy:**

```json
{
  "network": {
    "allowedDomains": ["api.openai.com", "*.npmjs.org"],
    "deniedDomains": ["169.254.169.254"],
    "defaultAction": "proxy",
    "upstreamProxy": "http://127.0.0.1:8080"
  }
}
```

Start mitmproxy externally before running fence:

```bash
mitmproxy --listen-port 8080
```

One mitmproxy instance can serve multiple fence instances simultaneously because fence only connects to it for grey-zone traffic.

**Key properties:**

- `deniedDomains` remains a hard block — mitmproxy never sees those requests.
- `allowedDomains` traffic bypasses mitmproxy entirely (direct connection).
- Only `http://` upstream proxy URLs are supported (`https://` upstream proxies are not yet supported).
- If the upstream proxy denies a connection, fence returns `403` to the client.
- If the upstream proxy is unreachable, fence returns `502`.
- SOCKS5 proxy traffic (via `ALL_PROXY`) is not forwarded upstream in this release; only HTTP/HTTPS clients using `HTTP_PROXY`/`HTTPS_PROXY` are affected.

> [!NOTE]
> Only `http://` upstream proxy URLs are supported for `upstreamProxy`. `https://` upstream proxies and SOCKS5 upstream chaining are not yet supported.

### Wildcard Domain Access

Setting `allowedDomains: ["*"]` enables **relaxed network mode**:

- Direct network connections are allowed (sandbox doesn't block outbound)
- Proxy still runs for apps that respect `HTTP_PROXY`
- `deniedDomains` is only enforced for apps using the proxy

> [!WARNING]
> **Security tradeoff**: Apps that ignore `HTTP_PROXY` will bypass `deniedDomains` filtering entirely.

Use this when you need to support apps that don't respect proxy environment variables.

## macOS Configuration

These settings apply only to the macOS Seatbelt backend and are ignored on
other platforms.

| Field | Description |
|-------|-------------|
| `mach.lookup` | Additional Mach/XPC services to allow for `mach-lookup`. Supports exact service names, trailing-wildcard prefixes like `org.chromium.*`, and `*` to allow all lookups. |
| `mach.register` | Additional Mach/XPC services to allow for `mach-register`. Supports exact service names, trailing-wildcard prefixes like `org.chromium.*`, and `*` to allow all registrations. |

Example:

```json
{
  "macos": {
    "mach": {
      "lookup": [
        "com.apple.CARenderServer",
        "com.apple.windowserver.active",
        "org.chromium.*"
      ],
      "register": [
        "org.chromium.Chromium.MachPortRendezvousServer"
      ]
    }
  }
}
```

Prefer exact service names when possible. Use trailing wildcards only when the
service name is dynamic, and reserve `["*"]` for compatibility debugging or as
a last resort when you intentionally want broad Mach access.

If you're unsure which services a tool needs, run with `-m` to surface blocked
`mach-lookup` / `mach-register` attempts.

## Filesystem Configuration

| Field | Description |
|-------|-------------|
| `wslInterop` | WSL interop support. `null` (default) = auto-detect, `true` = force on, `false` = force off. When active, auto-allows execute on `/init`. |
| `allowRead` | Paths to allow reading and directory listing (Landlock: `READ_FILE + READ_DIR + EXECUTE`) |
| `allowExecute` | Paths to allow executing only (Landlock: `READ_FILE + EXECUTE`, no directory listing) |
| `defaultDenyRead` | If true, deny all filesystem reads by default. Only paths listed in `allowRead` (and essential system paths) remain readable. Use for strict read isolation. |
| `strictDenyRead` | If true, suppress the default readable system paths that are normally added when `defaultDenyRead` is enabled. Only paths in `allowRead` will be readable. Implies `defaultDenyRead`. |
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

System paths like `/usr`, `/lib`, `/bin`, `/etc` are always readable — you don't need to add them. When `defaultDenyRead` is enabled, these system paths are still added automatically. To suppress them entirely, enable `strictDenyRead` — only paths in `allowRead` will be readable.

Device exposure under `/dev` is configured separately via [`devices`](#device-configuration), not via `filesystem.allowRead`/`allowWrite`.

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

## Device Configuration

> [!NOTE]
> Device configuration currently applies to Linux sandboxes. macOS does not use these settings.

| Field | Description |
|-------|-------------|
| `mode` | How `/dev` is set up inside the sandbox: `auto`, `minimal`, or `host`. If omitted, fence behaves as if `auto` was set. |
| `allow` | Extra `/dev/...` paths from the outer environment to pass through when using a minimal `/dev` |

### Device Modes

#### `minimal`

Creates a fresh minimal `/dev` inside the sandbox using `bwrap --dev /dev`.

This is the most predictable and least-privileged mode. Fence starts from bubblewrap's synthetic `/dev` and preserves the standard core device nodes needed by common runtimes, including `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, `/dev/tty`, and `/dev/ptmx`. Bubblewrap's minimal `/dev` also provides essentials such as `/dev/shm` and `devpts`.

Use this when you want sandbox behavior to be consistent across hosts and containers.

#### `host`

Bind-mounts the outer environment's `/dev` into the sandbox using `bwrap --dev-bind /dev /dev`.

Use this only when you intentionally need the outer environment's full device tree. In this mode, `devices.allow` is redundant because the entire outer `/dev` is already available inside the sandbox.

#### `auto`

Picks the safest compatible mode automatically.

If `devices.mode` is omitted, fence behaves the same as `auto`.

Current behavior:

- Prefers `minimal` inside containers
- Prefers `host` only for the older setuid-`bwrap`, non-root compatibility case
- Uses `minimal` otherwise

If you need deterministic behavior, prefer setting `mode` explicitly instead of relying on `auto`.

### Device Passthroughs

When `mode` is `minimal`, you can opt specific outer `/dev` paths back in with `allow`:

```json
{
  "devices": {
    "mode": "minimal",
    "allow": ["/dev/dri", "/dev/fuse"]
  }
}
```

Rules:

- Paths must be under `/dev/`
- `"/dev"` itself is not allowed in `allow`; use `mode: "host"` if you want the full outer device tree
- `allow` is only useful with `minimal`; in `host` mode the entire outer `/dev` is already available
- You do not need to list standard core devices like `/dev/null` or `/dev/urandom`; they are already available in `minimal`
- Missing device paths are skipped at runtime

### Choosing a Mode

- Use `minimal` for most sandboxing and containerized workflows
- Use `minimal` plus `allow` for targeted hardware passthrough like GPUs or FUSE
- Use `host` only when you explicitly need the full outer `/dev`

## Command Configuration

Block specific commands from being executed, even within command chains.

| Field | Description |
|-------|-------------|
| `deny` | List of command prefixes to block (e.g., `["git push", "rm -rf"]`) |
| `allow` | List of command prefixes to allow, overriding `deny` |
| `useDefaults` | Enable default deny list of dangerous system commands (default: `true`) |
| `runtimeExecPolicy` | Runtime child-process exec enforcement mode: `path` (default; single-token rules only) or Linux-only `argv` (multi-token argv-aware). See [Enforcement Across Child Processes](#enforcement-across-child-processes). |
| `acceptSharedBinaryCannotRuntimeDeny` | List of command names that cannot be isolated at runtime on this system (see below) |

Example:

```json
{
  "command": {
    "deny": ["git push", "npm publish"],
    "allow": ["git push origin docs"],
    "runtimeExecPolicy": "argv"
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

Fence also enforces a runtime child-process exec policy that applies to commands launched by descendants of the wrapped process (for example, an agent like `claude`, `codex`, or `opencode`). What gets enforced at runtime depends on platform and `runtimeExecPolicy` — see [Enforcement Across Child Processes](#enforcement-across-child-processes) below for the full matrix and the implications for macOS users.

Matching notes:

- Rules are still command prefixes, not fully order-insensitive command semantics.
- Tokens ending in `=` act like presence checks later in the argv, so `dd if=` also matches `dd of=/tmp/out if=/dev/zero`.
- Leading global flags before the first subcommand token are skipped, so `docker run --privileged` also matches `docker --debug run --privileged`.
- Other tokens stay positional, so `docker run --privileged` does not automatically match `docker run --name test --privileged`.

### Enforcement Across Child Processes

Fence's command policy is enforced at two distinct points:

- **Preflight** runs once, on the literal command Fence is told to execute (`fence -c "..."` or the trailing argv after `--`). It checks every `deny` rule, single- or multi-token, against that string and any nested `bash -c` payloads.
- **Runtime exec** is what catches commands launched *after* preflight, by descendants of the wrapped process. This is the case that matters when you wrap a long-running agent: `fence -t code -- claude` preflights `claude` once, and from that point on every shell command the agent spawns is a child process Fence sees only at the OS exec boundary.

What runtime exec actually enforces depends on platform and `runtimeExecPolicy`:

| Rule shape | Preflight | Runtime: Linux `path` (default) | Runtime: Linux `argv` | Runtime: macOS |
|---|---|---|---|---|
| Single-token (`sudo`, `python3`) | ✓ | ✓ | ✓ | ✓ |
| Multi-token (`gh repo create`, `git push`, `npm publish`) | ✓ | — | ✓ | — |

Why the asymmetry: `path` mode enforces denies by masking the resolved executable path at the kernel exec boundary (Linux Landlock / macOS Seatbelt `process-exec`). It can block whole binaries by name but cannot inspect argv. `argv` mode uses Linux seccomp user notification to inspect each `execve`/`execveat`'s actual argument vector and apply prefix rules to it. macOS has no equivalent unprivileged primitive - argv-aware exec mediation there would require an EndpointSecurity system extension, which is out of scope for Fence.

Concretely, this means: with the default `code` template on macOS (or Linux in `path` mode), denies like `gh repo create` and `git push` apply to commands you type directly to `fence`, but **not** to the same commands invoked by an agent you wrapped. This is the same model whether the agent is OpenCode, Claude Code, Codex, or any other process Fence is wrapping as a parent.

To close this gap on a given platform, in order of preference:

1. **Linux**: set `command.runtimeExecPolicy: "argv"`. Multi-token denies are then enforced against every descendant exec.
2. **Use agent hooks** (cross-platform): for agents that expose a pre-tool-use hook (Claude Code, Cursor, etc.), `fence hooks install --claude` / `--cursor` reroutes each tool-issued shell call back through `fence -c`, which re-triggers preflight on the actual command string. See [Agent Hooks](hooks.md).
3. **macOS, no agent hook available**: deny the whole executable as a single-token rule (e.g. add `gh` to `command.deny`) when you don't need any subcommand of it. This is blunt but reliable at runtime.

Filesystem isolation, network egress allowlisting, and denied-credential rules apply to every descendant on every platform regardless of `runtimeExecPolicy`. This section is specifically about command-policy enforcement.

### Shared and Multicall Binaries

Some systems use multicall binaries: a single executable file that implements many commands via hardlinks or symlinks. Examples include busybox (`ls`, `cat`, `head`, `tail`, and hundreds more sharing one binary) and some coreutils builds.

When fence tries to block a single-token rule at runtime, it resolves the path and denies it. If the target binary also implements critical shell commands (`ls`, `cat`, `head`, `tail`, `env`, `echo`, and similar), masking it will also block those commands as collateral damage. Fence detects this automatically by probing the denied executable name, critical command names, and other relevant aliases across the search path using inode/device identity. It still blocks the binary anyway (the sandbox is never silently weaker than configured), and emits an actionable warning:

```text
runtime exec deny warning for /usr/bin/busybox (requested: dd): shared binary also implements
critical commands [cat head tail +3 more detected aliases, use --debug for expanded details], which will be
collaterally blocked. To skip runtime blocking of "dd" and silence this warning, add it to
"acceptSharedBinaryCannotRuntimeDeny" in your command config.
```

Use `--debug` to expand the truncated list: critical commands appear first, followed by other detected relevant aliases sharing the same binary.

If the command genuinely cannot be isolated on this system and you accept that it will only be blocked at preflight, add it to `acceptSharedBinaryCannotRuntimeDeny`:

```json
{
  "command": {
    "deny": ["dd"],
    "acceptSharedBinaryCannotRuntimeDeny": ["dd"]
  }
}
```

This skips the runtime block silently and records the explicit decision in the config for future auditors.

Blocking a shared binary is **not** skipped when the collateral names are themselves plausible block targets (e.g., blocking both `python` and `python3` when they share a binary is fine — they are all variants of the same thing).

Current runtime-exec limitations:

- In `path` mode, multi-token rules (for example, `git push`, `dd if=`, `docker run --privileged`) are preflight-only for child processes - see [Enforcement Across Child Processes](#enforcement-across-child-processes) for the cross-platform matrix and recommended workarounds.
- In `path` mode, aliases are enforced only when they resolve to a denied executable path; for reliable blocking, deny the real executable name/path (for example, `python3`), not only an alias name.
- In `path` mode, renamed/copied binaries at new paths may bypass unless those paths are also denied.
- In `argv` mode, Fence fails closed if it cannot safely reconstruct the exec request or if seccomp user notification is unavailable.

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
| `allowPty` | Enable interactive PTY behavior. On macOS this allows PTY access in sandbox policy; on Linux this enables a PTY relay mode for interactive TUIs/editors. |
| `forceNewSession` | Linux only. Force `bwrap --new-session` even for interactive PTY sessions. Leave unset to use Fence's default Linux PTY session policy. |

### `allowPty` notes (Linux)

- Use `allowPty: true` for interactive terminal apps (TUIs/editors) that need proper resize redraw behavior.
- PTY relay is only used when stdin/stdout are both terminals (non-interactive pipes keep the normal stdio behavior).
- By default, Linux interactive PTY sessions skip `bwrap --new-session` so shells keep normal job control.
- If you need the stricter Bubblewrap session split, set `forceNewSession: true` or pass `--force-new-session`.
- Resize handling relays `SIGWINCH` to the PTY foreground process group so terminal apps can redraw after window size changes.

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
