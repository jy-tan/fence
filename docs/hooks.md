# Agent Hooks

Hook-based wrapping exists for environments where Fence cannot transparently
enforce argv-aware command policy on every descendant process after an agent is
already running. Instead of trying to catch child execs after the fact, Fence
uses an agent's hook or plugin system to inspect each declared tool call before
the agent runs it.

Prefer [whole-agent wrapping](agents.md) when possible. It is the stronger
isolation model for filesystem and network policy. Hooks are most useful when
you also need multi-token command denies like `git push`, `gh repo create`, or
`npm publish` to apply to tool-issued shell commands on macOS, or on Linux when
`command.runtimeExecPolicy: "argv"` is not enabled.

## Capability Matrix

| Integration | Hook surface | Command policy | Runtime network/filesystem for allowed shell commands | Preflights file/network tool inputs | Main caveat |
|---|---|---|---|---|---|
| Claude Code | `PreToolUse` for `Bash` | Denies blocked commands or rewrites allowed commands to `fence -c ...` | Yes, for hooked `Bash` commands | No | Covers shell tool calls, not native editor or agent file operations |
| Cursor | `preToolUse` for `Shell` | Denies blocked commands or rewrites allowed commands to `fence -c ...` | Yes, for hooked `Shell` commands | No | Covers Cursor shell tool calls, not arbitrary IDE behavior |
| OpenCode | `tool.execute.before` plugin for `bash` | Denies blocked commands or rewrites allowed commands to `fence -c ...` | Yes, for hooked `bash` commands | No | User-typed `!` commands bypass the plugin |
| Hermes Agent | `pre_tool_call` for `terminal`, `write_file`, `patch`, `web_extract` | Denies blocked terminal commands | No, hook mode is intent-only | Yes, for declared write paths and URLs | The hook checks declared tool inputs; wrap Hermes for traffic-time enforcement |
| Windsurf Cascade | `pre_run_command`, `pre_write_code` | Denies blocked terminal commands | No, Windsurf hooks do not support command rewriting | Yes, for declared write paths | The hook can block declared actions but cannot sandbox allowed commands |

The important distinction is whether the agent lets the hook modify the command
before execution. Claude Code, Cursor, and OpenCode support that, so Fence can
turn an allowed shell tool call into `fence -c "..."`. That nested Fence process
is what applies runtime filesystem and network policy to the command.

Some hook systems only let a pre-hook allow or block an action, usually via an
exit code or a block response. Hermes and Windsurf are in this category: Fence
can block denied commands, write paths, or URLs, but it cannot sandbox an
allowed command unless the agent also supports command rewriting or wrapper
execution.

## How It Works

For shell-command rewriting hooks, the Fence helper decides per invocation
whether to:

- **Deny the command** if it violates Fence command policy. The hook returns an
  error and the agent never runs the command.
- **Rewrite the command** to run through `fence -c "..."`, when the integration
  supports command mutation. The shell execution then happens inside the
  sandbox.

Commands that already violate Fence command policy are denied directly at hook
time instead of being rewritten to a nested `fence -c ...` invocation.

If the agent is already running inside Fence, the helper avoids launching a
second nested sandbox and only applies Fence's command policy at hook time.

## Shell Command Rewriting

Claude Code, Cursor, and OpenCode let Fence replace an allowed shell command
with `fence -c "..."`. That means the shell command itself runs inside Fence,
so runtime filesystem and network policy apply to the command after the hook
allows it.

### Claude Code

Claude Code uses `PreToolUse` for `Bash` and calls
`fence --claude-pre-tool-use`:

```bash
fence hooks print --claude
fence hooks install --claude
fence hooks uninstall --claude
```

Default file: `~/.claude/settings.json`.

### Cursor

Cursor uses `preToolUse` for `Shell` and calls
`fence --cursor-pre-tool-use`:

```bash
fence hooks print --cursor
fence hooks install --cursor
fence hooks uninstall --cursor
```

Default file: `~/.cursor/hooks.json`.

Cursor may also run Claude Code hook commands if Claude settings are present.
Fence handles either Cursor or Claude hook payloads.

### OpenCode

OpenCode loads plugins from npm packages listed in its `plugin` array, so the
Fence integration ships as the
[`@use-tusk/opencode-fence`](https://github.com/Use-Tusk/opencode-fence)
plugin. It hooks `tool.execute.before` for the `bash` tool and calls
`fence --opencode-pre-tool-use`:

```bash
fence hooks print --opencode
fence hooks install --opencode
fence hooks uninstall --opencode
```

Default file: `~/.config/opencode/opencode.jsonc` if it exists, otherwise
`~/.config/opencode/opencode.json` (created on first install). Override with
`--file` to target a project-local `opencode.{json,jsonc}`.

`install --opencode` only adds `@use-tusk/opencode-fence` to the `plugin`
array; OpenCode's npm-package plugin loader does not accept options, so
`--settings` and `--template` are not supported with `--opencode`. To pin a
specific config or template, write a local plugin shim under
`~/.config/opencode/plugins/` that constructs `FencePlugin({...})` directly.
See the plugin's
[README](https://github.com/Use-Tusk/opencode-fence#configuration).

> [!NOTE]
> **OpenCode `!`-prefixed commands bypass the plugin.** OpenCode's plugin
> lifecycle currently does not fire `tool.execute.before` for commands the
> user types directly into the TUI with the `!` prefix, so those bypass the
> Fence plugin even when installed. Whole-agent wrapping
> (`fence -t code -- opencode`) still applies its filesystem and network
> policy to those commands; only multi-token command denies are missed for
> the `!` path.

## Intent/Preflight Hooks

Hermes and Windsurf expose hooks for declared tool inputs. Fence can block
commands, write paths, or URLs that violate policy, but allowed actions do not
run inside a nested `fence -c ...` sandbox unless the whole agent is also
wrapped.

### Hermes Agent

Hermes Agent has a YAML-declared shell-hook system (`~/.hermes/config.yaml`)
that pipes JSON to a subprocess on stdin and reads JSON on stdout, so the
Fence integration ships as the `fence` binary itself, no separate package.
It registers `pre_tool_call` hooks for Hermes' `terminal`, `write_file`,
`patch`, and `web_extract` tools and calls `fence --hermes-pre-tool-use`:

```bash
fence hooks print --hermes
fence hooks install --hermes --template hermes
fence hooks install --hermes --settings ./fence.json
fence hooks uninstall --hermes
```

Default file: `~/.hermes/config.yaml`. Override with `--file` to target a
project-local config or alternate profile. The `hermes` template is the
recommended starting point because Hermes may need provider, messaging, cache,
and `~/.hermes/**` write access that plain coding-agent templates do not
include.

Unlike the shell-command integrations above, the Hermes hook surface goes
beyond bash. Each Hermes tool maps to one of Fence's existing config domains:

| Hermes tool | Fence policy domain | Reads |
|---|---|---|
| `terminal` | `command.deny` / `command.allow` | `tool_input.command` |
| `write_file` | `filesystem.allowWrite` / `denyWrite` and dangerous-file protection | `tool_input.path` |
| `patch` | `filesystem.allowWrite` / `denyWrite` and dangerous-file protection | `tool_input.path` |
| `web_extract` | `network.allowedDomains` / `deniedDomains` | `tool_input.url` |

Tools not in this table, including channel sends, MCP calls, subagent spawning,
memory, todos, and image or TTS generation, are passed through unmodified at the
hook layer. They do not fit Fence's filesystem, network, or command vocabulary
today. Wrap mode (`fence -t hermes -- hermes`) does cover their network traffic
at the proxy layer; the two modes compose.

> [!NOTE]
> **Hermes hook mode is intent-only, not traffic-enforced.** Fence sees what
> the agent declared it wants to do and decides against your config. It does
> not sit in the syscall or HTTP path. If a tool's actual implementation does
> something different from its declared arguments, the hook cannot catch that.
> For traffic-time enforcement, also wrap Hermes with `fence -- hermes`.

### Windsurf Cascade

Windsurf Cascade runs shell commands from `hooks.json` and blocks pre-hooks
when the hook exits with code `2`. Fence registers `pre_run_command` and
`pre_write_code` hooks and calls `fence --windsurf-hook`:

```bash
fence hooks print --windsurf
fence hooks install --windsurf
fence hooks install --windsurf --settings ./fence.json
fence hooks uninstall --windsurf
```

Default file: `~/.codeium/windsurf/hooks.json`. Override with `--file` to
target a workspace-level `.windsurf/hooks.json` or the JetBrains plugin's
`~/.codeium/hooks.json`.

Windsurf hook support maps supported events to Fence policy domains:

| Windsurf event | Fence policy domain | Reads |
|---|---|---|
| `pre_run_command` | `command.deny` / `command.allow` | `tool_info.command_line` |
| `pre_write_code` | `filesystem.allowWrite` / `denyWrite` and dangerous-file protection | `tool_info.file_path` |

> [!NOTE]
> **Windsurf hook mode can block, but not rewrite.** Windsurf's documented
> pre-hook API blocks by exit code and does not expose a response shape for
> replacing `tool_info.command_line`. That means allowed terminal commands run
> as normal Windsurf commands, not inside `fence -c ...`. Use this integration
> for command and write-path preflight checks, not traffic-time sandboxing.

## Pinning a Specific Policy

By default, hook helpers resolve Fence's config at runtime the same way the CLI
does. To pin a hook to a specific file or template for `--claude`, `--cursor`,
`--hermes`, or `--windsurf`:

```bash
fence hooks install --cursor --settings /path/to/fence.json
fence hooks install --cursor --template code
fence hooks install --hermes --template hermes
fence hooks install --windsurf --settings /path/to/fence.json
```

For `--opencode`, OpenCode's npm-package plugin loader does not accept options
through the `plugin` array. To pin a specific config or template, write a local
plugin shim under `~/.config/opencode/plugins/` that constructs the plugin
yourself:

```ts
// ~/.config/opencode/plugins/fence.ts
import { createFencePlugin } from "@use-tusk/opencode-fence/factory";

export const Fence = createFencePlugin({
  settingsPath: "/path/to/fence.json",
  // or template: "code",
});
```

If you use this route, remove `@use-tusk/opencode-fence` from
`opencode.json`'s `plugin` array to avoid registering the plugin twice.

## Other Agents

If your coding agent has a hook or plugin system you'd like Fence to support,
please open an issue or pull request.
