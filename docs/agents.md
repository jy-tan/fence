# Using Fence with AI Agents

Many popular coding agents already include sandboxing. Fence can still be useful when you want a tool-agnostic policy layer that works the same way across:

- local developer machines
- CI jobs
- custom/internal agents or automation scripts
- different agent products (as defense-in-depth)

## Recommended approach

Treat an agent as "semi-trusted automation":

- Restrict writes to the workspace (and maybe `/tmp`)
- Allowlist only the network destinations you actually need
- Use `-m` (monitor mode) to audit blocked attempts and tighten policy

Fence can also reduce the risk of running agents with fewer interactive permission prompts (e.g. "skip permissions"), as long as your Fence config tightly scopes writes and outbound destinations. It's defense-in-depth, not a substitute for the agent's own safeguards.

> [!NOTE]
> **Command policy and child processes.** When you wrap a long-running agent (`fence -t code -- claude`), Fence's `command.deny` rules catch the literal command Fence is told to run, plus — at runtime — single-token denies (e.g. `sudo`) on any descendant process. Multi-token rules like `gh repo create`, `git push`, or `npm publish` are only enforced at runtime when:
>
> - you're on Linux with `command.runtimeExecPolicy: "argv"` (opt-in), or
> - you've installed an agent hook (see [Hooks](#hooks)) that re-pipes each shell tool call through `fence -c`.
>
> On macOS in the default mode, multi-token denies apply to commands you type directly to `fence` but not to commands an agent spawns as a child process. This is a property of macOS Seatbelt's exec model, not a config bug - see [Enforcement Across Child Processes](configuration.md#enforcement-across-child-processes) for the full matrix and recommended workarounds.

## Example: API-only agent

```json
{
  "network": {
    "allowedDomains": ["api.openai.com", "api.anthropic.com"]
  },
  "filesystem": {
    "allowWrite": ["."]
  }
}
```

Run:

```bash
fence --settings ./fence.json <agent-command>
```

## Popular CLI coding agents

We provide these templates for guardrailing CLI coding agents:

- [`code`](/internal/templates/code.json) - Strict deny-by-default network filtering via proxy. Works with agents that respect `HTTP_PROXY`. Blocks cloud metadata APIs, protects secrets, restricts dangerous commands.
- [`code-relaxed`](/internal/templates/code-relaxed.json) - Allows direct network connections for agents that ignore `HTTP_PROXY`. Same filesystem/command protections as `code`, but `deniedDomains` only enforced for proxy-respecting apps.

You can use it like `fence -t code -- claude`.

| Agent | Works with template | Notes |
|-------|--------| ----- |
| Claude Code | `code` | - |
| Codex | `code` | - |
| Gemini CLI | `code` | - |
| OpenCode | `code` | - |
| Amp | `code` | - |
| Droid | `code` | - |
| Pi | `code` | - |
| Crush | `code` | - |
| GitHub Copilot | `code` | - |
| Cursor Agent | `code-relaxed` | Node.js/undici doesn't respect HTTP_PROXY |

These configs can drift as agents evolve. If you encounter false positives on blocked requests or want a CLI agent listed, please open an issue or PR.

Note: On Linux, if OpenCode or Gemini CLI is installed via Linuxbrew, Landlock can block the Linuxbrew node binary unless you widen filesystem access. Installing OpenCode/Gemini under your home directory (e.g., via nvm or npm prefix) avoids this without relaxing the template.

## Hooks

Hook-based wrapping uses the agent/editor's own hook system to rewrite shell tool invocations up front so they run through `fence -c`, instead of trying to catch child execs at the OS exec boundary. It is the recommended way to enforce **multi-token command policy** (e.g. `gh repo create`, `git push`) inside agents on macOS, and on Linux when `runtimeExecPolicy: "argv"` is not enabled — see [Enforcement Across Child Processes](configuration.md#enforcement-across-child-processes) for why this gap exists.

Prefer whole-agent wrapping (`fence -- <agent>`) when possible — it is the stronger isolation model for filesystem and network policy. Hooks are the right addition when you want multi-token command denies to apply to the agent's tool-issued shell calls; the two approaches compose.

`print` emits the hook snippet, and `install`/`uninstall` manage the default
settings file for that integration.

If you want hook-invoked shell commands to use a specific Fence policy instead
of resolving config at runtime, generate or install the hook with
`--settings /path/to/fence.json` or `--template code`. Supported on
`--claude` and `--cursor`; the `--opencode` install path uses a different
mechanism (see below).

Commands that already violate Fence command policy are denied directly at hook
time instead of being rewritten to a nested `fence -c ...` invocation.

If the agent is already running inside Fence, the helper avoids launching a
second nested sandbox and only applies Fence's command policy at hook time.

### Claude Code

Claude Code uses `PreToolUse` for `Bash` and calls
`fence --claude-pre-tool-use`:

```bash
fence hooks print --claude
fence hooks install --claude
fence hooks uninstall --claude
```

Default file: `~/.claude/settings.json`

### Cursor

Cursor uses `preToolUse` for `Shell` and calls
`fence --cursor-pre-tool-use`:

```bash
fence hooks print --cursor
fence hooks install --cursor
fence hooks uninstall --cursor
```

Default file: `~/.cursor/hooks.json`

Cursor may also run Claude Code hook commands if Claude settings are present.
Fence handles that too by accepting either Cursor or Claude hook payloads.

### OpenCode

OpenCode loads plugins from npm packages listed in its `plugin` array, so the
Fence integration ships as the [`@use-tusk/opencode-fence`](https://github.com/Use-Tusk/opencode-fence)
plugin. It hooks `tool.execute.before` for the `bash` tool and calls
`fence --opencode-pre-tool-use`:

```bash
fence hooks print --opencode
fence hooks install --opencode
fence hooks uninstall --opencode
```

Default file: `~/.config/opencode/opencode.json`

`install --opencode` only adds `@use-tusk/opencode-fence` to the `plugin`
array; OpenCode's npm-package plugin loader does not accept options, so
`--settings` and `--template` are not supported with `--opencode`. To pin a
specific config or template, write a local plugin shim under
`~/.config/opencode/plugins/` that constructs `FencePlugin({...})` directly -
see the plugin's [README](https://github.com/Use-Tusk/opencode-fence#configuration).

> [!NOTE]
> **OpenCode `!`-prefixed commands bypass the plugin.** OpenCode's plugin
> lifecycle currently does not fire `tool.execute.before` for commands the
> user types directly into the TUI with the `!` prefix, so those bypass the
> Fence plugin even when installed. Whole-agent wrapping
> (`fence -t code -- opencode`) still applies its filesystem and network
> policy to those commands; only multi-token command denies are missed for
> the `!` path.

If your coding agent has a hook or plugin system you'd like Fence to support, feel free to open an issue or pull request.

## Protecting your environment

Fence includes additional "dangerous file protection" (writes blocked regardless of config) to reduce persistence and environment-tampering vectors like:

- `.git/hooks/*`
- shell startup files (`.zshrc`, `.bashrc`, etc.)
- some editor/tool config directories

See [`ARCHITECTURE.md`](/ARCHITECTURE.md) for the full list and rationale.
