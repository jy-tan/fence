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

Default file: `~/.config/opencode/opencode.jsonc` if it exists, otherwise
`~/.config/opencode/opencode.json` (created on first install). Override with
`--file` to target a project-local `opencode.{json,jsonc}`.

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

### Hermes Agent

Hermes Agent has a YAML-declared shell-hook system (`~/.hermes/config.yaml`)
that pipes JSON to a subprocess on stdin and reads JSON on stdout, so the
Fence integration ships as the `fence` binary itself, no separate package.
It registers `pre_tool_call` hooks for Hermes' `terminal`, `write_file`,
`patch`, and `web_extract` tools and calls `fence --hermes-pre-tool-use`:

```bash
fence hooks print --hermes
fence hooks install --hermes --template hermes       # recommended starting point
fence hooks install --hermes --settings ./fence.json # pin a project config
fence hooks uninstall --hermes
```

The `hermes` template extends `code` with messaging-platform domains
(Telegram, Discord, Slack, Feishu, ...), Hermes-specific LLM providers,
and writable `~/.hermes/**`. Use it as a starting point and override
locally as needed; refine over time as Hermes' tool surface evolves.

Default file: `~/.hermes/config.yaml`. Override with `--file` to target a
project-local config or alternate profile.

Unlike the coding-agent integrations above, the Hermes hook surface goes
**beyond bash**. Each Hermes tool maps to one of Fence's existing config
domains:

| Hermes tool | Fence policy domain | Reads |
|-------------|---------------------|-------|
| `terminal` | `command.deny` / `command.allow` | `tool_input.command` |
| `write_file` | `filesystem.allowWrite` / `denyWrite` (+ dangerous-files protection) | `tool_input.path` |
| `patch` | `filesystem.allowWrite` / `denyWrite` (+ dangerous-files protection) | `tool_input.path` |
| `web_extract` | `network.allowedDomains` / `deniedDomains` | `tool_input.url` |

Tools not in this table — including channel sends (`send_message`,
`discord_tool`, `feishu_doc_tool`, ...), MCP calls (`mcp_tool`),
subagent spawning (`delegate_tool`), memory, todos, and image/TTS
generation — are passed through unmodified at the hook layer. They
don't fit Fence's filesystem/network/command vocabulary today.
Wrap mode (`fence -t hermes -- hermes`) does cover their network
traffic at the proxy layer; the two modes compose.

> [!NOTE]
> **Hermes hook mode is intent-only, not traffic-enforced.** Fence sees what
> the agent declared it wants to do (which path, which URL) and decides
> against your config; it doesn't sit in the syscall or HTTP path. If a
> tool's actual implementation does something different from its declared
> arguments (`web_extract` follows a redirect to a blocked host, for
> example), the hook can't catch that. For traffic-time enforcement, also
> wrap the gateway with `fence -- hermes` — the two compose.

> [!NOTE]
> **Consent / non-TTY runs.** Hermes prompts once per `(event, command)`
> pair before running it. For the gateway, cron, or CI, run with
> `HERMES_ACCEPT_HOOKS=1`, set `hooks_auto_accept: true` in
> `~/.hermes/config.yaml`, or run `hermes` once interactively to record
> the approval. See the Hermes
> [Shell Hooks docs](https://docs.hermes-agent.com/docs/user-guide/features/hooks)
> for the full consent model.

### OpenClaw

OpenClaw uses an imperative plugin manager rather than a declarative
config-array, so the Fence integration ships as the
[`@use-tusk/openclaw-fence`](https://github.com/Use-Tusk/openclaw-fence)
npm package and is installed via OpenClaw's own command:

```bash
openclaw plugins install @use-tusk/openclaw-fence
openclaw gateway restart
```

`fence hooks install --openclaw` is **not** supported — Fence editing the
config file would only be half the work. To see the install one-liner
plus optional plugin-options hints, run:

```bash
fence hooks print --openclaw
fence hooks print --openclaw --template openclaw   # surface the template hint
```

The plugin registers a `before_tool_call` handler and forwards a curated
set of OpenClaw tool calls through `fence --openclaw-pre-tool-use`:

| OpenClaw tool | Fence policy domain | Reads |
|---|---|---|
| `exec` (alias `bash`) | `command.deny` / `command.allow` | `params.command` |
| `write`, `edit`, `apply_patch` | `filesystem.allowWrite` / `denyWrite` (+ dangerous-files protection) | `params.path` |
| `web_fetch` | `network.allowedDomains` / `deniedDomains` | `params.url` |

Tools not in this table — channel sends, MCP, subagent spawning, image/media
generation, sessions, gateway, and so on — are passed through unmodified at
the hook layer. Wrap mode (`fence -t openclaw -- openclaw gateway run`)
covers their network traffic at the proxy layer.

#### Recommended config

The bundled `openclaw` template extends `code` with channel/provider
domains and writable `~/.openclaw/**`. Pin it via the plugin's options
in your OpenClaw config:

```jsonc
{
  "plugins": {
    "entries": {
      "openclaw-fence": {
        "enabled": true,
        "config": {
          "template": "openclaw"
        }
      }
    }
  }
}
```

> [!NOTE]
> **Hook mode is intent-only, not traffic-enforced.** Fence sees what
> the agent declared it wants to do (which command, path, or URL) and
> decides against your config; it doesn't sit in the syscall or HTTP
> path. Run `fence -t openclaw -- openclaw gateway run` for traffic-time
> enforcement; the two compose.

If your coding agent has a hook or plugin system you'd like Fence to support, feel free to open an issue or pull request.

## Protecting your environment

Fence includes additional "dangerous file protection" (writes blocked regardless of config) to reduce persistence and environment-tampering vectors like:

- `.git/hooks/*`
- shell startup files (`.zshrc`, `.bashrc`, etc.)
- some editor/tool config directories

See [`ARCHITECTURE.md`](/ARCHITECTURE.md) for the full list and rationale.
