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

Hook-based wrapping exists for environments where Fence cannot transparently enforce
child-process, argv-aware exec policy on every descendant command after the
agent is already running, especially outside Linux. Instead of trying to catch
child execs after the fact, Fence can use the agent/editor hook system to
rewrite shell tool invocations up front so they run through Fence.

Prefer whole-agent wrapping when possible, since it is the stronger isolation
model. This hook-based approach is the fallback when you need the agent itself
to stay outside Fence but still want shell commands sandboxed.

`print` emits the hook snippet, and `install`/`uninstall` manage the default
settings file for that integration.

If you want hook-invoked shell commands to use a specific Fence policy instead
of resolving config at runtime, generate or install the hook with
`--settings /path/to/fence.json` or `--template code`.

Commands that already violate Fence command policy are denied directly at hook
time instead of being rewritten to a nested `fence -c ...` invocation.

If the agent is already running inside Fence, the helper avoids launching a
second nested sandbox and only applies Fence's command policy at hook time.

Claude Code uses `PreToolUse` for `Bash` and calls
`fence --claude-pre-tool-use`:

```bash
fence hooks print --claude
fence hooks install --claude
fence hooks uninstall --claude
```

Default file: `~/.claude/settings.json`

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

If your coding agent has a hook or plugin system you'd like Fence to support, feel free to open an issue or pull request.

## Protecting your environment

Fence includes additional "dangerous file protection" (writes blocked regardless of config) to reduce persistence and environment-tampering vectors like:

- `.git/hooks/*`
- shell startup files (`.zshrc`, `.bashrc`, etc.)
- some editor/tool config directories

See [`ARCHITECTURE.md`](/ARCHITECTURE.md) for the full list and rationale.
