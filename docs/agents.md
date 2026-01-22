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

We provide these template for guardrailing CLI coding agents:

- [`code`](/internal/templates/code.json) - Strict deny-by-default network filtering via proxy. Works with agents that respect `HTTP_PROXY`. Blocks cloud metadata APIs, protects secrets, restricts dangerous commands.
- [`code-relaxed`](/internal/templates/code-relaxed.json) - Allows direct network connections for agents that ignore `HTTP_PROXY`. Same filesystem/command protections as `code`, but `deniedDomains` only enforced for proxy-respecting apps.

You can use it like `fence -t code -- claude`.

| Agent | Works with template | Notes |
|-------|--------| ----- |
| Claude Code | `code` | - |
| Codex | `code` | - |
| Cursor Agent | `code-relaxed` | Node.js/undici doesn't respect HTTP_PROXY |
| Gemini CLI | `code` | - |
| OpenCode | `code` | - |

These configs can drift as agents evolve. If you encounter false positives on blocked requests or want a CLI agent listed, please open an issue or PR.

Note: On Linux, if OpenCode or Gemini CLI is installed via Linuxbrew, Landlock can block the Linuxbrew node binary unless you widen filesystem access. Installing OpenCode/Gemini under your home directory (e.g., via nvm or npm prefix) avoids this without relaxing the template.

## Protecting your environment

Fence includes additional "dangerous file protection" (writes blocked regardless of config) to reduce persistence and environment-tampering vectors like:

- `.git/hooks/*`
- shell startup files (`.zshrc`, `.bashrc`, etc.)
- some editor/tool config directories

See [`ARCHITECTURE.md`](/ARCHITECTURE.md) for the full list and rationale.
