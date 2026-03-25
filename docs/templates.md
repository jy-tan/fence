# Config Templates

Fence includes built-in config templates for common use cases. Templates are embedded in the binary, so you can use them directly without copying files.

## Using templates

Use the `-t` / `--template` flag to apply a template:

```bash
# Use a built-in template
fence -t npm-install npm install

# Wraps Claude Code
fence -t code -- claude

# List available templates
fence --list-templates
```

You can also copy and customize templates from [`internal/templates/`](/internal/templates/).

## Extending templates

Instead of copying and modifying templates, you can extend them in your config file using the `extends` field:

```json
{
  "extends": "code",
  "network": {
    "allowedDomains": ["private-registry.company.com"]
  }
}
```

This inherits all settings from the `code` template and adds your private registry. Settings are merged:

- Slice fields (domains, paths, commands): Appended and deduplicated
- Boolean fields: OR logic (true if either enables it)
- Optional boolean fields (`useDefaults`): Override wins (child value takes precedence when set)
- Integer fields (ports): Override wins (0 keeps base value)

### Extending files

You can also extend other config files using file paths:

```json
{
  "extends": "./shared/base-config.json",
  "network": {
    "allowedDomains": ["extra-domain.com"]
  }
}
```

The `extends` value is treated as a file path if it contains `/` or `\`, or starts with `.`. Relative paths are resolved relative to the config file's directory. The extended file is validated before merging.

Chains are supported: a file can extend a template, and another file can extend that file. Circular extends are detected and rejected.

### Example: Company-specific AI agent config

```json
{
  "extends": "code",
  "network": {
    "allowedDomains": [
      "internal-npm.company.com",
      "artifactory.company.com"
    ],
    "deniedDomains": ["competitor-analytics.com"]
  },
  "filesystem": {
    "denyRead": ["~/.company-secrets/**"]
  }
}
```

This config:

- Extends the battle-tested `code` template
- Adds company-specific package registries
- Adds additional telemetry/analytics to deny list
- Protects company-specific secret directories

## Available Templates

| Template | Description |
|----------|-------------|
| `code` | Production-ready config for AI coding agents (Claude Code, Codex, Copilot, etc.) |
| `code-relaxed` | Like `code` but allows direct network for apps that ignore HTTP_PROXY |
| `git-readonly` | Blocks destructive commands like `git push`, `rm -rf`, etc. |
| `local-dev-server` | Allow binding and localhost outbound; allow writes to workspace/tmp |
