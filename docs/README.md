# Fence Documentation

Fence is a sandboxing tool that restricts network and filesystem access for arbitrary commands. It's most useful for running semi-trusted code (package installs, build scripts, CI jobs, unfamiliar repos) with controlled side effects.

## Getting Started

- [Quickstart](quickstart.md) - Install fence and run your first sandboxed command in 5 minutes
- [Why Fence](why-fence.md) - What problem it solves (and what it doesn't)

## Guides

- [Concepts](concepts.md) - Mental model: OS sandbox + local proxies + config
- [Troubleshooting](troubleshooting.md) - Common failure modes and fixes
- [Using Fence with AI agents](agents.md) - Defense-in-depth and policy standardization
- [Recipes](recipes/README.md) - Common workflows (npm/pip/git/CI)
- [Templates](./templates.md) - Copy/paste templates you can start from

## Reference

- [README](../README.md) - CLI usage
- [Library Usage (Go)](library.md) - Using Fence as a Go package
- [Configuration](./configuration.md) - How to configure Fence
- [Config JSON Schema](schema/fence.schema.json) - Editor validation and autocomplete for `fence.json`
- [Architecture](../ARCHITECTURE.md) - How fence works under the hood
- [Security model](security-model.md) - Threat model, guarantees, and limitations
- [Linux security features](linux-security-features.md) - Landlock, seccomp, eBPF details and fallback behavior
- [Testing](testing.md) - How to run tests and write new ones
- [Benchmarking](benchmarking.md) - Performance overhead and profiling

## Examples

See [`examples/`](../examples/README.md) for runnable demos.

## Quick Reference

### Common commands

```bash
# Block all network (default)
fence <command>

# Use custom config
fence --settings ./fence.json <command>

# Debug mode (verbose output)
fence -d <command>

# Monitor mode (show blocked requests)
fence -m <command>

# Expose port for servers
fence -p 3000 <command>

# Run shell command
fence -c "echo hello && ls"
```
