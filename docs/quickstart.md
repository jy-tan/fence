# Quickstart

## Installation

### Homebrew (macOS)

```bash
brew tap fencesandbox/tap
brew install fencesandbox/tap/fence
```

To update:

```bash
brew upgrade fencesandbox/tap/fence
```

### Nix (macOS, Linux, Windows (WSL))

```sh
nix run nixpkgs#fence -- --help
```

This runs it directly from the repository, without installing `fence`. If you want to install it, follow the guidelines [from NixOS](https://nix.dev) or [nix-darwin](https://github.com/nix-darwin/nix-darwin).

### From Source

```bash
git clone https://github.com/fencesandbox/fence
cd fence
go build -o fence ./cmd/fence
sudo mv fence /usr/local/bin/
```

### Using Go Install

```bash
go install github.com/fencesandbox/fence/cmd/fence@latest
```

### Linux Dependencies

On Linux, you also need:

```bash
# Ubuntu/Debian
sudo apt install bubblewrap socat

# Fedora
sudo dnf install bubblewrap socat

# Arch
sudo pacman -S bubblewrap socat
```

### Do I need sudo to run fence?

No, for most Linux systems. Fence works without root privileges because:

- Package-manager-installed `bubblewrap` is typically already setuid
- Fence detects available capabilities and adapts automatically

If some features aren't available (like network namespaces in Docker/CI), fence falls back gracefully - you'll still get filesystem isolation, command blocking, and proxy-based network filtering.

Run `fence --linux-features` to see what's available in your environment.

## Verify Installation

```bash
fence --version
```

## Your First Sandboxed Command

By default, fence blocks all network access:

```bash
# This will fail - network is blocked
fence curl https://example.com
```

You should see something like:

```text
curl: (56) CONNECT tunnel failed, response 403
```

## Allow Specific Domains

Create a starter config:

```bash
fence config init
```

By default, this writes `{"extends":"code"}` to `$XDG_CONFIG_HOME/fence/fence.json` on Linux (typically `~/.config/fence/fence.json`) and `~/.config/fence/fence.json` on macOS, so common coding workflows work out of the box.

If you want a starter file with empty arrays as editable hints, use:

```bash
fence config init --scaffold
```

You can also create a fully custom config manually:

```json
{
  "network": {
    "allowedDomains": ["example.com"]
  }
}
```

Now try again:

```bash
fence curl https://example.com
```

This time it succeeds!

## Debug Mode

Use `-d` to see what's happening under the hood:

```bash
fence -d curl https://example.com
```

This shows:

- The sandbox command being run
- Proxy activity (allowed/blocked requests)
- Filter rule matches

## Monitor Mode

Use `-m` to see only violations and blocked requests:

```bash
fence -m npm install
```

For fullscreen TUIs, send Fence's own monitor/debug logs to a file and watch
them in another terminal:

```bash
fence -m --fence-log-file /tmp/fence.log claude
tail -f /tmp/fence.log
```

This is useful for:

- Auditing what a command tries to access
- Debugging why something isn't working
- Understanding a package's network behavior

## Running Shell Commands

Use `-c` to run compound commands:

```bash
fence -c "echo hello && ls -la"
```

## Expose Ports for Servers

If you're running a server that needs to accept connections:

```bash
fence -p 3000 -c "npm run dev"
```

This allows connections from your machine to port 3000 (the host-side
listener binds `127.0.0.1` only) while keeping outbound network restricted.
On WSL2 this is also what makes the server reachable from a Windows browser
at `http://127.0.0.1:3000/`.

To expose the server to other hosts on your LAN, use `-p 0.0.0.0:3000`
(or a specific interface IP):

```bash
fence -p 0.0.0.0:3000 -c "npm run dev"   # reachable from other LAN hosts
```

## Next steps

- Read **[Why Fence](why-fence.md)** to understand when fence is a good fit (and when it isn't).
- Learn the mental model in **[Concepts](concepts.md)**.
- Use **[Troubleshooting](troubleshooting.md)** if something is blocked unexpectedly.
- Start from copy/paste configs in **[`docs/templates/`](templates/README.md)**.
- Follow workflow-specific guides in **[Recipes](recipes/README.md)** (npm/pip/git/CI).
