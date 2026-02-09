# Troubleshooting

## Nested Sandboxing Not Supported

Fence cannot run inside another sandbox that uses the same underlying technology.

**macOS (Seatbelt)**: If you try to run fence inside an existing `sandbox-exec` sandbox (e.g., Nix's Darwin build sandbox), you'll see:

```text
Sandbox: sandbox-exec(...) deny(1) forbidden-sandbox-reinit
```

This is a macOS kernel limitation - nested Seatbelt sandboxes are not allowed. There is no workaround.

**Linux (Landlock)**: Landlock supports stacking (nested restrictions), but fence's test binaries cannot use the Landlock wrapper (see [Testing docs](testing.md#sandboxed-build-environments-nix-etc)).

## "bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted" (Linux)

This error occurs when fence tries to create a network namespace but the environment lacks the `CAP_NET_ADMIN` capability. This is common in:

- **Docker containers** (unless run with `--privileged` or `--cap-add=NET_ADMIN`)
- **GitHub Actions** and other CI runners
- **Ubuntu 24.04+** with restrictive AppArmor policies
- **Kubernetes pods** without elevated security contexts

**What happens now:**

Fence automatically detects this limitation and falls back to running **without network namespace isolation**. The sandbox still provides:

- Filesystem restrictions (read-only root, allowWrite paths)
- PID namespace isolation
- Seccomp syscall filtering
- Landlock (if available)

**What's reduced:**

- Network isolation via namespace is skipped
- The proxy-based domain filtering still works (via `HTTP_PROXY`/`HTTPS_PROXY`)
- But programs that bypass proxy env vars won't be network-isolated

**To check if your environment supports network namespaces:**

```bash
fence --linux-features
```

Look for "Network namespace (--unshare-net): true/false"

**Solutions if you need full network isolation:**

1. **Run with elevated privileges:**

   ```bash
   sudo fence <command>
   ```

2. **In Docker, add capability:**

   ```bash
   docker run --cap-add=NET_ADMIN ...
   ```

3. **In GitHub Actions**, this typically isn't possible without self-hosted runners with elevated permissions.

4. **On Ubuntu 24.04+**, you may need to modify AppArmor profiles (see [Ubuntu bug 2069526](https://bugs.launchpad.net/bugs/2069526)).

## "bwrap: setting up uid map: Permission denied" (Linux)

This error occurs when bwrap cannot create user namespaces. This typically happens when:

- The `uidmap` package is not installed
- `/etc/subuid` and `/etc/subgid` are not configured for your user
- bwrap is not setuid

**Quick fix (if you have root access):**

```bash
# Install uidmap
sudo apt install uidmap  # Debian/Ubuntu

# Make bwrap setuid
sudo chmod u+s $(which bwrap)
```

**Or configure subuid/subgid for your user:**

```bash
echo "$(whoami):100000:65536" | sudo tee -a /etc/subuid
echo "$(whoami):100000:65536" | sudo tee -a /etc/subgid
```

On most systems with package-manager-installed bwrap, this error shouldn't occur. If it does, your system may have non-standard security policies.

## "curl: (56) CONNECT tunnel failed, response 403"

This usually means:

- the process tried to reach a domain that is **not allowed**, and
- the request went through fence's HTTP proxy, which returned `403`.

Fix:

- Run with monitor mode to see what was blocked:
  - `fence -m <command>`
- Add the required destination(s) to `network.allowedDomains`.

## "It works outside fence but not inside"

Start with:

- `fence -m <command>` to see what's being denied
- `fence -d <command>` to see full proxy and sandbox detail

Common causes:

- Missing `allowedDomains`
- A tool attempting direct sockets that don't respect proxy environment variables
- Localhost outbound blocked (DB/cache on `127.0.0.1`)
- Writes blocked (you didn't include a directory in `filesystem.allowWrite`)

## Node.js HTTP(S) doesn't use proxy env vars by default

Node's built-in `http`/`https` modules ignore `HTTP_PROXY`/`HTTPS_PROXY`.

If your Node code makes outbound HTTP(S) requests, use a proxy-aware client.
For example with `undici`:

```javascript
import { ProxyAgent, fetch } from "undici";

const proxyUrl = process.env.HTTPS_PROXY;
const response = await fetch(url, {
  dispatcher: new ProxyAgent(proxyUrl),
});
```

Fence's OS-level sandbox should still block direct connections; the above makes your requests go through the filtering proxy so allowlisting works as intended.

## Local services (Redis/Postgres/etc.) fail inside the sandbox

If your process needs to connect to `localhost` services, set:

```json
{
  "network": { "allowLocalOutbound": true }
}
```

If you're running a server inside the sandbox that must accept connections:

- set `network.allowLocalBinding: true` (to bind)
- use `-p <port>` (to expose inbound port(s))

## WSL: "Permission denied" for wslpath or Windows .exe files

On WSL2, commands like `wslpath` or `powershell.exe` may fail with "Permission denied" inside the sandbox.

**Common causes:**

- **`wslpath` fails**: Fence auto-detects WSL and allows `/init` (the binfmt_misc interpreter that `wslpath` symlinks to) via `wslInterop`. If this still fails, check that `wslInterop` is not set to `false` in your config.
- **Windows `.exe` files fail**: Paths under `/mnt/` are not auto-allowed. You must add the specific executables you need.

**Fix**: Add the Windows executables you need to `allowExecute`:

```json
{
  "extends": "code",
  "filesystem": {
    "allowExecute": [
      "/mnt/c/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe"
    ]
  }
}
```

Use `allowExecute` (not `allowRead` or `allowWrite`) for the tightest permissions. Only add the specific executables you need — avoid allowing all of `/mnt`.

> [!NOTE]
> You do **not** need to add `/init` — it is handled automatically by `wslInterop` (enabled by default on WSL). Set `"wslInterop": false` to disable it.

See [Linux Security Features > WSL2](linux-security-features.md#wsl2-windows-subsystem-for-linux) for details.

## "Permission denied" on file writes

Writes are denied by default.

- Add the minimum required writable directories to `filesystem.allowWrite`.
- Protect sensitive targets with `filesystem.denyWrite` (and note fence protects some targets regardless).

Example:

```json
{
  "filesystem": {
    "allowWrite": [".", "/tmp"],
    "denyWrite": [".env", "*.key"]
  }
}
```
