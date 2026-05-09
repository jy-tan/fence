# Security Model

Fence is intended as defense-in-depth for running semi-trusted commands with reduced side effects (package installs, build scripts, CI jobs, unfamiliar repos).

It is not designed to be a strong isolation boundary against actively malicious code that is attempting to escape.

## Threat model (what Fence helps with)

Fence is useful when you want to reduce risk from:

- Supply-chain scripts that unexpectedly call out to the network
- Tools that write broadly across your filesystem
- Accidental leakage of secrets via "phone home" behavior
- Unfamiliar repos that run surprising commands during install/build/test

## What Fence enforces

### Network

- **Default deny**: outbound network is blocked unless explicitly allowed.
- **Allowlisting by domain**: you can specify `allowedDomains` (with wildcard support like `*.example.com`).
- **Localhost controls**: inbound binding and localhost outbound are separately controlled.

Important: domain filtering does not inspect content. If you allow a domain, code can exfiltrate via that domain.

#### How allowlisting works

Fence combines OS-level enforcement with proxy-based allowlisting:

- The OS sandbox / network namespace is expected to block direct outbound connections.
- Domain allowlisting happens via local HTTP/SOCKS proxies and proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`).
- Optionally, a `network.upstreamProxy` can be configured so that grey-zone traffic (not matched by `allowedDomains`, not hard-blocked by `deniedDomains`) is forwarded to an external HTTP proxy (e.g. mitmproxy) for interactive inspection rather than being denied. `deniedDomains` are always hard-blocked and never forwarded upstream.

If a program does not use proxy env vars (or uses a custom protocol/stack), it may not benefit from domain allowlisting. In that case it typically fails with connection errors rather than being "selectively allowed."

Localhost is separate from "external domains":

- `allowLocalOutbound=false` can intentionally block connections to local services like Redis on `127.0.0.1:6379` (see the dev-server example).

### macOS IPC

- `macos.mach.lookup` and `macos.mach.register` can allow additional XPC/Mach services inside the macOS Seatbelt sandbox.
- These are local IPC exceptions, not domain allowlists. Granting more Mach access can let sandboxed code interact with system services that sit outside Fence's normal proxy-based network model.
- Prefer exact service names. Trailing wildcard prefixes and especially `["*"]` are broader compatibility tradeoffs and should be used sparingly.

### Filesystem

- **Writes are denied by default**; you must opt in with `allowWrite`.
- **denyWrite** can block specific files/patterns even if the parent directory is writable.
- **denyRead** can block reads from sensitive paths.
- Fence includes an internal list of always-protected targets (e.g. shell configs, git hooks) to reduce common persistence vectors.

### Environment sanitization

Fence strips dangerous environment variables before passing them to sandboxed commands:

- `LD_*` (Linux): `LD_PRELOAD`, `LD_LIBRARY_PATH`, etc.
- `DYLD_*` (macOS): `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, etc.

This prevents a library injection attack where a sandboxed process writes a malicious `.so`/`.dylib` and then uses `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` in a subsequent command to load it.

### Command policy boundary

Fence enforces command policy in two layers:

- Preflight command parsing supports intent-style rules (for example, `git push`).
- Runtime child-process enforcement is `execve` path-based, so it reliably blocks executable-level denies (for example, `python3`) even when launched by allowed wrappers/agents.

Because runtime checks are path-based, multi-token intent rules are not fully enforceable at runtime without overblocking broader executable usage. See `/configuration#command-detection` for exact behavior and limitations.

## Visibility / auditing

- `-m/--monitor` helps you discover what a command *tries* to access (blocked only).
- `-d/--debug` shows more detail to understand why something was blocked.

## Limitations (what Fence does NOT try to solve)

- **Hostile code containment**: assume determined attackers may escape via kernel/OS vulnerabilities.
- **Resource limits**: CPU, memory, disk, fork bombs, etc. are out of scope.
- **Content-based controls**: Fence does not block data exfiltration to *allowed* destinations.
- **Proxy limitations / protocol edge cases**: some programs may not respect proxy environment variables, so they won't get domain allowlisting unless you configure them to use a proxy (e.g. Node.js `http`/`https` without a proxy-aware client).

### Practical examples of proxy limitations

The proxy approach works well for many tools (curl, wget, git, npm, pip), but not by default for some stacks:

- Node.js native `http`/`https` (use a proxy-aware client, e.g. `undici` + `ProxyAgent`)
- Raw socket connections (custom TCP/UDP protocols)

Fence's OS-level sandbox is still expected to block direct outbound connections; bypassing the proxy should fail rather than silently succeeding.

### Domain-based filtering only

Fence does not inspect request content. If you allow a domain, a sandboxed process can still exfiltrate data to that domain.

### Not a hostile-code containment boundary

Fence is defense-in-depth for running semi-trusted code, not a strong isolation boundary against malware designed to escape sandboxes.

For implementation details (how proxies/sandboxes/bridges work), see [`ARCHITECTURE.md`](../ARCHITECTURE.md).
