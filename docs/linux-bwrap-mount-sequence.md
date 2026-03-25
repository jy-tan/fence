# Linux `bwrap` Mount Sequence

This document explains how Fence builds the Linux `bubblewrap` mount list in
`internal/sandbox/linux.go` inside `WrapCommandLinuxWithOptions()`.

## Why Order Matters

Fence does not build the Linux sandbox from a single mount rule. It builds a
stack of progressively narrower overlays:

1. Start from a broad base view of the filesystem.
2. Add special mounts such as `/dev`, `/proc`, and `/tmp`.
3. Re-open selected writable or cross-mount paths.
4. Re-hide selected read paths.
5. Re-protect dangerous paths.
6. Re-mask denied executables and bind bridge sockets.

That ordering is important because later mounts can narrow or replace earlier
ones. A few practical examples:

- `--ro-bind / /` creates a broad read-only base, then later `--bind` mounts
  punch writable holes back into that view.
- `denyRead` is applied after the broad base so it can hide paths that would
  otherwise still be visible.
- `allowWrite: ["/"]` is inserted *before* special mounts like `/dev` and
  `/proc` so it does not wipe out those dedicated mounts.

## Ordered Phases

The mount sequence is easiest to understand as a set of phases.

| Phase | What Fence adds | Why it happens here |
|-------|------------------|---------------------|
| 1 | Base `bwrap` flags | Establish session and namespace behavior |
| 2 | Optional `--unshare-net` and `--unshare-pid` | Decide isolation shape before filesystem setup |
| 3 | Optional `--seccomp 3` | Wire seccomp before final command assembly |
| 4 | Base readable filesystem view | Start from either `--ro-bind / /` or a stricter allowlist-style base |
| 5 | `/dev`, `/proc`, `/tmp` | Establish special mounts after the base view |
| 6 | `/etc/resolv.conf` cross-mount repair | Preserve DNS readability when symlinks cross mount boundaries |
| 7 | Writable path overlays | Re-open explicitly writable paths after the read-only base is in place |
| 8 | Cross-mount rebinds | Re-expose allowed paths that `--ro-bind / /` does not capture recursively |
| 9 | `denyRead` masks | Hide specific files/dirs after the broad view exists |
| 10 | Mandatory dangerous-path protection | Protect shell startup files, git hooks, and similar targets |
| 11 | `denyWrite` read-only overlays | Re-tighten specific writable paths |
| 12 | Runtime executable deny | Block selected executables at `execve` time |
| 13 | Bridge and reverse-bridge socket binds | Make proxy and inbound bridge sockets reachable |
| 14 | Final `-- <shell> <flag> <script>` | Hand off to the bootstrap script inside the sandbox |

## Phase-by-Phase Details

### 1. Base `bwrap` Flags

Fence starts with:

```text
bwrap
--die-with-parent
```

These are not mounts, but they shape the rest of the runtime:

- `--new-session` is added in the normal Linux path, and also in interactive PTY sessions when `forceNewSession` is enabled
- `--die-with-parent` ensures the sandbox dies when Fence dies

### 2. Namespace Isolation

Fence adds:

- `--unshare-net` when the environment supports network namespaces *and* the
  current config is not in relaxed wildcard-network mode
- `--unshare-pid` unconditionally

Why this is early:

- The rest of the mount plan assumes the chosen network model is already known
- The outbound proxy bridge strategy depends on whether `--unshare-net` is in use

If `allowedDomains` contains `"*"`, Fence intentionally skips `--unshare-net`
so tools that ignore proxy environment variables can still reach the network.

### 3. Optional Seccomp Wiring

If seccomp is enabled and available, Fence appends:

```text
--seccomp 3
```

The actual filter is attached later by wrapping the final command with:

```text
exec 3<filter-file; bwrap ...
```

This is adjacent to the mount sequence because it is part of wrapper assembly,
but it does not affect mount ordering directly.

### 4. Base Readable Filesystem View

Fence has two fundamentally different starting points.

#### Normal Mode

When `filesystem.defaultDenyRead` is **false**, Fence starts with:

```text
--ro-bind / /
```

That creates a broad read-only view of the outer filesystem. Later phases then:

- make selected paths writable with `--bind`
- hide selected paths with `--tmpfs` or `/dev/null`
- add extra binds for paths on other mount points

#### `defaultDenyRead` Mode

When `filesystem.defaultDenyRead` is **true**, Fence does *not* bind `/` at all.
Instead, it builds a narrower base out of explicit read-only binds:

- essential system paths from `GetDefaultReadablePaths()`
- expanded `allowRead` paths
- expanded `allowExecute` paths
- optional `/init` on WSL when `wslInterop` is active

Important nuance:

- `allowExecute` paths are still mounted with `--ro-bind` so they are visible
  inside the sandbox
- the finer distinction between `allowRead` and `allowExecute` is enforced by
  Landlock, not by the `bwrap` mount topology alone

### 5. Special Mounts: `/dev`, `/proc`, `/tmp`

After the base readable view is set up, Fence establishes the special mounts.

#### `/dev`

Fence chooses one of two strategies:

- `devices.mode = host` or equivalent auto-resolution uses
  `--dev-bind /dev /dev`
- `devices.mode = minimal` or equivalent auto-resolution uses `--dev /dev`,
  followed by `--dev-bind` passthroughs for core device nodes such as
  `/dev/null`, `/dev/urandom`, `/dev/tty`, `/dev/ptmx`, plus any entries from
  `devices.allow`

Why this happens after the base view:

- `/dev` is a special filesystem and should not be inherited from a generic
  `--ro-bind / /`
- the chosen `/dev` layout needs to override whatever the base filesystem phase
  would otherwise expose

#### `/proc`

Fence then adds:

```text
--proc /proc
```

This replaces `/proc` with a sandbox-specific procfs view.

#### `/tmp`

Fence then adds:

```text
--tmpfs /tmp
```

This ensures `/tmp` is writable even when the broader filesystem view is
read-only.

### 6. `/etc/resolv.conf` Cross-Mount Repair

After `/tmp` exists, Fence checks whether `/etc/resolv.conf` is a symlink to a
file on another filesystem, such as `/mnt/wsl/...`.

If so, Fence:

1. walks from `/` to the real target's parent directory
2. inserts `--tmpfs` at the first mount boundary
3. creates deeper directories with `--dir`
4. finally `--ro-bind`s the real target at its original path

Why this is needed:

- `--ro-bind / /` is non-recursive across separate mount points
- a symlink can remain visible while its real target is unreachable
- DNS then breaks even though `/etc/resolv.conf` itself exists

### 7. Writable Path Overlays

Fence next computes `writablePaths` from:

- `GetDefaultWritePaths()`
- `filesystem.allowWrite`

Then it re-opens those paths with `--bind`.

#### Special Case: `allowWrite: ["/"]`

If `/` is writable, Fence inserts:

```text
--bind / /
```

but not at the end. Instead it uses `insertLinuxArgsBeforeSpecialMounts()` to
place the root bind *before* `/dev`, `/proc`, and the host `/dev` bind case.

Why:

- a late `--bind / /` would clobber the special mounts Fence just created
- inserting it earlier preserves the later `/dev`, `/proc`, and `/tmp` setup

This is one of the key reasons the sequence is not "just append more binds."

### 8. Cross-Mount Rebinds

In normal mode, `--ro-bind / /` does not recursively pull in other mount points.
That matters for paths like:

- `/mnt/c/...` on WSL
- other filesystems mounted elsewhere under `/`

So after the basic writable overlays, Fence scans allowed paths from:

- `allowExecute`
- `allowRead`
- `allowWrite`

For each path on a different device than `/`, Fence:

1. walks the directory chain from `/` to the target
2. places `--tmpfs` at the first mount boundary
3. creates deeper directories with `--dir`
4. re-binds the target with `--ro-bind` or `--bind` depending on whether it is
   writable

Why this phase comes after the broad base:

- it is specifically a repair for the shortcomings of `--ro-bind / /`
- it should only touch the allowed paths that need re-exposure

### 9. `denyRead` Masks

Fence then applies explicit `filesystem.denyRead`.

Rules:

- directories are hidden with `--tmpfs <dir>`
- files are masked with `--ro-bind /dev/null <file>`
- symlinks are skipped because mounting over them can fail when their resolved
  target does not exist inside the sandbox

Fence also records these paths so they take precedence over later mandatory
dangerous-path protection.

### 10. Mandatory Dangerous-Path Protection

Fence next protects dangerous targets even if the user did not list them in
`denyWrite`.

The protected set comes from:

- dangerous files in the current working directory
- dangerous directories in the current working directory
- `.git/hooks`
- optionally `.git/config` unless `allowGitConfig` is enabled
- dangerous files in the user's home directory
- a depth-limited walk of nested project subdirectories

Before mounting over one of these paths, Fence canonicalizes it with
`resolvePathForMount()` so symlinked paths such as `/bin/...` on usr-merged
systems are converted to a real mount destination like `/usr/bin/...`.

Protection behavior differs by read mode:

- in normal mode: Fence uses `--ro-bind <path> <path>` to keep the path visible
  but read-only
- in `defaultDenyRead` mode: Fence uses `--tmpfs` or `/dev/null` masking so it
  does not accidentally re-expose something that the stricter base view hid

Explicit `denyRead` still wins over this phase.

### 11. `denyWrite` Read-Only Overlays

After the dangerous-path phase, Fence applies `filesystem.denyWrite`:

- expanded glob matches first
- then non-glob paths
- only existing paths are mounted

Each denied write path is re-mounted with:

```text
--ro-bind <path> <path>
```

This phase is deliberately late so it can tighten paths that may have become
writable earlier through `allowWrite`.

### 12. Runtime Executable Deny

Fence then masks selected executable paths with:

```text
--ro-bind /dev/null <resolved-executable-path>
```

This phase only applies to conservative single-token deny rules such as:

- `python3`
- `chroot`

It does *not* convert compound rules such as `git push` or `dd if=` into mount
rules. Those remain preflight-only checks.

Why this phase exists:

- preflight string checks block the initial command line
- runtime exec masks stop already-running wrapper processes from launching a
  denied child executable later

#### Multicall binary protection

Before masking an executable, Fence checks whether it is a multicall binary —
a single file that implements many commands via hardlinks or symlinks (e.g.,
busybox, some coreutils builds). It does this by comparing inode and device
numbers across all directories in the search path.

If the target binary also implements critical shell commands (`ls`, `cat`,
`head`, `tail`, `env`, `echo`, and similar), Fence still applies the mask —
the sandbox is never silently weaker than what was configured — but emits a
warning naming the collateral critical commands and the total number of
additional commands that will be blocked. The warning is always emitted to
stderr; `--debug` expands the truncated collision list to show every affected
name (critical commands first, then the alphabetical remainder).

One `command` config field controls the opt-out:

- `acceptSharedBinaryCannotRuntimeDeny: ["<token>"]` — accept that this command cannot be
  isolated at runtime on this system; skip the mask silently with no diagnostic.

When all shared names are themselves deny targets (e.g., blocking both
`python` and `python3` on a shared binary), no critical collision is recorded
and the mask is applied normally with no warning.

### 13. Bridge And Reverse-Bridge Socket Binds

Once the filesystem policy is in place, Fence binds the socket paths needed by
the Linux proxy bridges.

#### Outbound bridge sockets

If outbound proxy bridging is active, Fence binds:

- the HTTP bridge Unix socket
- the SOCKS bridge Unix socket

These are writable binds because the helper processes inside the sandbox connect
through them.

#### Reverse bridge socket directory

If inbound reverse bridges are active, Fence binds the temporary directory that
contains the reverse bridge socket files.

### 14. Final Command Handoff

After the mount list is complete, Fence appends:

```text
-- <shellPath> <shellFlag> <innerScript>
```

The inner bootstrap script is responsible for:

- starting the in-sandbox `socat` listeners that connect to the bound Unix sockets
- exporting `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY`
- starting reverse listeners for exposed ports
- optionally re-execing through `fence --landlock-apply`
- finally running the user command

## Practical Mental Model

If you are debugging the mount sequence, it helps to think in this order:

1. **What is the base view?**
   `--ro-bind / /` or explicit read-only allowlist mode.
2. **What special filesystems replace parts of that base?**
   `/dev`, `/proc`, `/tmp`.
3. **What paths are reopened?**
   `allowWrite`, cross-mount repairs, bridge sockets.
4. **What paths are hidden or tightened again?**
   `denyRead`, dangerous paths, `denyWrite`, runtime exec deny.

That mental model matches how Fence assembles the actual `bwrap` arguments.

## Common Gotchas

### `--ro-bind / /` is not enough on WSL or other multi-mount systems

Paths on a different device than `/` may still be missing. That is why Fence
has the cross-mount rebind phase.

### `allowExecute` is not purely a mount concept

In `defaultDenyRead` mode, `allowExecute` paths are still mounted read-only so
they exist. The tighter "execute without general directory browsing" behavior
comes from Landlock when available.

### Symlinked destinations are risky mount targets

Fence avoids mounting directly over symlinks in some deny phases and prefers
canonicalized real paths for self-binds. This avoids hard `bwrap` startup
failures on systems with symlink-heavy filesystem layouts.

### Root write access is a sequencing hazard

If Fence appended `--bind / /` at the end, it would wipe out the carefully
constructed `/dev`, `/proc`, and `/tmp` mounts. That is why `/` is inserted
before those special mounts instead.

## Related Docs

- [Architecture](../ARCHITECTURE.md)
- [Linux Security Features](linux-security-features.md)
- [Configuration](configuration.md)
