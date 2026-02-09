# Linux Security Features

Fence uses multiple layers of security on Linux, with graceful fallback when features are unavailable.

## Security Layers

| Layer | Technology | Purpose | Minimum Kernel |
|-------|------------|---------|----------------|
| 1 | **bubblewrap (bwrap)** | Namespace isolation | 3.8+ |
| 2 | **seccomp** | Syscall filtering | 3.5+ (logging: 4.14+) |
| 3 | **Landlock** | Filesystem access control | 5.13+ |
| 4 | **eBPF monitoring** | Violation visibility | 4.15+ (requires CAP_BPF) |

## Feature Detection

Fence automatically detects available features and uses the best available combination.

To see what features are detected:

```bash
# Check what features are available on your system
fence --linux-features

# Example output:
# Linux Sandbox Features:
#   Kernel: 6.8
#   Bubblewrap (bwrap): true
#   Socat: true
#   Seccomp: true (log level: 2)
#   Landlock: true (ABI v4)
#   eBPF: true (CAP_BPF: true, root: true)
#
# Feature Status:
#   ✓ Minimum requirements met (bwrap + socat)
#   ✓ Landlock available for enhanced filesystem control
#   ✓ Violation monitoring available
#   ✓ eBPF monitoring available (enhanced visibility)
```

## Landlock Integration

Landlock is applied via an **embedded wrapper** approach:

1. bwrap spawns `fence --landlock-apply -- <user-command>`
2. The wrapper applies Landlock kernel restrictions
3. The wrapper `exec()`s the user command

This provides **defense-in-depth**: both bwrap mounts AND Landlock kernel restrictions are enforced.

## Fallback Behavior

### When Landlock is not available (kernel < 5.13)

- **Impact**: No Landlock wrapper used; bwrap isolation only
- **Fallback**: Uses bwrap mount-based restrictions only
- **Security**: Still protected by bwrap's read-only mounts

### When seccomp logging is not available (kernel < 4.14)

- **Impact**: Blocked syscalls are not logged
- **Fallback**: Syscalls are still blocked, just silently
- **Workaround**: Use `dmesg` manually to check for blocked syscalls

### When eBPF is not available (no CAP_BPF/root)

- **Impact**: Filesystem violations not visible in monitor mode
- **Fallback**: Only proxy-level (network) violations are logged
- **Workaround**: Run with `sudo` or grant CAP_BPF capability

> [!NOTE]
> The eBPF monitor uses PID-range filtering (`pid >= SANDBOX_PID`) to exclude pre-existing system processes. This significantly reduces noise but isn't perfect—processes spawned after the sandbox starts may still appear.

### When network namespace is not available (containerized environments)

- **Impact**: `--unshare-net` is skipped; network is not fully isolated
- **Cause**: Running in Docker, GitHub Actions, or other environments without `CAP_NET_ADMIN`
- **Fallback**: Proxy-based filtering still works; filesystem/PID/seccomp isolation still active
- **Check**: Run `fence --linux-features` and look for "Network namespace (--unshare-net): false"
- **Workaround**: Run with `sudo`, or in Docker use `--cap-add=NET_ADMIN`

> [!NOTE]
> This is the most common "reduced isolation" scenario. Fence automatically detects this at startup and adapts. See the troubleshooting guide for more details.

### When bwrap is not available

- **Impact**: Cannot run fence on Linux
- **Solution**: Install bubblewrap: `apt install bubblewrap` or `dnf install bubblewrap`

### When socat is not available

- **Impact**: Cannot run fence on Linux
- **Solution**: Install socat: `apt install socat` or `dnf install socat`

## WSL2 (Windows Subsystem for Linux)

On WSL2, fence detects the WSL environment and reports it in feature detection (`wsl` in the summary line). The WSL init binary (`/init`) is automatically allowed via `wslInterop`. However, Windows executables under `/mnt/` must be configured explicitly.

### How it works

Fence auto-detects WSL by checking for `/proc/sys/fs/binfmt_misc/WSLInterop` or `/proc/sys/fs/binfmt_misc/WSLInterop-late`. When detected:

- The `wsl` flag appears in feature detection output
- `/init` is automatically granted execute permission in Landlock (via `wslInterop`, enabled by default on WSL)

`/init` is WSL's init binary — a statically-linked ELF executable. The kernel's binfmt_misc subsystem uses it as the interpreter for Windows PE executables. `/usr/bin/wslpath` is a symlink to `/init`.

### What still needs config

Windows drive mounts (`/mnt/c/`, `/mnt/d/`, etc.) are **not** auto-allowed — you must add specific executables and paths via `allowExecute` / `allowWrite`:

```json
{
  "extends": "code",
  "filesystem": {
    "allowExecute": [
      "/mnt/c/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe"
    ],
    "allowWrite": ["/mnt/c/temp"]
  }
}
```

### Disabling WSL interop

To prevent `/init` from being auto-allowed (e.g., to fully lock down the sandbox on WSL):

```json
{
  "filesystem": {
    "wslInterop": false
  }
}
```

See [Configuration > WSL Example](configuration.md#wsl-windows-subsystem-for-linux-example) for details.

## Blocked Syscalls (seccomp)

Fence blocks dangerous syscalls that could be used for sandbox escape or privilege escalation:

| Syscall | Reason |
|---------|--------|
| `ptrace` | Process debugging/injection |
| `process_vm_readv/writev` | Cross-process memory access |
| `keyctl`, `add_key`, `request_key` | Kernel keyring access |
| `personality` | Can bypass ASLR |
| `userfaultfd` | Potential sandbox escape vector |
| `perf_event_open` | Information leak |
| `bpf` | eBPF without proper capabilities |
| `kexec_load/file_load` | Kernel replacement |
| `mount`, `umount2`, `pivot_root` | Filesystem manipulation |
| `init_module`, `finit_module`, `delete_module` | Kernel module loading |
| And more... | See source for complete list |

## Violation Monitoring

On Linux, violation monitoring (`fence -m`) shows:

| Source | What it shows | Requirements |
|--------|---------------|--------------|
| `[fence:http]` | Blocked HTTP/HTTPS requests | None |
| `[fence:socks]` | Blocked SOCKS connections | None |
| `[fence:ebpf]` | Blocked filesystem access + syscalls | CAP_BPF or root |

**Notes**:

- The eBPF monitor tracks sandbox processes and logs `EACCES`/`EPERM` errors from syscalls
- Seccomp violations are blocked but not logged (programs show "Operation not permitted")
- eBPF requires `bpftrace` to be installed: `sudo apt install bpftrace`

## Comparison with macOS

| Feature | macOS (Seatbelt) | Linux (fence) |
|---------|------------------|---------------|
| Filesystem control | Native | bwrap + Landlock |
| Glob patterns | Native regex | Expanded at startup |
| Network isolation | Syscall filtering | Network namespace |
| Syscall filtering | Implicit | seccomp (27 blocked) |
| Violation logging | log stream | eBPF (PID-filtered) |
| Root required | No | No (eBPF monitoring: yes) |

## Kernel Version Reference

| Distribution | Default Kernel | Landlock | seccomp LOG | eBPF |
|--------------|----------------|----------|-------------|------|
| Ubuntu 24.04 | 6.8 | ✅ v4 | ✅ | ✅ |
| Ubuntu 22.04 | 5.15 | ✅ v1 | ✅ | ✅ |
| Ubuntu 20.04 | 5.4 | ❌ | ✅ | ✅ |
| Debian 12 | 6.1 | ✅ v2 | ✅ | ✅ |
| Debian 11 | 5.10 | ❌ | ✅ | ✅ |
| RHEL 9 | 5.14 | ✅ v1 | ✅ | ✅ |
| RHEL 8 | 4.18 | ❌ | ✅ | ✅ |
| Fedora 40 | 6.8 | ✅ v4 | ✅ | ✅ |
| Arch Linux | Latest | ✅ | ✅ | ✅ |

## Installing Dependencies

### Debian/Ubuntu

```bash
sudo apt install bubblewrap socat
```

### Fedora/RHEL

```bash
sudo dnf install bubblewrap socat
```

### Arch Linux

```bash
sudo pacman -S bubblewrap socat
```

### Alpine Linux

```bash
sudo apk add bubblewrap socat
```

## Enabling eBPF Monitoring

For full violation visibility without root:

```bash
# Grant CAP_BPF to the fence binary
sudo setcap cap_bpf+ep /usr/local/bin/fence
```

Or run fence with sudo when monitoring is needed:

```bash
sudo fence -m <command>
```
