# Linux argv-aware exec policy (design)
 
## Status
 
Draft proposal.
 
## Motivation
 
Fence currently enforces command policy primarily via preflight parsing of the
top-level command string (`command.deny`/`command.allow`). This is effective for
direct invocations (`fence -c "python3 --version"`), but it does not prevent an
allowed parent process (for example, an agent) from spawning a denied command as
a child process later.
 
Fence now includes runtime *executable* deny (path-based) to block single-token
denies (for example `python3`) for child processes. However, this still cannot
enforce multi-token intent rules at runtime (for example `git push` but allow
`git status`) because intent rules require argv-level inspection.
 
This document proposes a Linux-only, opt-in runtime exec policy that is
argv-aware at the `execve(2)` boundary.
 
## Goals
 
- Enforce multi-token command policy at runtime for child processes:
  - deny `["git", "push", ...]` while allowing `["git", "status", ...]`
- Make policy decisions based on the actual program path + argv observed at
  `execve`.
- Be usable without requiring root in common local-dev environments.
- Be explicitly opt-in (complexity + portability constraints).
 
## Non-goals
 
- Cross-platform argv-aware runtime enforcement (macOS lacks a comparable
  unprivileged mechanism; see below).
- Comprehensive syscall mediation (this targets exec only).
- Perfect anti-evasion. If the kernel/platform cannot provide reliable argv
  capture, Fence should fail closed or fall back explicitly.
 
## High-level approach (Linux)
 
Use seccomp user notification to intercept `execve` and `execveat` for processes
in the sandbox, and delegate allow/deny decisions to a userspace supervisor.
 
### Components
 
1. **Supervisor (host-side)**
   - Runs outside the sandbox.
   - Holds the effective command policy (allow/deny/prompt as needed).
   - Receives seccomp user-notif events for `execve`/`execveat`.
   - Reconstructs the candidate exec:
     - executable path (filename argument)
     - argv vector (read from tracee memory)
   - Applies policy and replies allow/deny (errno).
 
2. **Sandboxed child / init shim (sandbox-side)**
   - Installs a seccomp filter with `SECCOMP_RET_USER_NOTIF` for exec syscalls.
   - Exposes the seccomp listener FD to the supervisor (via FD inheritance or a
     local IPC channel established before sandbox entry).
   - Executes the requested command after the filter is active.
 
### Data model
 
At runtime, the supervisor evaluates:
 
- `exec_path`: resolved program path (as provided to `execve`; may be absolute or
  relative depending on caller)
- `argv`: the full argument vector
 
Rules can then be expressed as argv-prefix matches, for example:
 
- Deny: `["git", "push"]`
- Allow: `["git", "status"]`
 
This avoids the "overblock `git`" problem that arises when trying to translate
multi-token rules into path-only denies.
 
## Privileges and feasibility
 
This design does not inherently require root, but it depends on kernel and
environment support:
 
- **Kernel support**: seccomp user notification must be available.
- **Process ability**: the sandboxed process must be permitted to install a
  seccomp filter (`seccomp()`/`prctl()`).
- **Argv reconstruction**: the supervisor typically needs to read tracee memory
  to reconstruct argv. Common approaches include `process_vm_readv`. These can
  be blocked by existing seccomp policies, LSMs, or container restrictions.
 
Practical implication:
 
- Works well on typical developer machines.
- May be unavailable or unreliable in some CI/container environments.
 
## Failure modes
 
This feature must define explicit behavior for:
 
- Supervisor not running / crashed
- Listener FD not available
- Argv cannot be reconstructed
- Policy evaluation errors
- Timeout waiting for supervisor decision
 
Recommended default: **fail closed** for exec decisions when argv-aware mode is
enabled (deny exec with a clear error), because fail open would silently weaken
the user's expectation of enforcement.
 
## Performance considerations
 
Intercepting `execve` adds overhead for each process spawn:
 
- syscall trap + notification
- IPC roundtrip
- argv reconstruction
- policy match
 
This is typically acceptable for agent workloads (exec frequency is low relative
to the work being done), but it should be benchmarked and guarded behind an
explicit opt-in flag.
 
## macOS / cross-platform note
 
macOS Seatbelt (`sandbox-exec`) can deny process execution by path (`process-exec`)
but does not provide a practical, unprivileged argv-aware exec hook comparable
to seccomp user notification.
 
Achieving argv-aware blocking on macOS generally requires privileged platform
components (for example, EndpointSecurity system extensions), which is out of
scope for Fence's "lightweight CLI sandbox" goals.
 
Therefore:
 
- argv-aware runtime exec policy is Linux-only.
- On macOS, Fence should continue using:
  - preflight parsing for multi-token intent rules
  - runtime executable-path deny for single-token rules
 
## Proposed UX surface
 
### Config
 
Add an opt-in switch, for example:
 
```json
{
  "command": {
    "runtimeExecPolicy": "path" // default
    // "runtimeExecPolicy": "argv" // Linux-only
  }
}
```
 
Behavior:
 
- `path`: current behavior (cross-platform), single-token runtime exec deny.
- `argv`: Linux-only; if unavailable, error with an actionable message or allow an
  explicit fallback flag.
 
### Diagnostics
 
When a runtime exec is denied, include:
 
- executable path
- argv prefix that matched
- whether decision came from runtime exec policy vs preflight parsing
 
## Testing strategy
 
- Unit tests:
  - argv-prefix matching correctness (including tricky quoting cases once argv is
    reconstructed)
  - failure mode handling (timeouts, missing argv, supervisor down)
- Integration tests (Linux):
  - allow `git status`, deny `git push` within a single fenced session where a
    parent process spawns both commands
  - verify child process denial (agent-like wrapper spawns denied exec)
