package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"

	"github.com/Use-Tusk/fence/internal/fencelog"
	"golang.org/x/sys/unix"
)

// waitWithJobControl runs a stop-aware wait loop for execCmd so that the
// outer shell sees fence (rather than the inner child) suspend and resume
// when the user hits Ctrl-Z / fg.
//
// On SIGTSTP:
//   - the TTY delivers SIGTSTP directly to the child's pgrp (the foreground
//     pgrp), so the child stops on its own.
//   - this loop sees the stop via wait4(WUNTRACED), hands the terminal back
//     to fence's own pgrp, and SIGSTOPs fence itself so the user's shell
//     prints "[1]+ Stopped …".
//
// On SIGCONT (typically from `fg`):
//   - fence resumes after its self-SIGSTOP, re-grants the terminal to the
//     child's pgrp, and SIGCONTs the child group.
//
// The function returns the exit code in the conventional shell shape
// (128+signal for signaled termination). The caller is responsible for
// restoring the saved foreground pgrp on the way out.
//
// We intentionally do NOT pass WCONTINUED to wait4. On Darwin, wait4
// reports a continued child with status 0x137F — that is, the standard
// "stopped" low byte (0x7F) with SIGCONT (0x13) in the high byte.
// golang.org/x/sys/unix's WaitStatus.Stopped() on BSD checks only that
// the low byte is 0x7F and the high byte is not SIGSTOP, so it returns
// **true** for this encoding. With WCONTINUED enabled, every SIGCONT
// the loop itself just issued to the child would come back here looking
// indistinguishable from a fresh Ctrl-Z stop — sending us right back
// into self-SIGSTOP and wedging the user in an infinite [1]+ Stopped
// loop on every `fg`. Sticking to WUNTRACED keeps the loop strictly
// event-driven on stop / terminate, which is all the main Ctrl-Z / fg
// flow needs. The "third-party SIGCONT to fence" edge case still works
// because we redo the child-resume handshake inline after every
// kill(self, SIGSTOP) returns.
func waitWithJobControl(execCmd *exec.Cmd, stdinFd, childPgrp int, debug bool) (int, error) {
	if execCmd.Process == nil {
		return 0, errors.New("waitWithJobControl: child not started")
	}
	selfPgrp := syscall.Getpgrp()
	pid := execCmd.Process.Pid

	if debug {
		fencelog.Printf("[fence:jobctl] waiting on pid=%d childPgrp=%d selfPgrp=%d stdinFd=%d\n",
			pid, childPgrp, selfPgrp, stdinFd)
	}

	for {
		var ws unix.WaitStatus
		_, err := unix.Wait4(pid, &ws, unix.WUNTRACED, nil)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				if debug {
					fencelog.Printf("[fence:jobctl] wait4 EINTR; retrying\n")
				}
				continue
			}
			return 0, err
		}

		if debug {
			fencelog.Printf("[fence:jobctl] wait4 ws=0x%x stopped=%v exited=%v signaled=%v\n",
				uint32(ws), ws.Stopped(), ws.Exited(), ws.Signaled())
		}

		switch {
		case ws.Stopped():
			if ws.StopSignal() == syscall.SIGTTIN {
				currentFg, fgErr := unix.IoctlGetInt(stdinFd, unix.TIOCGPGRP)
				if fgErr == nil && currentFg == childPgrp {
					// Start()/TIOCSPGRP race: child is already the TTY fg pgrp,
					// so it just needs a SIGCONT to proceed.
					if debug {
						fencelog.Printf("[fence:jobctl] child stopped on SIGTTIN after foreground handoff; resuming\n")
					}
					_ = syscall.Kill(-childPgrp, syscall.SIGCONT)
					continue
				}
				// Child stopped on SIGTTIN while not the TTY fg (Ctrl-Z → bg
				// scenario). The shell owns the terminal — calling TIOCSPGRP(self)
				// here would steal it, the same class of bug fixed in b5d31f7.
				// Self-stop without claiming the TTY so the shell can fg fence;
				// the resume path below re-grants the TTY to the child.
				if debug {
					fencelog.Printf("[fence:jobctl] child stopped on SIGTTIN while not foreground (currentFg=%d); self-stopping without TTY claim\n", currentFg)
				}
				if err := syscall.Kill(os.Getpid(), syscall.SIGSTOP); err != nil && debug {
					fencelog.Printf("[fence:jobctl] kill(self, SIGSTOP) err=%v\n", err)
				}
			} else {
				// Normal job-control stop (SIGTSTP from Ctrl-Z). Hand the
				// terminal to fence's own pgrp so the outer shell sees
				// "[1]+ Stopped …", then stop ourselves.
				if err := unix.IoctlSetPointerInt(stdinFd, unix.TIOCSPGRP, selfPgrp); err != nil && debug {
					fencelog.Printf("[fence:jobctl] tcsetpgrp(self=%d) err=%v\n", selfPgrp, err)
				}
				if debug {
					fencelog.Printf("[fence:jobctl] stopping self (pid=%d)\n", os.Getpid())
				}
				if err := syscall.Kill(os.Getpid(), syscall.SIGSTOP); err != nil && debug {
					fencelog.Printf("[fence:jobctl] kill(self, SIGSTOP) err=%v\n", err)
				}
			}
			// Re-grant the TTY to the child only when we were brought to the
			// foreground. With bg, the shell is still the TTY owner; calling
			// TIOCSPGRP here would steal it.
			currentFg, applied := setForegroundIfOwner(stdinFd, selfPgrp, childPgrp)
			if debug {
				if applied {
					fencelog.Printf("[fence:jobctl] resumed as fg; re-granted TTY to child pgrp %d\n", childPgrp)
				} else {
					fencelog.Printf("[fence:jobctl] resumed as bg (currentFg=%d); skipping TTY re-grant\n", currentFg)
				}
			}
			if err := syscall.Kill(-childPgrp, syscall.SIGCONT); err != nil && debug {
				fencelog.Printf("[fence:jobctl] kill(-%d, SIGCONT) err=%v\n", childPgrp, err)
			}
		case ws.Exited():
			if debug {
				fencelog.Printf("[fence:jobctl] child exited code=%d\n", ws.ExitStatus())
			}
			return ws.ExitStatus(), nil
		case ws.Signaled():
			if debug {
				fencelog.Printf("[fence:jobctl] child signaled sig=%d\n", int(ws.Signal()))
			}
			return 128 + int(ws.Signal()), nil
		default:
			// WUNTRACED only reports stop/exit/terminate, so this should be
			// unreachable; log it under debug rather than silently re-waiting
			// if the platform's wait status assumptions ever shift.
			if debug {
				fencelog.Printf("[fence:jobctl] unhandled wait status ws=0x%x; re-waiting\n", uint32(ws))
			}
		}
	}
}

// setForegroundIfOwner sets newOwner as the terminal foreground process group
// on fd, but only if the current foreground pgrp is still expectedOwner. This
// guards every "hand off the TTY" site against stealing the terminal from
// whoever currently owns it (e.g. the shell after a Ctrl-Z -> bg). It returns
// the observed current foreground pgrp and whether the change was applied.
func setForegroundIfOwner(fd, expectedOwner, newOwner int) (current int, applied bool) {
	current, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil || current != expectedOwner {
		return current, false
	}
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, newOwner); err != nil {
		return current, false
	}
	return current, true
}
