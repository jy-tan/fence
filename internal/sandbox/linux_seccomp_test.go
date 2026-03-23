//go:build linux

package sandbox

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestSeccompArgLow32Offset(t *testing.T) {
	if got := seccompArgLow32Offset(1); got != 24 {
		t.Fatalf("seccompArgLow32Offset(1) = %d, want 24", got)
	}
}

func TestBuildBPFProgram_BlocksTIOCSTI(t *testing.T) {
	filter := NewSeccompFilter(false)
	program, err := filter.buildBPFProgram()
	if err != nil {
		t.Fatalf("buildBPFProgram() error = %v", err)
	}

	ioctlNum, ok := getSyscallNumber("ioctl")
	if !ok {
		t.Skip("ioctl syscall number unavailable on this architecture")
	}

	wantAction := uint32(SECCOMP_RET_ERRNO | (unix.EPERM & 0xFFFF))
	found := false

	for i := 0; i+4 < len(program); i++ {
		if program[i].code != BPF_JMP|BPF_JEQ|BPF_K || program[i].k != ioctlNum {
			continue
		}
		if program[i+1].code != BPF_LD|BPF_W|BPF_ABS || program[i+1].k != seccompArgLow32Offset(1) {
			continue
		}
		if program[i+2].code != BPF_JMP|BPF_JEQ|BPF_K || program[i+2].k != uint32(unix.TIOCSTI) {
			continue
		}
		if program[i+3].code != BPF_RET|BPF_K || program[i+3].k != wantAction {
			continue
		}
		if program[i+4].code != BPF_RET|BPF_K || program[i+4].k != SECCOMP_RET_ALLOW {
			continue
		}
		found = true
		break
	}

	if !found {
		t.Fatal("expected seccomp program to contain an ioctl(TIOCSTI) blocking rule")
	}
}
