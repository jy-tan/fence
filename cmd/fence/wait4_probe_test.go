//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestProbeWait4Continued is a diagnostic probe for what wait4(WUNTRACED|
// WCONTINUED) actually returns on Darwin when a child is SIGTSTP'd then
// SIGCONT'd. We need to know whether the kernel reports a continued event
// at all, and if so what bit pattern. The result drives whether the
// jobcontrol wait loop should pass WCONTINUED to wait4 on macOS.
//
// Run with: go test -v -run TestProbeWait4Continued ./cmd/fence/
func TestProbeWait4Continued(t *testing.T) {
	if testing.Short() {
		t.Skip("probe test; skipped under -short")
	}
	if os.Getenv("FENCE_RUN_WAIT4_PROBE") != "1" {
		t.Skip("set FENCE_RUN_WAIT4_PROBE=1 to run")
	}

	signal.Ignore(syscall.SIGTTOU)
	cmd := exec.Command("sleep", "10")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: 0}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	pid := cmd.Process.Pid
	pgrp, _ := syscall.Getpgid(pid)
	t.Logf("child pid=%d pgrp=%d", pid, pgrp)

	time.Sleep(200 * time.Millisecond)

	// SIGTSTP the child.
	if err := syscall.Kill(-pgrp, syscall.SIGTSTP); err != nil {
		t.Fatalf("SIGTSTP: %v", err)
	}

	// Iteration 1: expect stopped.
	var ws1 unix.WaitStatus
	_, err := unix.Wait4(pid, &ws1, unix.WUNTRACED|unix.WCONTINUED, nil)
	t.Logf("iter1 err=%v ws=0x%x stopped=%v continued=%v exited=%v signaled=%v sig=%v",
		err, uint32(ws1), ws1.Stopped(), ws1.Continued(), ws1.Exited(), ws1.Signaled(), ws1.Signal())

	if !ws1.Stopped() {
		t.Fatalf("expected stopped; got ws=0x%x", uint32(ws1))
	}

	// SIGCONT the child.
	if err := syscall.Kill(-pgrp, syscall.SIGCONT); err != nil {
		t.Fatalf("SIGCONT: %v", err)
	}

	// Iteration 2: see what wait4 returns now. This is the critical case.
	// Use a deadline so the test doesn't hang if wait4 just blocks.
	resultCh := make(chan unix.WaitStatus, 1)
	go func() {
		var ws unix.WaitStatus
		_, _ = unix.Wait4(pid, &ws, unix.WUNTRACED|unix.WCONTINUED, nil)
		resultCh <- ws
	}()
	select {
	case ws2 := <-resultCh:
		t.Logf("iter2 (WUNTRACED|WCONTINUED) ws=0x%x stopped=%v continued=%v exited=%v signaled=%v sig=%v",
			uint32(ws2), ws2.Stopped(), ws2.Continued(), ws2.Exited(), ws2.Signaled(), ws2.Signal())
		fmt.Printf("RAW ws2 = 0x%x (decimal %d) low=0x%x high=0x%x\n",
			uint32(ws2), uint32(ws2), uint32(ws2)&0xFF, uint32(ws2)>>8)
	case <-time.After(2 * time.Second):
		t.Log("iter2 (WUNTRACED|WCONTINUED) wait4 BLOCKED for 2s after SIGCONT")
	}

	// Iteration 3: same child, now SIGTSTP then SIGCONT it again, but this
	// time check WUNTRACED-only — it should block past SIGCONT and only
	// return on the next genuine stop/exit. This is what waitWithJobControl
	// relies on.
	_ = syscall.Kill(-pgrp, syscall.SIGTSTP)
	var ws3 unix.WaitStatus
	_, _ = unix.Wait4(pid, &ws3, unix.WUNTRACED, nil)
	t.Logf("iter3 (WUNTRACED) after another SIGTSTP: ws=0x%x stopped=%v", uint32(ws3), ws3.Stopped())

	_ = syscall.Kill(-pgrp, syscall.SIGCONT)
	wuntracedCh := make(chan unix.WaitStatus, 1)
	go func() {
		var ws unix.WaitStatus
		_, _ = unix.Wait4(pid, &ws, unix.WUNTRACED, nil)
		wuntracedCh <- ws
	}()
	select {
	case ws4 := <-wuntracedCh:
		t.Errorf("iter4 (WUNTRACED) unexpectedly returned ws=0x%x after SIGCONT — fix is broken",
			uint32(ws4))
	case <-time.After(1 * time.Second):
		t.Log("iter4 (WUNTRACED) correctly blocked past SIGCONT — fix is sound")
	}
}
