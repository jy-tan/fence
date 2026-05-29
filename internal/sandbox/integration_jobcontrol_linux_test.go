//go:build linux

package sandbox

import "testing"

func TestLinux_CtrlZSuspendsFence(t *testing.T) {
	ctrlZSuspendsFence(t)
}

func TestLinux_CtrlZSuspendsFenceAndResumesChild(t *testing.T) {
	ctrlZSuspendsFenceAndResumesChild(t)
}

func TestLinux_CtrlZBgStdinReadFgRecovery(t *testing.T) {
	ctrlZBgStdinReadFgRecovery(t)
}
