//go:build darwin

package sandbox

import "testing"

func TestMacOS_CtrlZSuspendsFence(t *testing.T) {
	ctrlZSuspendsFence(t)
}

func TestMacOS_CtrlZSuspendsFenceAndResumesChild(t *testing.T) {
	ctrlZSuspendsFenceAndResumesChild(t)
}

func TestMacOS_CtrlZBgStdinReadFgRecovery(t *testing.T) {
	ctrlZBgStdinReadFgRecovery(t)
}
