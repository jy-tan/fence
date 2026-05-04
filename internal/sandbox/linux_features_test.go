//go:build linux

package sandbox

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDetectSeccompRequiresFilterProbeSuccess(t *testing.T) {
	restore := stubLinuxSeccompProbes(t,
		func(kind linuxSeccompProbeKind) error {
			if kind == linuxSeccompProbeFilter {
				return unix.EINVAL
			}
			t.Fatalf("unexpected seccomp probe %q after filter failure", kind)
			return nil
		},
		func(action uint32) error {
			t.Fatalf("unexpected seccomp action probe %#x after filter failure", action)
			return nil
		},
	)
	defer restore()

	var features LinuxFeatures
	features.detectSeccomp()

	if features.HasSeccomp {
		t.Fatal("expected HasSeccomp=false when the filter probe fails")
	}
	if features.Seccomp.Filter {
		t.Fatal("expected filter capability to be false")
	}
	if features.Seccomp.FilterError == "" {
		t.Fatal("expected filter probe error to be retained")
	}
	if features.Seccomp.UserNotify {
		t.Fatal("expected user notification to be false when filter mode is unavailable")
	}
	if features.SeccompLogLevel != 0 {
		t.Fatalf("expected seccomp log level 0, got %d", features.SeccompLogLevel)
	}
}

func TestDetectSeccompKeepsFilterWhenOptionalProbesFail(t *testing.T) {
	restore := stubLinuxSeccompProbes(t,
		func(kind linuxSeccompProbeKind) error {
			switch kind {
			case linuxSeccompProbeFilter:
				return nil
			case linuxSeccompProbeUserNotify:
				return errors.New("user notification unavailable")
			default:
				t.Fatalf("unexpected seccomp probe %q", kind)
				return nil
			}
		},
		func(action uint32) error {
			if action != uint32(unix.SECCOMP_RET_LOG) {
				t.Fatalf("unexpected seccomp action probe %#x", action)
			}
			return errors.New("log action unavailable")
		},
	)
	defer restore()

	var features LinuxFeatures
	features.detectSeccomp()

	if !features.HasSeccomp || !features.Seccomp.Filter {
		t.Fatal("expected filter mode to remain available")
	}
	if features.Seccomp.Log {
		t.Fatal("expected log action to be false")
	}
	if features.Seccomp.LogError == "" {
		t.Fatal("expected log probe error to be retained")
	}
	if features.Seccomp.UserNotify {
		t.Fatal("expected user notification to be false")
	}
	if features.Seccomp.UserNotifyError == "" {
		t.Fatal("expected user notification probe error to be retained")
	}
	if features.SeccompLogLevel != 0 {
		t.Fatalf("expected seccomp log level 0, got %d", features.SeccompLogLevel)
	}
}

func TestDetectSeccompReportsUserNotifyAsHighestCapability(t *testing.T) {
	restore := stubLinuxSeccompProbes(t,
		func(kind linuxSeccompProbeKind) error {
			switch kind {
			case linuxSeccompProbeFilter, linuxSeccompProbeUserNotify:
				return nil
			default:
				t.Fatalf("unexpected seccomp probe %q", kind)
				return nil
			}
		},
		func(action uint32) error {
			if action != uint32(unix.SECCOMP_RET_LOG) {
				t.Fatalf("unexpected seccomp action probe %#x", action)
			}
			return nil
		},
	)
	defer restore()

	var features LinuxFeatures
	features.detectSeccomp()

	if !features.HasSeccomp || !features.Seccomp.Filter {
		t.Fatal("expected seccomp filter mode to be available")
	}
	if !features.Seccomp.Log {
		t.Fatal("expected seccomp log action to be available")
	}
	if !features.Seccomp.UserNotify {
		t.Fatal("expected seccomp user notification to be available")
	}
	if features.SeccompLogLevel != 2 {
		t.Fatalf("expected seccomp log level 2, got %d", features.SeccompLogLevel)
	}
}

func TestLinuxFeatureTableRowsIncludeProbeFailures(t *testing.T) {
	rows := linuxFeatureTableRows(&LinuxFeatures{
		HasBwrap:      true,
		HasSocat:      true,
		CanUnshareNet: true,
		Seccomp: LinuxSeccompCapabilities{
			FilterError:     "prctl(PR_SET_SECCOMP): invalid argument",
			UserNotifyError: "requires seccomp filter",
		},
		HasLandlock: true,
		LandlockABI: 5,
	})

	filterRow, ok := findLinuxFeatureTableRow(rows, "Seccomp filter")
	if !ok {
		t.Fatal("missing Seccomp filter row")
	}
	if filterRow.Status != "unavailable" {
		t.Fatalf("Seccomp filter status = %q, want unavailable", filterRow.Status)
	}
	if !strings.Contains(filterRow.Details, "PR_SET_SECCOMP") {
		t.Fatalf("Seccomp filter details = %q, want probe failure", filterRow.Details)
	}

	userNotifyRow, ok := findLinuxFeatureTableRow(rows, "Seccomp user notification")
	if !ok {
		t.Fatal("missing Seccomp user notification row")
	}
	if userNotifyRow.RequiredFor != `runtimeExecPolicy: "argv"` {
		t.Fatalf("RequiredFor = %q, want runtime exec policy detail", userNotifyRow.RequiredFor)
	}
	if userNotifyRow.Status != "unavailable" {
		t.Fatalf("Seccomp user notification status = %q, want unavailable", userNotifyRow.Status)
	}
}

func findLinuxFeatureTableRow(rows []linuxFeatureTableRow, capability string) (linuxFeatureTableRow, bool) {
	for _, row := range rows {
		if row.Capability == capability {
			return row, true
		}
	}
	return linuxFeatureTableRow{}, false
}

func stubLinuxSeccompProbes(t *testing.T, probe linuxSeccompProbeFunc, actionProbe linuxSeccompActionProbeFunc) func() {
	t.Helper()

	oldProbe := linuxSeccompProbe
	oldActionProbe := linuxSeccompActionProbe
	linuxSeccompProbe = probe
	linuxSeccompActionProbe = actionProbe

	return func() {
		linuxSeccompProbe = oldProbe
		linuxSeccompActionProbe = oldActionProbe
	}
}
