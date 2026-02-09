//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// LinuxFeatures describes available Linux sandboxing features.
type LinuxFeatures struct {
	// Core dependencies
	HasBwrap bool
	HasSocat bool

	// Kernel features
	HasSeccomp      bool
	SeccompLogLevel int // 0=none, 1=LOG, 2=USER_NOTIF
	HasLandlock     bool
	LandlockABI     int // 0=none, 1-4 = ABI version

	// eBPF capabilities (requires CAP_BPF or root)
	HasEBPF    bool
	HasCapBPF  bool
	HasCapRoot bool

	// Network namespace capability
	// This can be false in containerized environments (Docker, CI) without CAP_NET_ADMIN
	CanUnshareNet bool

	// WSL (Windows Subsystem for Linux) detection
	IsWSL bool

	// Kernel version
	KernelMajor int
	KernelMinor int
}

var (
	detectedFeatures *LinuxFeatures
	detectOnce       sync.Once
)

// DetectLinuxFeatures checks what sandboxing features are available.
// Results are cached for subsequent calls.
func DetectLinuxFeatures() *LinuxFeatures {
	detectOnce.Do(func() {
		detectedFeatures = &LinuxFeatures{}
		detectedFeatures.detect()
	})
	return detectedFeatures
}

func (f *LinuxFeatures) detect() {
	// Check for bwrap and socat
	f.HasBwrap = commandExists("bwrap")
	f.HasSocat = commandExists("socat")

	// Parse kernel version
	f.parseKernelVersion()

	// Check seccomp support
	f.detectSeccomp()

	// Check Landlock support
	f.detectLandlock()

	// Check eBPF capabilities
	f.detectEBPF()

	// Check if we can create network namespaces
	f.detectNetworkNamespace()

	// Check if running under WSL
	f.detectWSL()
}

func (f *LinuxFeatures) parseKernelVersion() {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return
	}

	release := unix.ByteSliceToString(uname.Release[:])
	parts := strings.Split(release, ".")
	if len(parts) >= 2 {
		f.KernelMajor, _ = strconv.Atoi(parts[0])
		// Handle versions like "6.2.0-39-generic"
		minorStr := strings.Split(parts[1], "-")[0]
		f.KernelMinor, _ = strconv.Atoi(minorStr)
	}
}

func (f *LinuxFeatures) detectSeccomp() {
	// Check if seccomp is supported via prctl
	// PR_GET_SECCOMP returns 0 if seccomp is disabled, 1/2 if enabled, -1 on error
	_, _, err := unix.Syscall(unix.SYS_PRCTL, unix.PR_GET_SECCOMP, 0, 0)
	if err == 0 || err == unix.EINVAL {
		// EINVAL means seccomp is supported but not enabled for this process
		f.HasSeccomp = true
	}

	// SECCOMP_RET_LOG available since kernel 4.14
	if f.KernelMajor > 4 || (f.KernelMajor == 4 && f.KernelMinor >= 14) {
		f.SeccompLogLevel = 1
	}

	// SECCOMP_RET_USER_NOTIF available since kernel 5.0
	if f.KernelMajor >= 5 {
		f.SeccompLogLevel = 2
	}
}

func (f *LinuxFeatures) detectLandlock() {
	// Landlock available since kernel 5.13
	if f.KernelMajor < 5 || (f.KernelMajor == 5 && f.KernelMinor < 13) {
		return
	}

	// Try to query the Landlock ABI version using Landlock syscall
	// landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
	// Returns the highest supported ABI version on success
	ret, _, err := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		0, // NULL attr to query ABI version
		0, // size = 0
		uintptr(LANDLOCK_CREATE_RULESET_VERSION),
	)

	// Check if syscall succeeded (errno == 0)
	// ret contains the ABI version number (1, 2, 3, 4, etc.)
	if err == 0 {
		f.HasLandlock = true
		f.LandlockABI = int(ret)
		return
	}

	// Fallback: try creating an actual ruleset (for older detection methods)
	attr := landlockRulesetAttr{
		handledAccessFS: LANDLOCK_ACCESS_FS_READ_FILE,
	}
	ret, _, err = unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), //nolint:gosec // required for syscall
		unsafe.Sizeof(attr),
		0,
	)
	if err == 0 {
		f.HasLandlock = true
		f.LandlockABI = 1 // Minimum supported version
		_ = unix.Close(int(ret))
	}
}

func (f *LinuxFeatures) detectEBPF() {
	// Check if we have CAP_BPF or CAP_SYS_ADMIN (root)
	f.HasCapRoot = os.Geteuid() == 0

	// Try to check CAP_BPF capability
	if f.HasCapRoot {
		f.HasCapBPF = true
		f.HasEBPF = true
		return
	}

	// Check if user has CAP_BPF via /proc/self/status
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			// Parse effective capabilities
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				caps, err := strconv.ParseUint(fields[1], 16, 64)
				if err == nil {
					// CAP_BPF is bit 39
					const CAP_BPF = 39
					if caps&(1<<CAP_BPF) != 0 {
						f.HasCapBPF = true
						f.HasEBPF = true
					}
				}
			}
			break
		}
	}
}

// detectNetworkNamespace probes whether bwrap --unshare-net works.
// This can fail in containerized environments (Docker, GitHub Actions, etc.)
// that don't have CAP_NET_ADMIN capability needed to set up the loopback interface.
func (f *LinuxFeatures) detectNetworkNamespace() {
	if !f.HasBwrap {
		return
	}

	// Run a minimal bwrap command with --unshare-net to test if it works
	// We use a very short timeout since this should either succeed or fail immediately
	// The bind mount is required in some environments
	cmd := exec.Command("bwrap", "--unshare-net", "--ro-bind", "/", "/", "--", "/bin/true")
	err := cmd.Run()
	f.CanUnshareNet = err == nil
}

// detectWSL checks whether the system is running under Windows Subsystem for Linux.
func (f *LinuxFeatures) detectWSL() {
	for _, path := range []string{
		"/proc/sys/fs/binfmt_misc/WSLInterop-late",
		"/proc/sys/fs/binfmt_misc/WSLInterop",
	} {
		if _, err := os.Stat(path); err == nil {
			f.IsWSL = true
			return
		}
	}
}

// Summary returns a human-readable summary of available features.
func (f *LinuxFeatures) Summary() string {
	var parts []string

	parts = append(parts, fmt.Sprintf("kernel %d.%d", f.KernelMajor, f.KernelMinor))

	if f.HasBwrap {
		if f.CanUnshareNet {
			parts = append(parts, "bwrap")
		} else {
			parts = append(parts, "bwrap(no-netns)")
		}
	}
	if f.HasSeccomp {
		switch f.SeccompLogLevel {
		case 2:
			parts = append(parts, "seccomp+usernotif")
		case 1:
			parts = append(parts, "seccomp+log")
		default:
			parts = append(parts, "seccomp")
		}
	}
	if f.HasLandlock {
		parts = append(parts, fmt.Sprintf("landlock-v%d", f.LandlockABI))
	}
	if f.HasEBPF {
		if f.HasCapRoot {
			parts = append(parts, "ebpf(root)")
		} else {
			parts = append(parts, "ebpf(CAP_BPF)")
		}
	}
	if f.IsWSL {
		parts = append(parts, "wsl")
	}

	return strings.Join(parts, ", ")
}

// CanMonitorViolations returns true if we can monitor sandbox violations.
func (f *LinuxFeatures) CanMonitorViolations() bool {
	// seccomp LOG requires kernel 4.14+
	// eBPF monitoring requires CAP_BPF or root
	return f.SeccompLogLevel >= 1 || f.HasEBPF
}

// CanUseLandlock returns true if Landlock is available.
func (f *LinuxFeatures) CanUseLandlock() bool {
	return f.HasLandlock && f.LandlockABI >= 1
}

// MinimumViable returns true if the minimum required features are available.
func (f *LinuxFeatures) MinimumViable() bool {
	return f.HasBwrap && f.HasSocat
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Landlock constants
const (
	LANDLOCK_CREATE_RULESET_VERSION = 1 << 0

	// Filesystem access rights (ABI v1+)
	LANDLOCK_ACCESS_FS_EXECUTE     = 1 << 0
	LANDLOCK_ACCESS_FS_WRITE_FILE  = 1 << 1
	LANDLOCK_ACCESS_FS_READ_FILE   = 1 << 2
	LANDLOCK_ACCESS_FS_READ_DIR    = 1 << 3
	LANDLOCK_ACCESS_FS_REMOVE_DIR  = 1 << 4
	LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
	LANDLOCK_ACCESS_FS_MAKE_CHAR   = 1 << 6
	LANDLOCK_ACCESS_FS_MAKE_DIR    = 1 << 7
	LANDLOCK_ACCESS_FS_MAKE_REG    = 1 << 8
	LANDLOCK_ACCESS_FS_MAKE_SOCK   = 1 << 9
	LANDLOCK_ACCESS_FS_MAKE_FIFO   = 1 << 10
	LANDLOCK_ACCESS_FS_MAKE_BLOCK  = 1 << 11
	LANDLOCK_ACCESS_FS_MAKE_SYM    = 1 << 12
	LANDLOCK_ACCESS_FS_REFER       = 1 << 13 // ABI v2
	LANDLOCK_ACCESS_FS_TRUNCATE    = 1 << 14 // ABI v3
	LANDLOCK_ACCESS_FS_IOCTL_DEV   = 1 << 15 // ABI v5

	// Network access rights (ABI v4+)
	LANDLOCK_ACCESS_NET_BIND_TCP    = 1 << 0
	LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1

	// Rule types
	LANDLOCK_RULE_PATH_BENEATH = 1
	LANDLOCK_RULE_NET_PORT     = 2
)

// landlockRulesetAttr is the Landlock ruleset attribute structure
type landlockRulesetAttr struct {
	handledAccessFS  uint64
	handledAccessNet uint64
}

// landlockPathBeneathAttr is used to add path-based rules
type landlockPathBeneathAttr struct {
	allowedAccess uint64
	parentFd      int32
	_             [4]byte // padding
}
