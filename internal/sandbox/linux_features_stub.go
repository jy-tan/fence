//go:build !linux

package sandbox

// LinuxFeatures describes available Linux sandboxing features.
// This is a stub for non-Linux platforms.
type LinuxFeatures struct {
	HasBwrap        bool
	HasSocat        bool
	HasSeccomp      bool
	SeccompLogLevel int
	Seccomp         LinuxSeccompCapabilities
	HasLandlock     bool
	LandlockABI     int
	HasEBPF         bool
	HasCapBPF       bool
	HasCapRoot      bool
	CanUnshareNet   bool
	KernelMajor     int
	KernelMinor     int
}

// LinuxSeccompCapabilities is empty on non-Linux platforms.
type LinuxSeccompCapabilities struct {
	Filter          bool
	UserNotify      bool
	Log             bool
	FilterError     string
	UserNotifyError string
	LogError        string
}

// DetectLinuxFeatures returns empty features on non-Linux platforms.
func DetectLinuxFeatures() *LinuxFeatures {
	return &LinuxFeatures{}
}

// Summary returns an empty string on non-Linux platforms.
func (f *LinuxFeatures) Summary() string {
	return "not linux"
}

// CanMonitorViolations returns false on non-Linux platforms.
func (f *LinuxFeatures) CanMonitorViolations() bool {
	return false
}

// CanUseLandlock returns false on non-Linux platforms.
func (f *LinuxFeatures) CanUseLandlock() bool {
	return false
}

// MinimumViable returns false on non-Linux platforms.
func (f *LinuxFeatures) MinimumViable() bool {
	return false
}
