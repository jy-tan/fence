//go:build !linux

package sandbox

import "fmt"

// RunLinuxArgvExecRunnerFromEnv is unavailable on non-Linux platforms.
func RunLinuxArgvExecRunnerFromEnv() (int, error) {
	return 1, fmt.Errorf("Linux argv exec runner is only available on Linux")
}

// RunLinuxArgvExecShim is unavailable on non-Linux platforms.
func RunLinuxArgvExecShim(args []string) (int, error) {
	return 1, fmt.Errorf("Linux argv exec shim is only available on Linux")
}
