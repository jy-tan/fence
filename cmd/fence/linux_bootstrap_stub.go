//go:build !linux

package main

import (
	"fmt"
	"os"
)

// runLinuxBootstrapWrapper is a stub for non-Linux platforms.
// The bootstrap wrapper is only needed inside Linux sandboxes.
func runLinuxBootstrapWrapper() {
	fmt.Fprintln(os.Stderr, "[fence] --linux-bootstrap is only supported on Linux")
	os.Exit(1)
}
