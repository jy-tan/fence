//go:build !linux

package main

import (
	"fmt"
	"os/exec"
)

func startCommandWithPTY(_ *exec.Cmd) (func(), error) {
	return nil, fmt.Errorf("PTY relay is only supported on Linux")
}
