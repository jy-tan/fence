package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// ShellModeDefault keeps deterministic behavior by using bash.
	ShellModeDefault = "default"
	// ShellModeUser uses the caller's SHELL env var with validation.
	ShellModeUser = "user"
)

var allowedUserShells = map[string]bool{
	"sh":   true,
	"bash": true,
	"zsh":  true,
	"ksh":  true,
	"dash": true,
	"fish": true,
}

// ResolveExecutionShell returns the shell executable path and invocation flag.
// Supported modes:
//   - default: deterministic bash
//   - user: validated absolute path from $SHELL
func ResolveExecutionShell(mode string, login bool) (string, string, error) {
	if mode == "" {
		mode = ShellModeDefault
	}

	var shellPath string
	switch mode {
	case ShellModeDefault:
		path, err := exec.LookPath("bash")
		if err != nil {
			return "", "", fmt.Errorf("shell %q not found: %w", "bash", err)
		}
		shellPath = path
	case ShellModeUser:
		envShell := strings.TrimSpace(os.Getenv("SHELL"))
		if envShell == "" {
			return "", "", fmt.Errorf("shell mode %q requires $SHELL to be set", ShellModeUser)
		}
		if !filepath.IsAbs(envShell) {
			return "", "", fmt.Errorf("shell mode %q requires absolute $SHELL path, got %q", ShellModeUser, envShell)
		}
		shellName := filepath.Base(envShell)
		if !allowedUserShells[shellName] {
			return "", "", fmt.Errorf("shell %q from $SHELL is not allowed", shellName)
		}
		info, err := os.Stat(envShell)
		if err != nil {
			return "", "", fmt.Errorf("shell from $SHELL not found: %w", err)
		}
		if info.IsDir() || info.Mode()&0o111 == 0 {
			return "", "", fmt.Errorf("shell from $SHELL is not executable: %q", envShell)
		}
		shellPath = envShell
	default:
		return "", "", fmt.Errorf("invalid shell mode %q (expected %q or %q)", mode, ShellModeDefault, ShellModeUser)
	}

	shellFlag := "-c"
	if login {
		shellFlag = "-lc"
	}

	return shellPath, shellFlag, nil
}
