package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Use-Tusk/fence/internal/sandbox"
)

const fenceSandboxEnvVar = "FENCE_SANDBOX"

type hookFenceOptions struct {
	SettingsPath string
	TemplateName string
}

type shellHookRequest struct {
	Command   string
	CWD       string
	ToolInput map[string]any
}

type shellHookResult struct {
	Decision     hookShellDecision
	UpdatedInput map[string]any
}

type hookShellDecision int

const (
	hookShellNoChange hookShellDecision = iota
	hookShellDeny
	hookShellWrap
)

func (o hookFenceOptions) normalized() (hookFenceOptions, error) {
	if o.SettingsPath == "" {
		return o, nil
	}

	resolvedPath, err := resolveCLIPath(o.SettingsPath, "")
	if err != nil {
		return hookFenceOptions{}, err
	}

	o.SettingsPath = resolvedPath
	return o, nil
}

func (o hookFenceOptions) fenceArgs() []string {
	args := make([]string, 0, 4)
	if o.SettingsPath != "" {
		args = append(args, "--settings", o.SettingsPath)
	}
	if o.TemplateName != "" {
		args = append(args, "--template", o.TemplateName)
	}
	return args
}

func resolveFenceExecutable() string {
	fenceExePath, err := os.Executable()
	if err != nil || fenceExePath == "" {
		return "fence"
	}
	return filepath.Clean(fenceExePath)
}

func wrapShellCommand(command, fenceExePath string, extraFenceArgs []string) string {
	args := make([]string, 0, len(extraFenceArgs)+3)
	args = append(args, fenceExePath)
	args = append(args, extraFenceArgs...)
	args = append(args, "-c", command)
	return sandbox.ShellQuote(args)
}

func evaluateShellHookRequest(request shellHookRequest, fenceExePath string, extraFenceArgs []string) (shellHookResult, bool, error) {
	if shouldSkipShellWrap(request.Command, fenceExePath) {
		return shellHookResult{}, false, nil
	}

	blocked, err := isHookCommandBlocked(request.Command, request.CWD, extraFenceArgs)
	if err != nil {
		return shellHookResult{}, false, err
	}
	if blocked {
		return shellHookResult{Decision: hookShellDeny}, true, nil
	}

	if os.Getenv(fenceSandboxEnvVar) == "1" {
		return shellHookResult{}, false, nil
	}

	updatedInput := cloneJSONMap(request.ToolInput)
	updatedInput["command"] = wrapShellCommand(request.Command, fenceExePath, extraFenceArgs)
	return shellHookResult{
		Decision:     hookShellWrap,
		UpdatedInput: updatedInput,
	}, true, nil
}

func buildCompatiblePreToolUseResponse(stdin io.Reader, fenceExePath string, extraFenceArgs []string) ([]byte, bool, error) {
	payload, err := io.ReadAll(stdin)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read hook JSON: %w", err)
	}

	response, changed, err := buildClaudePreToolUseResponse(bytes.NewReader(payload), fenceExePath, extraFenceArgs)
	if err != nil {
		return nil, false, err
	}
	if changed {
		return response, true, nil
	}

	return buildCursorPreToolUseResponse(bytes.NewReader(payload), fenceExePath, extraFenceArgs)
}

func isHookCommandBlocked(command, commandCWD string, extraFenceArgs []string) (bool, error) {
	hookOptions, err := parseHookFenceOptionsArgs(extraFenceArgs)
	if err != nil {
		return false, err
	}

	activeConfig, err := loadActiveConfigAudit(commandCWD, hookOptions.SettingsPath, hookOptions.TemplateName)
	if err != nil {
		return false, err
	}

	return sandbox.CheckCommand(command, activeConfig.Config) != nil, nil
}

func extractHookCommandCWD(toolInput map[string]any, fallback string) string {
	if cwd, ok := stringFromJSONMap(toolInput, "cwd"); ok {
		return cwd
	}
	if cwd, ok := stringFromJSONMap(toolInput, "working_directory"); ok {
		return cwd
	}
	if cwd, ok := stringFromJSONMap(toolInput, "workingDirectory"); ok {
		return cwd
	}
	return fallback
}

func stringFromJSONMap(input map[string]any, key string) (string, bool) {
	if input == nil {
		return "", false
	}
	value, ok := input[key]
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	return text, ok && text != ""
}

func parseHookFenceOptionsArgs(args []string) (hookFenceOptions, error) {
	var hookOptions hookFenceOptions

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--settings" || arg == "-s":
			if i+1 >= len(args) {
				return hookFenceOptions{}, fmt.Errorf("missing value for %s", arg)
			}
			hookOptions.SettingsPath = args[i+1]
			i++
		case strings.HasPrefix(arg, "--settings="):
			hookOptions.SettingsPath = strings.TrimPrefix(arg, "--settings=")
		case arg == "--template" || arg == "-t":
			if i+1 >= len(args) {
				return hookFenceOptions{}, fmt.Errorf("missing value for %s", arg)
			}
			hookOptions.TemplateName = args[i+1]
			i++
		case strings.HasPrefix(arg, "--template="):
			hookOptions.TemplateName = strings.TrimPrefix(arg, "--template=")
		default:
			return hookFenceOptions{}, fmt.Errorf("unknown hook helper flag: %s", arg)
		}
	}

	if hookOptions.SettingsPath != "" && hookOptions.TemplateName != "" {
		return hookFenceOptions{}, fmt.Errorf("cannot use --settings and --template together")
	}

	return hookOptions.normalized()
}

func shouldSkipShellWrap(command, fenceExePath string) bool {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return true
	}
	if isPureCDCommand(trimmed) {
		return true
	}
	return isAlreadyFencedCommand(trimmed, fenceExePath)
}

func isPureCDCommand(command string) bool {
	if command != "cd" && !(strings.HasPrefix(command, "cd ") || strings.HasPrefix(command, "cd\t")) {
		return false
	}
	if containsCommandSubstitution(command) {
		return false
	}

	for _, separator := range []string{"&&", "||", ";", "|", ">", "<", "\n", "\r"} {
		if strings.Contains(command, separator) {
			return false
		}
	}

	return true
}

func containsCommandSubstitution(command string) bool {
	var inSingleQuote bool
	var inDoubleQuote bool
	var escaped bool

	runes := []rune(command)
	for i := 0; i < len(runes); i++ {
		c := runes[i]

		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && !inSingleQuote {
			escaped = true
			continue
		}
		if c == '\'' && !inDoubleQuote {
			inSingleQuote = !inSingleQuote
			continue
		}
		if c == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			continue
		}
		if inSingleQuote {
			continue
		}
		if c == '`' {
			return true
		}
		if c == '$' && i+1 < len(runes) && runes[i+1] == '(' {
			if i+2 < len(runes) && runes[i+2] == '(' {
				continue
			}
			return true
		}
	}

	return false
}

func isAlreadyFencedCommand(command, fenceExePath string) bool {
	quotedFenceExePath := sandbox.ShellQuote([]string{fenceExePath})
	prefixes := []string{
		"fence ",
		fenceExePath + " ",
		quotedFenceExePath + " ",
	}

	for _, prefix := range prefixes {
		if strings.HasPrefix(command, prefix) {
			return true
		}
	}

	return command == "fence" || command == fenceExePath || command == quotedFenceExePath
}

func cloneJSONMap(input map[string]any) map[string]any {
	cloned := make(map[string]any, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}
