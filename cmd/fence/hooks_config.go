package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Use-Tusk/fence/internal/sandbox"
)

func writeClaudeHooksConfigWithOptions(w io.Writer, hookOptions hookFenceOptions) error {
	config := buildClaudeHooksConfigWithOptions(hookOptions)
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal Claude hook config: %w", err)
	}

	_, err = fmt.Fprintln(w, string(data))
	return err
}

func writeCursorHooksConfigWithOptions(w io.Writer, hookOptions hookFenceOptions) error {
	config := buildCursorHooksConfigWithOptions(hookOptions)
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal Cursor hook config: %w", err)
	}

	_, err = fmt.Fprintln(w, string(data))
	return err
}

func defaultCursorHooksPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cursor", "hooks.json")
}

func buildClaudeHooksConfigWithOptions(hookOptions hookFenceOptions) map[string]any {
	return map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				buildClaudePreToolUseHookGroupWithOptions(hookOptions),
			},
		},
	}
}

func buildCursorHooksConfigWithOptions(hookOptions hookFenceOptions) map[string]any {
	return map[string]any{
		"version": 1,
		"hooks": map[string]any{
			"preToolUse": []any{
				buildCursorPreToolUseHookGroupWithOptions(hookOptions),
			},
		},
	}
}

func buildClaudePreToolUseHookGroupWithOptions(hookOptions hookFenceOptions) map[string]any {
	return map[string]any{
		"matcher": "Bash",
		"hooks": []any{
			map[string]any{
				"type":    "command",
				"command": claudeHookCommandWithOptions(hookOptions),
			},
		},
	}
}

func buildCursorPreToolUseHookGroupWithOptions(hookOptions hookFenceOptions) map[string]any {
	return map[string]any{
		"matcher": "Shell",
		"command": cursorHookCommandWithOptions(hookOptions),
	}
}

func claudeHookCommand() string {
	return claudeHookCommandWithOptions(hookFenceOptions{})
}

func claudeHookCommandWithOptions(hookOptions hookFenceOptions) string {
	args := []string{"fence", claudePreToolUseMode}
	args = append(args, hookOptions.fenceArgs()...)
	return sandbox.ShellQuote(args)
}

func cursorHookCommand() string {
	return cursorHookCommandWithOptions(hookFenceOptions{})
}

func cursorHookCommandWithOptions(hookOptions hookFenceOptions) string {
	args := []string{"fence", cursorPreToolUseMode}
	args = append(args, hookOptions.fenceArgs()...)
	return sandbox.ShellQuote(args)
}

func installClaudeHook(path string) (bool, error) {
	return installClaudeHookWithOptions(path, hookFenceOptions{})
}

func installClaudeHookWithOptions(path string, hookOptions hookFenceOptions) (bool, error) {
	doc, err := loadHookConfigDocument(path, "Claude settings")
	if err != nil {
		return false, err
	}

	hooks, err := ensureJSONObjectField(doc, "hooks", "Claude settings")
	if err != nil {
		return false, err
	}

	preToolUse, err := getJSONArrayField(hooks, "PreToolUse", "Claude settings")
	if err != nil {
		return false, err
	}

	desiredCommand := claudeHookCommandWithOptions(hookOptions)
	summary := summarizeHookCommands(preToolUse, desiredCommand, isClaudeHookCommand)
	if summary.Total == 1 && summary.Exact == 1 {
		return false, nil
	}

	filtered := preToolUse
	if summary.Total > 0 {
		var removed bool
		filtered, removed = removeHookCommands(preToolUse, isClaudeHookCommand)
		if !removed {
			filtered = preToolUse
		}
	}

	hooks["PreToolUse"] = append(filtered, buildClaudePreToolUseHookGroupWithOptions(hookOptions))
	doc["hooks"] = hooks

	if err := writeHookConfigDocument(path, doc, "Claude settings"); err != nil {
		return false, err
	}
	return true, nil
}

func installCursorHook(path string) (bool, error) {
	return installCursorHookWithOptions(path, hookFenceOptions{})
}

func installCursorHookWithOptions(path string, hookOptions hookFenceOptions) (bool, error) {
	doc, err := loadHookConfigDocument(path, "Cursor hooks config")
	if err != nil {
		return false, err
	}

	if _, ok := doc["version"]; !ok {
		doc["version"] = 1
	}

	hooks, err := ensureJSONObjectField(doc, "hooks", "Cursor hooks config")
	if err != nil {
		return false, err
	}

	preToolUse, err := getJSONArrayField(hooks, "preToolUse", "Cursor hooks config")
	if err != nil {
		return false, err
	}

	desiredCommand := cursorHookCommandWithOptions(hookOptions)
	summary := summarizeHookCommands(preToolUse, desiredCommand, isCursorHookCommand)
	if summary.Total == 1 && summary.Exact == 1 {
		return false, nil
	}

	filtered := preToolUse
	if summary.Total > 0 {
		var removed bool
		filtered, removed = removeHookCommands(preToolUse, isCursorHookCommand)
		if !removed {
			filtered = preToolUse
		}
	}

	hooks["preToolUse"] = append(filtered, buildCursorPreToolUseHookGroupWithOptions(hookOptions))
	doc["hooks"] = hooks

	if err := writeHookConfigDocument(path, doc, "Cursor hooks config"); err != nil {
		return false, err
	}
	return true, nil
}

func uninstallClaudeHook(path string) (bool, error) {
	doc, err := loadHookConfigDocument(path, "Claude settings")
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	hooksValue, ok := doc["hooks"]
	if !ok {
		return false, nil
	}
	hooks, ok := hooksValue.(map[string]any)
	if !ok {
		return false, fmt.Errorf("invalid Claude settings: hooks must be an object")
	}

	preToolUseValue, ok := hooks["PreToolUse"]
	if !ok {
		return false, nil
	}
	preToolUse, ok := preToolUseValue.([]any)
	if !ok {
		return false, fmt.Errorf("invalid Claude settings: hooks.PreToolUse must be an array")
	}

	filtered, removed := removeHookCommands(preToolUse, isClaudeHookCommand)
	if !removed {
		return false, nil
	}

	if len(filtered) == 0 {
		delete(hooks, "PreToolUse")
	} else {
		hooks["PreToolUse"] = filtered
	}

	if len(hooks) == 0 {
		delete(doc, "hooks")
	} else {
		doc["hooks"] = hooks
	}

	if err := writeHookConfigDocument(path, doc, "Claude settings"); err != nil {
		return false, err
	}
	return true, nil
}

func uninstallCursorHook(path string) (bool, error) {
	doc, err := loadHookConfigDocument(path, "Cursor hooks config")
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	hooksValue, ok := doc["hooks"]
	if !ok {
		return false, nil
	}
	hooks, ok := hooksValue.(map[string]any)
	if !ok {
		return false, fmt.Errorf("invalid Cursor hooks config: hooks must be an object")
	}

	preToolUseValue, ok := hooks["preToolUse"]
	if !ok {
		return false, nil
	}
	preToolUse, ok := preToolUseValue.([]any)
	if !ok {
		return false, fmt.Errorf("invalid Cursor hooks config: hooks.preToolUse must be an array")
	}

	filtered, removed := removeHookCommands(preToolUse, isCursorHookCommand)
	if !removed {
		return false, nil
	}

	if len(filtered) == 0 {
		delete(hooks, "preToolUse")
	} else {
		hooks["preToolUse"] = filtered
	}

	if len(hooks) == 0 {
		delete(doc, "hooks")
	} else {
		doc["hooks"] = hooks
	}

	if err := writeHookConfigDocument(path, doc, "Cursor hooks config"); err != nil {
		return false, err
	}
	return true, nil
}

func isClaudeHookCommand(command string) bool {
	return containsHelperMode(command, claudePreToolUseMode)
}

func isCursorHookCommand(command string) bool {
	return containsHelperMode(command, cursorPreToolUseMode)
}
