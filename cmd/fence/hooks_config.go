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

// writeOpencodeHooksConfig prints a minimal opencode.json snippet that
// registers the Fence plugin via OpenCode's `plugin: [...]` array. Policy
// pinning is not supported here; for that, see the local plugin shim flow
// in the opencode-fence README.
func writeOpencodeHooksConfig(w io.Writer) error {
	config := buildOpencodeConfigSnippet()
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal OpenCode plugin config: %w", err)
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

// resolveOpencodeConfigPath returns the OpenCode config path to install into,
// preferring an existing ~/.config/opencode/opencode.jsonc over .json (matching
// OpenCode's own load order), and falling back to .json when neither exists.
// Returns "" if the home directory cannot be resolved.
func resolveOpencodeConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	dir := filepath.Join(home, ".config", "opencode")
	jsonc := filepath.Join(dir, "opencode.jsonc")
	plain := filepath.Join(dir, "opencode.json")

	if fileExists(jsonc) {
		return jsonc
	}
	if fileExists(plain) {
		return plain
	}
	return plain
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
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

const opencodePluginPackageName = "@use-tusk/opencode-fence"

func buildOpencodeConfigSnippet() map[string]any {
	return map[string]any{
		"$schema": "https://opencode.ai/config.json",
		"plugin":  []any{opencodePluginPackageName},
	}
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

// installOpencodePlugin adds the Fence plugin package to opencode.json's
// `plugin` array. Returns changed=true if the file was modified.
//
// Tries the sjson byte-level edit first (preserves comments + formatting in
// user-authored .jsonc files). Falls back to the map[string]any structured
// rewrite when the file is missing or has no `plugin` array yet; that path
// strips comments, and the cobra layer warns before calling us.
//
// Policy pinning (--settings / --template) is not plumbed through here;
// OpenCode's `plugin: [...]` loader does not accept options. Users who need
// it write a local plugin shim under .opencode/plugins/.
func installOpencodePlugin(path string) (bool, error) {
	res, err := addStringToOpencodePluginArray(path, opencodePluginPackageName)
	if err != nil {
		return false, err
	}
	if res.attempted {
		return res.changed, nil
	}

	doc, err := loadHookConfigDocument(path, "OpenCode config")
	if err != nil {
		return false, err
	}

	plugins, err := getJSONArrayField(doc, "plugin", "OpenCode config")
	if err != nil {
		return false, err
	}

	for _, value := range plugins {
		if name, ok := value.(string); ok && name == opencodePluginPackageName {
			return false, nil
		}
	}

	if _, ok := doc["$schema"]; !ok {
		doc["$schema"] = "https://opencode.ai/config.json"
	}
	doc["plugin"] = append(plugins, opencodePluginPackageName)

	if err := writeHookConfigDocument(path, doc, "OpenCode config"); err != nil {
		return false, err
	}
	return true, nil
}

// uninstallOpencodePlugin removes the Fence plugin package from opencode.json's
// `plugin` array. Returns changed=true if the file was modified. Same byte-edit
// path as installOpencodePlugin, with structured fallback when sjson declines.
//
// When the resulting array would be empty, the `plugin` field is dropped from
// the document; `$schema` is left intact.
func uninstallOpencodePlugin(path string) (bool, error) {
	res, err := removeStringFromOpencodePluginArray(path, opencodePluginPackageName)
	if err != nil {
		return false, err
	}
	if res.attempted {
		return res.changed, nil
	}

	doc, err := loadHookConfigDocument(path, "OpenCode config")
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	pluginsValue, ok := doc["plugin"]
	if !ok {
		return false, nil
	}
	plugins, ok := pluginsValue.([]any)
	if !ok {
		return false, fmt.Errorf("invalid OpenCode config: plugin must be an array")
	}

	filtered := make([]any, 0, len(plugins))
	removed := false
	for _, value := range plugins {
		if name, ok := value.(string); ok && name == opencodePluginPackageName {
			removed = true
			continue
		}
		filtered = append(filtered, value)
	}

	if !removed {
		return false, nil
	}

	if len(filtered) == 0 {
		delete(doc, "plugin")
	} else {
		doc["plugin"] = filtered
	}

	if err := writeHookConfigDocument(path, doc, "OpenCode config"); err != nil {
		return false, err
	}
	return true, nil
}
