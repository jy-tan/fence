package main

import (
	"fmt"
	"os"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// Byte-level JSONC editing for the OpenCode installer, so user-authored
// .jsonc files keep their comments through an install/uninstall cycle.
// sjson edits the underlying bytes rather than re-marshaling, so anything
// outside the edit region survives intact. Best-effort: callers fall back to
// the structured (comment-stripping) path when these helpers decline.

// editStringInPluginArrayResult is the outcome of a byte-level array edit.
// attempted=false means the helper declined and the caller should fall back
// to the structured rewrite; attempted=true means the file is in its final
// state.
type editStringInPluginArrayResult struct {
	attempted bool
	changed   bool
}

// opencodeWillPreserveComments reports whether a pending install/uninstall at
// path will run through the comment-preserving sjson edit (file exists and has
// a top-level `plugin` array) vs the structured re-marshal (which strips
// comments). Used by the cobra layer to decide whether to warn the user.
func opencodeWillPreserveComments(path string) (bool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-provided path is intentional
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	pluginField := gjson.GetBytes(data, "plugin")
	return pluginField.Exists() && pluginField.IsArray(), nil
}

// addStringToOpencodePluginArray appends value to the `plugin` array via
// sjson, preserving comments and surrounding formatting. Declines (and lets
// the caller fall back) when the file is missing, the `plugin` field is
// missing, or it isn't an array — sjson auto-creating the field produces
// unindented output we'd rather not inflict on fresh configs.
func addStringToOpencodePluginArray(path, value string) (editStringInPluginArrayResult, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-provided path is intentional
	if err != nil {
		if os.IsNotExist(err) {
			return editStringInPluginArrayResult{attempted: false}, nil
		}
		return editStringInPluginArrayResult{}, fmt.Errorf("failed to read OpenCode config: %w", err)
	}

	pluginField := gjson.GetBytes(data, "plugin")
	if !pluginField.Exists() || !pluginField.IsArray() {
		return editStringInPluginArrayResult{attempted: false}, nil
	}

	for _, entry := range pluginField.Array() {
		if entry.Type == gjson.String && entry.String() == value {
			// Already installed; preserve the file byte-for-byte.
			return editStringInPluginArrayResult{attempted: true, changed: false}, nil
		}
	}

	updated, err := sjson.SetBytes(data, "plugin.-1", value)
	if err != nil {
		// Defensive: sjson shouldn't fail on a valid array we just inspected.
		return editStringInPluginArrayResult{attempted: false}, nil
	}

	//nolint:gosec // G703: path comes from the user via --file or the resolved
	// default config path; writing where the user told us to is the contract.
	if err := os.WriteFile(path, updated, 0o600); err != nil {
		return editStringInPluginArrayResult{}, fmt.Errorf("failed to write OpenCode config: %w", err)
	}
	return editStringInPluginArrayResult{attempted: true, changed: true}, nil
}

// removeStringFromOpencodePluginArray removes the first occurrence of value
// from the `plugin` array via sjson, preserving comments and surrounding
// formatting. Declines for missing file / missing or non-array `plugin`, and
// also for last-entry removal — sjson's field-level delete re-marshals the
// surrounding region and loses comments anyway, so we defer to the structured
// path (which fires the documented comment-stripping warning).
func removeStringFromOpencodePluginArray(path, value string) (editStringInPluginArrayResult, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-provided path is intentional
	if err != nil {
		if os.IsNotExist(err) {
			return editStringInPluginArrayResult{attempted: false}, nil
		}
		return editStringInPluginArrayResult{}, fmt.Errorf("failed to read OpenCode config: %w", err)
	}

	pluginField := gjson.GetBytes(data, "plugin")
	if !pluginField.Exists() || !pluginField.IsArray() {
		return editStringInPluginArrayResult{attempted: false}, nil
	}

	matchIndex := -1
	remainingCount := 0
	for i, entry := range pluginField.Array() {
		if entry.Type == gjson.String && entry.String() == value && matchIndex == -1 {
			matchIndex = i
			continue
		}
		remainingCount++
	}
	if matchIndex == -1 {
		return editStringInPluginArrayResult{attempted: true, changed: false}, nil
	}

	if remainingCount == 0 {
		// Defer to the structured path so the empty `plugin` field is dropped cleanly.
		return editStringInPluginArrayResult{attempted: false}, nil
	}

	updated, err := sjson.DeleteBytes(data, fmt.Sprintf("plugin.%d", matchIndex))
	if err != nil {
		return editStringInPluginArrayResult{attempted: false}, nil
	}

	//nolint:gosec // G703: path comes from the user via --file or the resolved
	// default config path; writing where the user told us to is the contract.
	if err := os.WriteFile(path, updated, 0o600); err != nil {
		return editStringInPluginArrayResult{}, fmt.Errorf("failed to write OpenCode config: %w", err)
	}
	return editStringInPluginArrayResult{attempted: true, changed: true}, nil
}
