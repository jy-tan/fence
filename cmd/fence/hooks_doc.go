package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tidwall/jsonc"
)

type hookCommandSummary struct {
	Total int
	Exact int
}

func loadHookConfigDocument(path string, label string) (map[string]any, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-provided path is intentional
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, fmt.Errorf("failed to read %s: %w", label, err)
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		return map[string]any{}, nil
	}

	var doc map[string]any
	if err := json.Unmarshal(jsonc.ToJSON(data), &doc); err != nil {
		return nil, fmt.Errorf("invalid JSON in %s: %w", label, err)
	}
	if doc == nil {
		return map[string]any{}, nil
	}
	return doc, nil
}

// hookConfigHasJSONCComments reports whether the file at path contains JSONC
// comments that would be stripped on a structured re-marshal. Implemented via
// byte-for-byte comparison against jsonc.ToJSON output (which replaces comments
// with whitespace, preserving positions). Returns false on a missing file.
func hookConfigHasJSONCComments(path string) (bool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-provided path is intentional
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		return false, nil
	}

	stripped := jsonc.ToJSON(data)
	if !bytes.Equal(data, stripped) {
		return true, nil
	}
	return false, nil
}

func writeHookConfigDocument(path string, doc map[string]any, label string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("failed to create %s directory: %w", label, err)
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal %s: %w", label, err)
	}

	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", label, err)
	}
	return nil
}

func ensureJSONObjectField(doc map[string]any, key string, label string) (map[string]any, error) {
	if value, ok := doc[key]; ok {
		object, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid %s: %s must be an object", label, key)
		}
		return object, nil
	}
	return map[string]any{}, nil
}

func getJSONArrayField(doc map[string]any, key string, label string) ([]any, error) {
	if value, ok := doc[key]; ok {
		array, ok := value.([]any)
		if !ok {
			return nil, fmt.Errorf("invalid %s: %s must be an array", label, key)
		}
		return array, nil
	}
	return []any{}, nil
}

func summarizeHookCommands(hookGroups []any, desiredCommand string, matcher func(string) bool) hookCommandSummary {
	var summary hookCommandSummary
	for _, groupValue := range hookGroups {
		group, ok := groupValue.(map[string]any)
		if !ok {
			continue
		}
		groupSummary := summarizeCommandsInHookGroup(group, desiredCommand, matcher)
		summary.Total += groupSummary.Total
		summary.Exact += groupSummary.Exact
	}
	return summary
}

func removeHookCommands(hookGroups []any, matcher func(string) bool) ([]any, bool) {
	filteredGroups := make([]any, 0, len(hookGroups))
	removed := false

	for _, groupValue := range hookGroups {
		group, ok := groupValue.(map[string]any)
		if !ok {
			filteredGroups = append(filteredGroups, groupValue)
			continue
		}
		filteredGroup, groupRemoved, keepGroup := removeCommandsFromHookGroup(group, matcher)
		removed = removed || groupRemoved
		if keepGroup {
			filteredGroups = append(filteredGroups, filteredGroup)
		}
	}

	return filteredGroups, removed
}

func summarizeCommandsInHookGroup(group map[string]any, desiredCommand string, matcher func(string) bool) hookCommandSummary {
	var summary hookCommandSummary

	if command, ok := group["command"].(string); ok {
		if matcher(command) {
			summary.Total++
			if command == desiredCommand {
				summary.Exact++
			}
		}
		return summary
	}

	hooksValue, ok := group["hooks"].([]any)
	if !ok {
		return summary
	}
	for _, hookValue := range hooksValue {
		hook, ok := hookValue.(map[string]any)
		if !ok {
			continue
		}
		command, ok := hook["command"].(string)
		if hook["type"] == "command" && ok && matcher(command) {
			summary.Total++
			if command == desiredCommand {
				summary.Exact++
			}
		}
	}
	return summary
}

func removeCommandsFromHookGroup(group map[string]any, matcher func(string) bool) (map[string]any, bool, bool) {
	if command, ok := group["command"].(string); ok {
		if matcher(command) {
			return nil, true, false
		}
		return group, false, true
	}

	hooksValue, ok := group["hooks"].([]any)
	if !ok {
		return group, false, true
	}

	filteredHooks := make([]any, 0, len(hooksValue))
	groupRemoved := false
	for _, hookValue := range hooksValue {
		hook, ok := hookValue.(map[string]any)
		command, commandOK := hook["command"].(string)
		if ok && hook["type"] == "command" && commandOK && matcher(command) {
			groupRemoved = true
			continue
		}
		filteredHooks = append(filteredHooks, hookValue)
	}

	if !groupRemoved {
		return group, false, true
	}
	if len(filteredHooks) == 0 {
		return nil, true, false
	}

	groupCopy := cloneJSONMap(group)
	groupCopy["hooks"] = filteredHooks
	return groupCopy, true, true
}

func containsHelperMode(command, helperMode string) bool {
	tokens := tokenizeHookCommand(command)
	executableIndex := firstHookExecutableTokenIndex(tokens)
	if executableIndex == -1 {
		return false
	}
	if filepath.Base(tokens[executableIndex]) != "fence" {
		return false
	}

	for _, token := range tokens[executableIndex+1:] {
		if token == helperMode {
			return true
		}
	}
	return false
}

func tokenizeHookCommand(command string) []string {
	var tokens []string
	var current strings.Builder
	var inSingleQuote bool
	var inDoubleQuote bool

	for _, c := range command {
		switch {
		case c == '\'' && !inDoubleQuote:
			inSingleQuote = !inSingleQuote
		case c == '"' && !inSingleQuote:
			inDoubleQuote = !inDoubleQuote
		case (c == ' ' || c == '\t') && !inSingleQuote && !inDoubleQuote:
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(c)
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

func firstHookExecutableTokenIndex(tokens []string) int {
	for i, token := range tokens {
		if isShellAssignmentToken(token) {
			continue
		}
		return i
	}
	return -1
}

func isShellAssignmentToken(token string) bool {
	separator := strings.IndexByte(token, '=')
	if separator <= 0 {
		return false
	}

	name := token[:separator]
	for i := 0; i < len(name); i++ {
		c := name[i]
		if i == 0 {
			if c != '_' && !isASCIILetter(c) {
				return false
			}
			continue
		}
		if c != '_' && !isASCIILetter(c) && !isASCIIDigit(c) {
			return false
		}
	}

	return true
}

func isASCIILetter(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

func isASCIIDigit(c byte) bool {
	return '0' <= c && c <= '9'
}
