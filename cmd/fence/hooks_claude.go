package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const claudePreToolUseMode = "--claude-pre-tool-use"

type claudePreToolUseEvent struct {
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	CWD           string         `json:"cwd,omitempty"`
}

type claudePreToolUseResponse struct {
	HookSpecificOutput *claudePreToolUseHookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

type claudePreToolUseHookSpecificOutput struct {
	HookEventName      string         `json:"hookEventName"`
	PermissionDecision string         `json:"permissionDecision"`
	UpdatedInput       map[string]any `json:"updatedInput,omitempty"`
}

func runClaudePreToolUseMode() error {
	return runClaudePreToolUse(os.Stdin, os.Stdout, resolveFenceExecutable(), os.Args[2:])
}

func runClaudePreToolUse(stdin io.Reader, stdout io.Writer, fenceExePath string, extraFenceArgs []string) error {
	response, changed, err := buildCompatiblePreToolUseResponse(stdin, fenceExePath, extraFenceArgs)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}

	_, err = fmt.Fprintln(stdout, string(response))
	return err
}

func buildClaudePreToolUseResponse(stdin io.Reader, fenceExePath string, extraFenceArgs []string) ([]byte, bool, error) {
	var event claudePreToolUseEvent
	decoder := json.NewDecoder(stdin)
	decoder.UseNumber()
	if err := decoder.Decode(&event); err != nil {
		return nil, false, fmt.Errorf("failed to decode Claude hook JSON: %w", err)
	}

	if event.HookEventName != "PreToolUse" || event.ToolName != "Bash" {
		return nil, false, nil
	}

	command, ok := event.ToolInput["command"].(string)
	if !ok {
		return nil, false, fmt.Errorf("Bash tool_input.command missing or not a string")
	}
	result, changed, err := evaluateShellHookRequest(shellHookRequest{
		Command:   command,
		CWD:       extractHookCommandCWD(event.ToolInput, event.CWD),
		ToolInput: event.ToolInput,
	}, fenceExePath, extraFenceArgs)
	if err != nil {
		return nil, false, err
	}
	if !changed {
		return nil, false, nil
	}
	response := claudePreToolUseResponse{HookSpecificOutput: &claudePreToolUseHookSpecificOutput{
		HookEventName: "PreToolUse",
	}}
	switch result.Decision {
	case hookShellDeny:
		response.HookSpecificOutput.PermissionDecision = "deny"
	case hookShellWrap:
		response.HookSpecificOutput.PermissionDecision = "allow"
		response.HookSpecificOutput.UpdatedInput = result.UpdatedInput
	default:
		return nil, false, nil
	}

	data, err := json.Marshal(response)
	if err != nil {
		return nil, false, fmt.Errorf("failed to encode Claude hook response: %w", err)
	}
	return data, true, nil
}
