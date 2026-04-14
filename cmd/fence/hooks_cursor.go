package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const cursorPreToolUseMode = "--cursor-pre-tool-use"

type cursorPreToolUseEvent struct {
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	CWD           string         `json:"cwd,omitempty"`
}

type cursorPreToolUseResponse struct {
	Permission   string         `json:"permission,omitempty"`
	UpdatedInput map[string]any `json:"updated_input,omitempty"`
	Continue     bool           `json:"continue,omitempty"`
}

func runCursorPreToolUseMode() error {
	return runCursorPreToolUse(os.Stdin, os.Stdout, resolveFenceExecutable(), os.Args[2:])
}

func runCursorPreToolUse(stdin io.Reader, stdout io.Writer, fenceExePath string, extraFenceArgs []string) error {
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

func buildCursorPreToolUseResponse(stdin io.Reader, fenceExePath string, extraFenceArgs []string) ([]byte, bool, error) {
	var event cursorPreToolUseEvent
	decoder := json.NewDecoder(stdin)
	decoder.UseNumber()
	if err := decoder.Decode(&event); err != nil {
		return nil, false, fmt.Errorf("failed to decode Cursor hook JSON: %w", err)
	}

	if event.ToolName != "Shell" {
		return nil, false, nil
	}
	if event.HookEventName != "" && event.HookEventName != "preToolUse" {
		return nil, false, nil
	}

	command, ok := event.ToolInput["command"].(string)
	if !ok {
		return nil, false, fmt.Errorf("Shell tool_input.command missing or not a string")
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
	response := cursorPreToolUseResponse{Continue: true}
	switch result.Decision {
	case hookShellDeny:
		response.Permission = "deny"
	case hookShellWrap:
		response.Permission = "allow"
		response.UpdatedInput = result.UpdatedInput
	default:
		return nil, false, nil
	}

	data, err := json.Marshal(response)
	if err != nil {
		return nil, false, fmt.Errorf("failed to encode Cursor hook response: %w", err)
	}
	return data, true, nil
}
