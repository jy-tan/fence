package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/fencesandbox/fence/internal/sandbox"
)

// opencodePreToolUseMode is the helper-mode flag invoked by the OpenCode
// plugin at https://github.com/Use-Tusk/opencode-fence. It reads a Claude-
// shaped PreToolUse envelope on stdin and emits a flat decision response on
// stdout (see opencodePreToolUseResponse).
const opencodePreToolUseMode = "--opencode-pre-tool-use"

// opencodePreToolUseEvent mirrors Claude's PreToolUse envelope shape.
type opencodePreToolUseEvent struct {
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	CWD           string         `json:"cwd,omitempty"`
}

// opencodePreToolUseResponse is the flat response emitted on stdout. Keep in
// sync with opencode-fence/src/fence-runner.ts.
type opencodePreToolUseResponse struct {
	Decision  string                           `json:"decision"`
	Reason    string                           `json:"reason,omitempty"`
	ToolInput *opencodePreToolUseResponseInput `json:"tool_input,omitempty"`
}

type opencodePreToolUseResponseInput struct {
	Command string `json:"command,omitempty"`
}

func runOpencodePreToolUseMode() error {
	return runOpencodePreToolUse(os.Stdin, os.Stdout, resolveFenceExecutable(), os.Args[2:])
}

func runOpencodePreToolUse(stdin io.Reader, stdout io.Writer, fenceExePath string, extraFenceArgs []string) error {
	response, changed, err := buildOpencodePreToolUseResponse(stdin, fenceExePath, extraFenceArgs)
	if err != nil {
		return err
	}
	if !changed {
		// No-op: pure cd, already-fenced, or running inside Fence and not denied.
		// The plugin treats empty stdout as "allow unchanged".
		return nil
	}

	_, err = fmt.Fprintln(stdout, string(response))
	return err
}

func buildOpencodePreToolUseResponse(stdin io.Reader, fenceExePath string, extraFenceArgs []string) ([]byte, bool, error) {
	var event opencodePreToolUseEvent
	decoder := json.NewDecoder(stdin)
	decoder.UseNumber()
	if err := decoder.Decode(&event); err != nil {
		return nil, false, fmt.Errorf("failed to decode OpenCode hook JSON: %w", err)
	}

	if event.HookEventName != "" && event.HookEventName != "PreToolUse" {
		return nil, false, nil
	}
	if event.ToolName != "" && event.ToolName != "Bash" {
		return nil, false, nil
	}

	command, ok := event.ToolInput["command"].(string)
	if !ok {
		return nil, false, fmt.Errorf("bash tool_input.command missing or not a string")
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

	var response opencodePreToolUseResponse
	switch result.Decision {
	case hookShellDeny:
		response.Decision = "deny"
		response.Reason = opencodeDenyReason(command, extraFenceArgs)
	case hookShellWrap:
		wrapped, ok := result.UpdatedInput["command"].(string)
		if !ok {
			return nil, false, fmt.Errorf("OpenCode wrap result missing wrapped command")
		}
		response.Decision = "wrap"
		response.ToolInput = &opencodePreToolUseResponseInput{Command: wrapped}
	default:
		return nil, false, nil
	}

	data, err := json.Marshal(response)
	if err != nil {
		return nil, false, fmt.Errorf("failed to encode OpenCode hook response: %w", err)
	}
	return data, true, nil
}

// opencodeDenyReason re-runs CheckCommand to surface the rich CommandBlockedError
// text (mentioning the matched deny prefix) rather than a generic message. The
// caller has already determined the command is blocked; this call is just for
// error-text extraction.
func opencodeDenyReason(command string, extraFenceArgs []string) string {
	fallback := fmt.Sprintf("command blocked by Fence policy: %s", command)
	hookOptions, err := parseHookFenceOptionsArgs(extraFenceArgs)
	if err != nil {
		return fallback
	}
	activeConfig, err := loadActiveConfigAudit("", hookOptions.SettingsPath, hookOptions.TemplateName)
	if err != nil {
		return fallback
	}
	if checkErr := sandbox.CheckCommand(command, activeConfig.Config); checkErr != nil {
		return checkErr.Error()
	}
	return fallback
}
