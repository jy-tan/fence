package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Use-Tusk/fence/internal/toolcall"
)

// windsurfHookMode is the helper-mode flag invoked by Windsurf Cascade hooks.
// Wire protocol: Windsurf pipes a JSON envelope on stdin. For pre-hooks,
// exiting 2 blocks the action and stderr is surfaced to Cascade.
const windsurfHookMode = "--windsurf-hook"

type windsurfHookEvent struct {
	AgentActionName string         `json:"agent_action_name"`
	ToolInfo        map[string]any `json:"tool_info"`
}

func runWindsurfHookMode() error {
	return runWindsurfHook(os.Stdin, os.Stderr, os.Args[2:])
}

func runWindsurfHook(stdin io.Reader, stderr io.Writer, extraFenceArgs []string) error {
	message, blocked, err := buildWindsurfHookBlockMessage(stdin, extraFenceArgs)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err.Error())
		return err
	}
	if !blocked {
		return nil
	}
	if _, err := fmt.Fprintln(stderr, message); err != nil {
		return err
	}
	return windsurfHookBlockedError(message)
}

type windsurfHookBlockedError string

func (e windsurfHookBlockedError) Error() string {
	return string(e)
}

func buildWindsurfHookBlockMessage(stdin io.Reader, extraFenceArgs []string) (string, bool, error) {
	var event windsurfHookEvent
	decoder := json.NewDecoder(stdin)
	decoder.UseNumber()
	if err := decoder.Decode(&event); err != nil {
		return "", false, fmt.Errorf("failed to decode Windsurf hook JSON: %w", err)
	}

	spec, ok := windsurfDispatchTable[event.AgentActionName]
	if !ok {
		return "", false, nil
	}
	value, ok := spec.Extract(event.ToolInfo)
	if !ok {
		return "", false, fmt.Errorf("Windsurf %s tool_info missing required policy field", event.AgentActionName)
	}

	hookOptions, err := parseHookFenceOptionsArgs(extraFenceArgs)
	if err != nil {
		return "", false, err
	}

	cwd := extractHookCommandCWD(event.ToolInfo, "")
	activeConfig, err := loadActiveConfigAudit(cwd, hookOptions.SettingsPath, hookOptions.TemplateName)
	if err != nil {
		return "", false, err
	}

	evaluator := &toolcall.Evaluator{
		Table:  windsurfDispatchTable,
		Config: activeConfig.Config,
	}
	decision := evaluator.Evaluate(toolcall.ToolCall{
		ToolName: event.AgentActionName,
		Params:   event.ToolInfo,
		CWD:      cwd,
	})
	if decision.Outcome != toolcall.OutcomeDeny {
		return "", false, nil
	}
	if decision.Value == "" {
		decision.Value = value
	}
	return windsurfDenyMessage(event.AgentActionName, decision), true, nil
}

func windsurfDenyMessage(actionName string, decision toolcall.Decision) string {
	if decision.Reason != "" {
		return fmt.Sprintf("blocked by Fence policy (%s): %s", actionName, decision.Reason)
	}
	if decision.MatchedRule != "" {
		return fmt.Sprintf("blocked by Fence policy (%s): %s matches %q", actionName, decision.Domain, decision.MatchedRule)
	}
	return fmt.Sprintf("blocked by Fence policy (%s)", actionName)
}

var windsurfDispatchTable = toolcall.Table{
	"pre_run_command": {
		Domain:  toolcall.DomainCommand,
		Extract: toolcall.StringExtractor("command_line"),
	},
	"pre_write_code": {
		Domain:  toolcall.DomainFilesystemWrite,
		Extract: toolcall.StringExtractor("file_path"),
	},
}
