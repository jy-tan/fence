package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Use-Tusk/fence/internal/toolcall"
)

// hermesPreToolUseMode is the helper-mode flag invoked by Hermes' shell-hook
// system. Wire protocol: Hermes' agent/shell_hooks.py pipes a JSON envelope
// on stdin and reads JSON on stdout. Empty stdout = allow.
const hermesPreToolUseMode = "--hermes-pre-tool-use"

type hermesPreToolUseEvent struct {
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	CWD           string         `json:"cwd,omitempty"`
	SessionID     string         `json:"session_id,omitempty"`
}

// hermesPreToolUseResponse is the canonical Hermes block shape. Hermes also
// accepts {"decision":"block","reason":...} (Claude-Code style); we emit the
// canonical one.
type hermesPreToolUseResponse struct {
	Action  string `json:"action"`
	Message string `json:"message"`
}

func runHermesPreToolUseMode() error {
	return runHermesPreToolUse(os.Stdin, os.Stdout, os.Args[2:])
}

func runHermesPreToolUse(stdin io.Reader, stdout io.Writer, extraFenceArgs []string) error {
	response, changed, err := buildHermesPreToolUseResponse(stdin, extraFenceArgs)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	_, err = fmt.Fprintln(stdout, string(response))
	return err
}

// buildHermesPreToolUseResponse decodes the envelope, evaluates against the
// dispatch table, and emits a block response on deny. changed=false on
// allow / skip / non-pre_tool_call event.
func buildHermesPreToolUseResponse(stdin io.Reader, extraFenceArgs []string) ([]byte, bool, error) {
	var event hermesPreToolUseEvent
	decoder := json.NewDecoder(stdin)
	decoder.UseNumber()
	if err := decoder.Decode(&event); err != nil {
		return nil, false, fmt.Errorf("failed to decode Hermes hook JSON: %w", err)
	}

	if event.HookEventName != "" && event.HookEventName != "pre_tool_call" {
		return nil, false, nil
	}

	hookOptions, err := parseHookFenceOptionsArgs(extraFenceArgs)
	if err != nil {
		return nil, false, err
	}

	cwd := extractHookCommandCWD(event.ToolInput, event.CWD)
	activeConfig, err := loadActiveConfigAudit(cwd, hookOptions.SettingsPath, hookOptions.TemplateName)
	if err != nil {
		return nil, false, err
	}

	evaluator := &toolcall.Evaluator{
		Table:  hermesDispatchTable,
		Config: activeConfig.Config,
	}

	decision := evaluator.Evaluate(toolcall.ToolCall{
		ToolName: event.ToolName,
		Params:   event.ToolInput,
		CWD:      cwd,
	})

	if decision.Outcome != toolcall.OutcomeDeny {
		return nil, false, nil
	}

	response := hermesPreToolUseResponse{
		Action:  "block",
		Message: hermesDenyMessage(event.ToolName, decision),
	}
	data, err := json.Marshal(response)
	if err != nil {
		return nil, false, fmt.Errorf("failed to encode Hermes hook response: %w", err)
	}
	return data, true, nil
}

// hermesDenyMessage formats a deny reason. Hermes echoes this into the
// model's tool result stream so the LLM can recover with a different call.
func hermesDenyMessage(toolName string, decision toolcall.Decision) string {
	if decision.Reason != "" {
		return fmt.Sprintf("blocked by Fence policy (%s): %s", toolName, decision.Reason)
	}
	if decision.MatchedRule != "" {
		return fmt.Sprintf("blocked by Fence policy (%s): %s matches %q", toolName, decision.Domain, decision.MatchedRule)
	}
	return fmt.Sprintf("blocked by Fence policy (%s)", toolName)
}

// hermesDispatchTable maps Hermes tool names (from hermes-agent/tools/) to
// their policy domain. Keep curated: only tools whose primary risk maps to
// one of Fence's existing config domains. Tools needing their own policy
// vocabulary (delegate_tool, send_message, mcp_tool, ...) wait for that
// vocabulary to land.
var hermesDispatchTable = toolcall.Table{
	"terminal": {
		Domain:  toolcall.DomainCommand,
		Extract: toolcall.StringExtractor("command"),
	},
	"write_file": {
		Domain:  toolcall.DomainFilesystemWrite,
		Extract: toolcall.StringExtractor("path"),
	},
	"patch": {
		Domain:  toolcall.DomainFilesystemWrite,
		Extract: toolcall.StringExtractor("path"),
	},
	"web_extract": {
		Domain:  toolcall.DomainNetworkURL,
		Extract: toolcall.StringExtractor("url"),
	},
}
