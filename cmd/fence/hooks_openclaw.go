package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Use-Tusk/fence/internal/toolcall"
)

// openclawPreToolUseMode is invoked by the @use-tusk/openclaw-fence plugin.
// Wire protocol: JSON envelope on stdin, JSON response on stdout, empty
// stdout = allow.
const openclawPreToolUseMode = "--openclaw-pre-tool-use"

type openclawPreToolUseEvent struct {
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	CWD           string         `json:"cwd,omitempty"`
}

// openclawPreToolUseResponse is the deny shape the plugin reads. We only
// emit denies; allow is signalled by empty stdout.
type openclawPreToolUseResponse struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

func runOpenclawPreToolUseMode() error {
	return runOpenclawPreToolUse(os.Stdin, os.Stdout, os.Args[2:])
}

func runOpenclawPreToolUse(stdin io.Reader, stdout io.Writer, extraFenceArgs []string) error {
	response, changed, err := buildOpenclawPreToolUseResponse(stdin, extraFenceArgs)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	_, err = fmt.Fprintln(stdout, string(response))
	return err
}

// buildOpenclawPreToolUseResponse decodes the envelope, evaluates against
// the dispatch table, and emits a deny on block. changed=false on allow /
// skip / non-before_tool_call event.
func buildOpenclawPreToolUseResponse(stdin io.Reader, extraFenceArgs []string) ([]byte, bool, error) {
	var event openclawPreToolUseEvent
	decoder := json.NewDecoder(stdin)
	decoder.UseNumber()
	if err := decoder.Decode(&event); err != nil {
		return nil, false, fmt.Errorf("failed to decode OpenClaw hook JSON: %w", err)
	}

	if event.HookEventName != "" && event.HookEventName != "before_tool_call" {
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
		Table:  openclawDispatchTable,
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

	response := openclawPreToolUseResponse{
		Decision: "deny",
		Reason:   openclawDenyMessage(event.ToolName, decision),
	}
	data, err := json.Marshal(response)
	if err != nil {
		return nil, false, fmt.Errorf("failed to encode OpenClaw hook response: %w", err)
	}
	return data, true, nil
}

// openclawDenyMessage formats a deny reason. The plugin echoes this into
// the agent's tool-result stream so the LLM can recover with a different call.
func openclawDenyMessage(toolName string, decision toolcall.Decision) string {
	if decision.Reason != "" {
		return fmt.Sprintf("blocked by Fence policy (%s): %s", toolName, decision.Reason)
	}
	if decision.MatchedRule != "" {
		return fmt.Sprintf("blocked by Fence policy (%s): %s matches %q", toolName, decision.Domain, decision.MatchedRule)
	}
	return fmt.Sprintf("blocked by Fence policy (%s)", toolName)
}

// openclawDispatchTable maps OpenClaw tool names (from
// src/agents/tool-catalog.ts) to their policy domain. Keep curated: only
// tools whose primary risk maps to one of Fence's existing config domains.
// Tools needing their own policy vocabulary (channel sends, MCP, subagent
// spawning, image/media generation) wait for that vocabulary to land.
//
// "bash" is here because external agents may emit it before OpenClaw's
// normalizeToolName collapses it to "exec".
var openclawDispatchTable = toolcall.Table{
	"exec": {
		Domain:  toolcall.DomainCommand,
		Extract: toolcall.StringExtractor("command"),
	},
	"bash": {
		Domain:  toolcall.DomainCommand,
		Extract: toolcall.StringExtractor("command"),
	},
	"write": {
		Domain:  toolcall.DomainFilesystemWrite,
		Extract: toolcall.StringExtractor("path"),
	},
	"edit": {
		Domain:  toolcall.DomainFilesystemWrite,
		Extract: toolcall.StringExtractor("path"),
	},
	"apply_patch": {
		Domain:  toolcall.DomainFilesystemWrite,
		Extract: toolcall.StringExtractor("path"),
	},
	"web_fetch": {
		Domain:  toolcall.DomainNetworkURL,
		Extract: toolcall.StringExtractor("url"),
	},
}
