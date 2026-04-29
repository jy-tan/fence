// Package toolcall is Fence's agent-agnostic tool-call evaluator.
//
// Adapters for different agents (Claude Code, Cursor, OpenCode, Hermes, ...)
// translate their native hook envelope into a ToolCall and look the tool
// name up in their dispatch Table; the policy logic lives here.
//
// Wrap (rewrite-the-command) decisions are intentionally not part of this
// package — they're command-domain-specific and live in the adapter
// alongside the bash envelope it understands.
package toolcall

import (
	"errors"
	"fmt"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/Use-Tusk/fence/internal/proxy"
	"github.com/Use-Tusk/fence/internal/sandbox"
)

// Domain is the policy domain a tool maps to. Add new domains rarely and
// deliberately — the value of this package is a shared vocabulary.
type Domain int

const (
	// DomainUnknown: no mapping; evaluator returns OutcomeSkip.
	DomainUnknown Domain = iota
	// DomainCommand: shell command, backed by sandbox.CheckCommand.
	DomainCommand
	// DomainFilesystemWrite: path, backed by sandbox.CheckWritePath.
	DomainFilesystemWrite
	// DomainNetworkURL: URL, backed by proxy.CheckURL.
	DomainNetworkURL
)

func (d Domain) String() string {
	switch d {
	case DomainCommand:
		return "command"
	case DomainFilesystemWrite:
		return "filesystem.write"
	case DomainNetworkURL:
		return "network.url"
	default:
		return "unknown"
	}
}

// ToolCall is the agent-agnostic tool-call shape adapters convert to.
type ToolCall struct {
	ToolName string
	Params   map[string]any
	// CWD resolves relative paths in DomainFilesystemWrite.
	CWD string
}

// Spec describes how to extract the policy-relevant primitive from a tool's
// raw param map and which domain it belongs to.
type Spec struct {
	Domain Domain
	// Extract pulls the value (command, path, URL) out of params.
	// ok=false (missing or wrong type) → OutcomeSkip, not deny.
	Extract func(params map[string]any) (value string, ok bool)
}

// Table maps tool names to their Spec.
type Table map[string]Spec

// Outcome is the evaluator's verdict. Skip is distinct from Allow because
// command-domain adapters that wrap (`fence -c ...`) should only do so on a
// concrete Allow, never on Skip.
type Outcome int

const (
	OutcomeAllow Outcome = iota
	OutcomeDeny
	OutcomeSkip
)

func (o Outcome) String() string {
	switch o {
	case OutcomeAllow:
		return "allow"
	case OutcomeDeny:
		return "deny"
	case OutcomeSkip:
		return "skip"
	default:
		return fmt.Sprintf("unknown(%d)", int(o))
	}
}

// Decision is the result of an evaluation.
type Decision struct {
	Outcome Outcome
	// Domain is DomainUnknown when the table lookup missed entirely.
	Domain Domain
	// Value is the extracted primitive, set on Allow/Deny so adapters
	// don't have to re-extract from params.
	Value string
	// Reason is the human-readable deny message; empty unless Deny.
	Reason string
	// MatchedRule is the deny pattern (e.g. "git push", "/etc") when
	// available. Empty for default-deny and allow/skip outcomes.
	MatchedRule string
}

// Evaluator is the per-call policy engine. Construct with a dispatch Table
// and the active config; call Evaluate per tool invocation.
type Evaluator struct {
	Table  Table
	Config *config.Config
}

// Evaluate looks up call.ToolName and dispatches to the matching domain
// evaluator. Unknown tools produce OutcomeSkip so adapters can choose their
// own open/closed-world default by post-processing.
func (e *Evaluator) Evaluate(call ToolCall) Decision {
	spec, ok := e.Table[call.ToolName]
	if !ok {
		return Decision{Outcome: OutcomeSkip}
	}
	value, ok := spec.Extract(call.Params)
	if !ok {
		return Decision{Outcome: OutcomeSkip, Domain: spec.Domain}
	}

	switch spec.Domain {
	case DomainCommand:
		if err := sandbox.CheckCommand(value, e.Config); err != nil {
			return commandDeny(value, err)
		}
		return Decision{Outcome: OutcomeAllow, Domain: spec.Domain, Value: value}
	case DomainFilesystemWrite:
		if err := sandbox.CheckWritePath(value, call.CWD, e.Config); err != nil {
			return pathDeny(value, err)
		}
		return Decision{Outcome: OutcomeAllow, Domain: spec.Domain, Value: value}
	case DomainNetworkURL:
		if err := proxy.CheckURL(value, e.Config); err != nil {
			return urlDeny(value, err)
		}
		return Decision{Outcome: OutcomeAllow, Domain: spec.Domain, Value: value}
	default:
		return Decision{Outcome: OutcomeSkip, Domain: spec.Domain, Value: value}
	}
}

func commandDeny(value string, err error) Decision {
	d := Decision{Outcome: OutcomeDeny, Domain: DomainCommand, Value: value, Reason: err.Error()}
	var blocked *sandbox.CommandBlockedError
	if errors.As(err, &blocked) {
		d.MatchedRule = blocked.BlockedPrefix
	}
	// SSHBlockedError has no stable matched-pattern field; its Reason
	// already cites the pattern, so MatchedRule stays empty there.
	return d
}

func pathDeny(value string, err error) Decision {
	d := Decision{Outcome: OutcomeDeny, Domain: DomainFilesystemWrite, Value: value, Reason: err.Error()}
	var blocked *sandbox.PathWriteBlockedError
	if errors.As(err, &blocked) {
		d.MatchedRule = blocked.MatchedRule
	}
	return d
}

func urlDeny(value string, err error) Decision {
	d := Decision{Outcome: OutcomeDeny, Domain: DomainNetworkURL, Value: value, Reason: err.Error()}
	var blocked *proxy.URLBlockedError
	if errors.As(err, &blocked) {
		d.MatchedRule = blocked.MatchedRule
	}
	return d
}

// StringExtractor returns a Spec.Extract that pulls a non-empty string from
// params[key]. Covers the common case of a single-field tool input.
func StringExtractor(key string) func(map[string]any) (string, bool) {
	return func(params map[string]any) (string, bool) {
		if params == nil {
			return "", false
		}
		raw, ok := params[key]
		if !ok {
			return "", false
		}
		text, ok := raw.(string)
		if !ok || text == "" {
			return "", false
		}
		return text, true
	}
}
