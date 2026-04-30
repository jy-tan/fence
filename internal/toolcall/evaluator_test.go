package toolcall

import (
	"testing"

	"github.com/Use-Tusk/fence/internal/config"
)

// fixtureTable mirrors the shape an adapter would build. Keeping it close to
// hermesDispatchTable in production code so this test catches regressions in
// the public Spec / StringExtractor surface.
func fixtureTable() Table {
	return Table{
		"shell":   {Domain: DomainCommand, Extract: StringExtractor("cmd")},
		"writer":  {Domain: DomainFilesystemWrite, Extract: StringExtractor("path")},
		"fetcher": {Domain: DomainNetworkURL, Extract: StringExtractor("url")},
	}
}

func TestEvaluator_UnknownToolSkips(t *testing.T) {
	ev := &Evaluator{Table: fixtureTable(), Config: config.Default()}
	dec := ev.Evaluate(ToolCall{ToolName: "not_listed", Params: map[string]any{}})
	if dec.Outcome != OutcomeSkip {
		t.Fatalf("expected skip for unknown tool, got %v", dec.Outcome)
	}
	if dec.Domain != DomainUnknown {
		t.Errorf("expected DomainUnknown for unmapped tool, got %v", dec.Domain)
	}
}

func TestEvaluator_MissingFieldSkips(t *testing.T) {
	ev := &Evaluator{Table: fixtureTable(), Config: config.Default()}
	// 'shell' is mapped, but its extractor needs `cmd` and we omit it.
	dec := ev.Evaluate(ToolCall{ToolName: "shell", Params: map[string]any{}})
	if dec.Outcome != OutcomeSkip {
		t.Fatalf("expected skip when extractor returns ok=false, got %v", dec.Outcome)
	}
	if dec.Domain != DomainCommand {
		t.Errorf("expected domain to be set even when skipping, got %v", dec.Domain)
	}
}

func TestEvaluator_CommandDeny(t *testing.T) {
	cfg := &config.Config{
		Command: config.CommandConfig{Deny: []string{"git push"}},
	}
	ev := &Evaluator{Table: fixtureTable(), Config: cfg}
	dec := ev.Evaluate(ToolCall{
		ToolName: "shell",
		Params:   map[string]any{"cmd": "git push origin main"},
	})
	if dec.Outcome != OutcomeDeny {
		t.Fatalf("expected deny, got %v: %s", dec.Outcome, dec.Reason)
	}
	if dec.MatchedRule != "git push" {
		t.Errorf("expected MatchedRule=git push, got %q", dec.MatchedRule)
	}
}

func TestEvaluator_CommandAllow(t *testing.T) {
	cfg := &config.Config{
		Command: config.CommandConfig{Deny: []string{"git push"}},
	}
	ev := &Evaluator{Table: fixtureTable(), Config: cfg}
	dec := ev.Evaluate(ToolCall{
		ToolName: "shell",
		Params:   map[string]any{"cmd": "git status"},
	})
	if dec.Outcome != OutcomeAllow {
		t.Fatalf("expected allow, got %v: %s", dec.Outcome, dec.Reason)
	}
	if dec.Value != "git status" {
		t.Errorf("expected Value to round-trip the command, got %q", dec.Value)
	}
}

func TestEvaluator_FilesystemWrite(t *testing.T) {
	cfg := &config.Config{
		Filesystem: config.FilesystemConfig{
			AllowWrite: []string{"/workspace"},
			DenyWrite:  []string{"/workspace/secrets"},
		},
	}
	ev := &Evaluator{Table: fixtureTable(), Config: cfg}

	allow := ev.Evaluate(ToolCall{
		ToolName: "writer",
		Params:   map[string]any{"path": "/workspace/main.go"},
	})
	if allow.Outcome != OutcomeAllow {
		t.Fatalf("expected allow, got %v: %s", allow.Outcome, allow.Reason)
	}

	deny := ev.Evaluate(ToolCall{
		ToolName: "writer",
		Params:   map[string]any{"path": "/workspace/secrets/db.json"},
	})
	if deny.Outcome != OutcomeDeny {
		t.Fatalf("expected deny, got %v", deny.Outcome)
	}
	if deny.MatchedRule != "/workspace/secrets" {
		t.Errorf("expected matched rule /workspace/secrets, got %q", deny.MatchedRule)
	}
}

func TestEvaluator_NetworkURL(t *testing.T) {
	cfg := &config.Config{
		Network: config.NetworkConfig{
			AllowedDomains: []string{"example.com"},
		},
	}
	ev := &Evaluator{Table: fixtureTable(), Config: cfg}
	allow := ev.Evaluate(ToolCall{
		ToolName: "fetcher",
		Params:   map[string]any{"url": "https://example.com/x"},
	})
	if allow.Outcome != OutcomeAllow {
		t.Fatalf("expected allow, got %v: %s", allow.Outcome, allow.Reason)
	}
	deny := ev.Evaluate(ToolCall{
		ToolName: "fetcher",
		Params:   map[string]any{"url": "https://blocked.test/"},
	})
	if deny.Outcome != OutcomeDeny {
		t.Fatalf("expected deny, got %v", deny.Outcome)
	}
}

func TestStringExtractor(t *testing.T) {
	extract := StringExtractor("foo")
	cases := []struct {
		name   string
		params map[string]any
		want   string
		ok     bool
	}{
		{"present-string", map[string]any{"foo": "bar"}, "bar", true},
		{"empty-string-skips", map[string]any{"foo": ""}, "", false},
		{"wrong-type-skips", map[string]any{"foo": 42}, "", false},
		{"missing-skips", map[string]any{"baz": "bar"}, "", false},
		{"nil-params-skips", nil, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := extract(tc.params)
			if got != tc.want || ok != tc.ok {
				t.Errorf("extract(%v) = (%q, %v), want (%q, %v)", tc.params, got, ok, tc.want, tc.ok)
			}
		})
	}
}
