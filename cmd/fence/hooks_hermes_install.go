package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fencesandbox/fence/internal/sandbox"
	"gopkg.in/yaml.v3"
)

// hermesInstallEntry is one (matcher, command) pair Fence writes into the
// Hermes config under hooks.pre_tool_call. The matcher is a Hermes-style
// regex applied to tool_name (see hermes-agent/agent/shell_hooks.py:132 —
// uses re.fullmatch). We emit one entry per tool group so a `hermes hooks
// list` reads naturally and so users who only opt into a subset (say,
// terminal but not write_file) can prune individual entries.
type hermesInstallEntry struct {
	Matcher string
	Tools   []string
}

// hermesInstallEntries returns the install plan in deterministic order.
// Each tool maps to a regex that fullmatches its name. Multi-tool groups
// share a matcher built from `^(a|b|c)$` for readability when the user
// runs `hermes hooks list`.
func hermesInstallEntries() []hermesInstallEntry {
	groups := map[string][]string{}
	for tool := range hermesDispatchTable {
		// Group tools by domain so the matcher and the deny shape
		// stay consistent. We don't *need* per-domain grouping for
		// correctness — Fence dispatches on tool name regardless —
		// but it gives users a cleaner picture of what each entry
		// is for.
		domain := hermesDispatchTable[tool].Domain.String()
		groups[domain] = append(groups[domain], tool)
	}
	domains := make([]string, 0, len(groups))
	for d := range groups {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	entries := make([]hermesInstallEntry, 0, len(domains))
	for _, d := range domains {
		tools := groups[d]
		sort.Strings(tools)
		entries = append(entries, hermesInstallEntry{
			Matcher: hermesMatcherFor(tools),
			Tools:   tools,
		})
	}
	return entries
}

func hermesMatcherFor(tools []string) string {
	if len(tools) == 1 {
		return tools[0]
	}
	return "^(" + strings.Join(tools, "|") + ")$"
}

func hermesHookCommandWithOptions(hookOptions hookFenceOptions) string {
	args := []string{"fence", hermesPreToolUseMode}
	args = append(args, hookOptions.fenceArgs()...)
	return sandbox.ShellQuote(args)
}

func defaultHermesConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".hermes", "config.yaml")
}

// hermesEmptyPolicyAdvice returns advisory lines about which Hermes-gated
// domains will hard-deny under the active config, or nil when the policy
// covers all of them. Hook mode is deny-by-default for parity with wrap
// mode, so an `command.deny`-only fence.json would silently start denying
// every write_file/web_extract call after install — surfacing this at
// install time saves the user a debugging round-trip.
//
// hookOptions is the resolved policy pin (--settings / --template) that
// will be embedded in the hook command line; we evaluate against the same
// resolution so the warning matches runtime behavior.
func hermesEmptyPolicyAdvice(hookOptions hookFenceOptions) []string {
	audit, err := loadActiveConfigAudit("", hookOptions.SettingsPath, hookOptions.TemplateName)
	if err != nil || audit == nil || audit.Config == nil {
		// If config resolution itself failed, the hook will surface
		// the error at runtime; skip the install-time hint.
		return nil
	}
	cfg := audit.Config

	var blocked []string
	if len(cfg.Filesystem.AllowWrite) == 0 {
		blocked = append(blocked, "filesystem.allowWrite is empty: write_file and patch will be denied")
	}
	if len(cfg.Network.AllowedDomains) == 0 {
		blocked = append(blocked, "network.allowedDomains is empty: web_extract will be denied")
	}
	if len(blocked) == 0 {
		return nil
	}
	blocked = append(
		blocked,
		"To start with sane defaults for messaging-shaped agents, run:",
		"  fence hooks install --hermes --template hermes",
	)
	return blocked
}

// writeHermesHooksConfig prints the snippet a user can copy into their
// hermes config.yaml manually. Mirrors writeOpencodeHooksConfig's intent:
// "here is the YAML you'd paste".
func writeHermesHooksConfig(w io.Writer, hookOptions hookFenceOptions) error {
	cmd := hermesHookCommandWithOptions(hookOptions)
	root := newYAMLMappingNode()
	hooks := newYAMLMappingNode()
	addYAMLMapEntry(root, "hooks", hooks)

	preToolUse := newYAMLSequenceNode()
	for _, entry := range hermesInstallEntries() {
		preToolUse.Content = append(preToolUse.Content, buildHermesPreToolUseHookNode(entry, cmd))
	}
	addYAMLMapEntry(hooks, "pre_tool_call", preToolUse)

	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		_ = enc.Close()
		return err
	}
	return enc.Close()
}

// installHermesHook writes the Fence-owned entries into the user's Hermes
// config.yaml. Existing user-authored hooks (and unrelated config keys) are
// preserved by round-tripping through yaml.Node.
//
// Returns changed=true when the file was modified.
func installHermesHook(path string, hookOptions hookFenceOptions) (bool, error) {
	desiredCmd := hermesHookCommandWithOptions(hookOptions)
	root, existed, err := loadHermesConfigDocument(path)
	if err != nil {
		return false, err
	}

	hooksNode := ensureYAMLMappingChild(root, "hooks")
	preToolUseNode := ensureYAMLSequenceChild(hooksNode, "pre_tool_call")

	preToolUseNode.Content = removeFenceHermesEntries(preToolUseNode.Content)

	for _, entry := range hermesInstallEntries() {
		preToolUseNode.Content = append(preToolUseNode.Content, buildHermesPreToolUseHookNode(entry, desiredCmd))
	}

	if err := writeHermesConfigDocument(path, root); err != nil {
		return false, err
	}
	if !existed {
		// First write — definitely a change.
		return true, nil
	}
	// We don't compare byte-for-byte because the YAML encoder may have
	// re-indented or reflowed even when the semantic content is
	// unchanged from the user's perspective. Treating "wrote the file"
	// as "changed" matches the OpenCode plugin install behaviour.
	return true, nil
}

// uninstallHermesHook removes the Fence-owned entries from the user's
// Hermes config.yaml. Returns changed=true when entries were removed.
func uninstallHermesHook(path string) (bool, error) {
	root, existed, err := loadHermesConfigDocument(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if !existed {
		return false, nil
	}

	hooksNode := findYAMLMappingChild(root, "hooks")
	if hooksNode == nil {
		return false, nil
	}
	preToolUseNode := findYAMLSequenceChild(hooksNode, "pre_tool_call")
	if preToolUseNode == nil {
		return false, nil
	}

	originalLen := len(preToolUseNode.Content)
	preToolUseNode.Content = removeFenceHermesEntries(preToolUseNode.Content)
	if len(preToolUseNode.Content) == originalLen {
		return false, nil
	}

	// Drop empty containers so we leave the file clean.
	if len(preToolUseNode.Content) == 0 {
		removeYAMLMapEntry(hooksNode, "pre_tool_call")
	}
	if isEmptyMapping(hooksNode) {
		removeYAMLMapEntry(root, "hooks")
	}

	if err := writeHermesConfigDocument(path, root); err != nil {
		return false, err
	}
	return true, nil
}

// loadHermesConfigDocument reads and parses ~/.hermes/config.yaml as a
// yaml.Node so we can preserve user content on round-trip. Missing files
// produce an empty mapping node and existed=false.
func loadHermesConfigDocument(path string) (root *yaml.Node, existed bool, err error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-provided path
	if err != nil {
		if os.IsNotExist(err) {
			return newYAMLMappingNode(), false, nil
		}
		return nil, false, fmt.Errorf("failed to read Hermes config: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return newYAMLMappingNode(), true, nil
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, true, fmt.Errorf("invalid YAML in Hermes config: %w", err)
	}
	root = unwrapYAMLDocument(&doc)
	if root == nil || root.Kind == 0 {
		return newYAMLMappingNode(), true, nil
	}
	if root.Kind != yaml.MappingNode {
		return nil, true, fmt.Errorf("hermes config root must be a YAML mapping (got %s)", yamlKindName(root.Kind))
	}
	return root, true, nil
}

func writeHermesConfigDocument(path string, root *yaml.Node) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("failed to create Hermes config directory: %w", err)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		_ = enc.Close()
		return fmt.Errorf("failed to marshal Hermes config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("failed to close Hermes YAML encoder: %w", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("failed to write Hermes config: %w", err)
	}
	return nil
}

// buildHermesPreToolUseHookNode builds a YAML mapping node like
//
//	{ matcher: "^(write_file|patch)$", command: "fence --hermes-pre-tool-use" }
//
// Using yaml.Node directly lets us emit deterministic key order
// (matcher before command, matching the Hermes docs example) which makes
// `git diff` on hand-edited configs less noisy.
func buildHermesPreToolUseHookNode(entry hermesInstallEntry, command string) *yaml.Node {
	node := newYAMLMappingNode()
	addYAMLMapEntry(node, "matcher", scalarString(entry.Matcher))
	addYAMLMapEntry(node, "command", scalarString(command))
	return node
}

// removeFenceHermesEntries filters out any hook entry whose `command` field
// invokes `fence --hermes-pre-tool-use` (with or without a path prefix).
// User-authored entries are preserved.
func removeFenceHermesEntries(items []*yaml.Node) []*yaml.Node {
	filtered := items[:0]
	for _, item := range items {
		if !isFenceHermesEntry(item) {
			filtered = append(filtered, item)
		}
	}
	out := make([]*yaml.Node, len(filtered))
	copy(out, filtered)
	return out
}

func isFenceHermesEntry(item *yaml.Node) bool {
	if item == nil || item.Kind != yaml.MappingNode {
		return false
	}
	cmd := mappingScalarValue(item, "command")
	if cmd == "" {
		return false
	}
	return containsHelperMode(cmd, hermesPreToolUseMode)
}

// ----- yaml.Node helpers --------------------------------------------------
//
// The yaml.v3 API expresses documents as a tree of nodes. We need just
// enough plumbing to (a) round-trip user content losslessly and (b) make
// targeted edits to a single mapping path. Keeping these helpers in this
// file rather than a shared util file because no other Fence integration
// edits YAML today; promote when the second one lands.

func newYAMLMappingNode() *yaml.Node {
	return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
}

func newYAMLSequenceNode() *yaml.Node {
	return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
}

func scalarString(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

func unwrapYAMLDocument(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		return node.Content[0]
	}
	return node
}

func addYAMLMapEntry(mapping *yaml.Node, key string, value *yaml.Node) {
	mapping.Content = append(mapping.Content, scalarString(key), value)
}

// ensureYAMLMappingChild returns the existing mapping value for key under
// mapping, creating an empty mapping (and inserting it) when absent. If
// the key exists with a non-mapping value we replace it — the alternative
// (returning an error) makes the install path complain about a config
// drift we can fix in place.
func ensureYAMLMappingChild(mapping *yaml.Node, key string) *yaml.Node {
	if v := findYAMLMappingChild(mapping, key); v != nil {
		return v
	}
	if v := findYAMLChild(mapping, key); v != nil {
		// Replace non-mapping value in place.
		v.Kind = yaml.MappingNode
		v.Tag = "!!map"
		v.Content = nil
		v.Value = ""
		return v
	}
	child := newYAMLMappingNode()
	addYAMLMapEntry(mapping, key, child)
	return child
}

func ensureYAMLSequenceChild(mapping *yaml.Node, key string) *yaml.Node {
	if v := findYAMLSequenceChild(mapping, key); v != nil {
		return v
	}
	if v := findYAMLChild(mapping, key); v != nil {
		v.Kind = yaml.SequenceNode
		v.Tag = "!!seq"
		v.Content = nil
		v.Value = ""
		return v
	}
	child := newYAMLSequenceNode()
	addYAMLMapEntry(mapping, key, child)
	return child
}

func findYAMLChild(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		k := mapping.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func findYAMLMappingChild(mapping *yaml.Node, key string) *yaml.Node {
	v := findYAMLChild(mapping, key)
	if v == nil || v.Kind != yaml.MappingNode {
		return nil
	}
	return v
}

func findYAMLSequenceChild(mapping *yaml.Node, key string) *yaml.Node {
	v := findYAMLChild(mapping, key)
	if v == nil || v.Kind != yaml.SequenceNode {
		return nil
	}
	return v
}

func removeYAMLMapEntry(mapping *yaml.Node, key string) {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		k := mapping.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == key {
			mapping.Content = append(mapping.Content[:i], mapping.Content[i+2:]...)
			return
		}
	}
}

func mappingScalarValue(mapping *yaml.Node, key string) string {
	v := findYAMLChild(mapping, key)
	if v == nil || v.Kind != yaml.ScalarNode {
		return ""
	}
	return v.Value
}

func isEmptyMapping(mapping *yaml.Node) bool {
	return mapping != nil && mapping.Kind == yaml.MappingNode && len(mapping.Content) == 0
}

func yamlKindName(kind yaml.Kind) string {
	switch kind {
	case yaml.DocumentNode:
		return "document"
	case yaml.SequenceNode:
		return "sequence"
	case yaml.MappingNode:
		return "mapping"
	case yaml.ScalarNode:
		return "scalar"
	case yaml.AliasNode:
		return "alias"
	default:
		return fmt.Sprintf("unknown(%d)", int(kind))
	}
}
