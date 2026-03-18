package configschema

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestGeneratedSchemaIsInSync(t *testing.T) {
	generated, err := Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	expectedPath := schemaFilePath(t)
	expected, err := os.ReadFile(expectedPath) //nolint:gosec // reading repo fixture in tests
	if err != nil {
		t.Fatalf("failed to read schema file: %v", err)
	}

	generated = append(generated, '\n')
	if string(expected) != string(generated) {
		t.Fatalf("schema file is stale: run `go run ./tools/generate-config-schema`")
	}
}

func TestGenerate_DevicesSchemaConstraints(t *testing.T) {
	generated, err := Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	var document map[string]any
	if err := json.Unmarshal(generated, &document); err != nil {
		t.Fatalf("failed to parse generated schema: %v", err)
	}

	properties := nestedMap(t, document, "properties")
	devices := nestedMap(t, properties, "devices")
	deviceProperties := nestedMap(t, devices, "properties")

	mode := nestedMap(t, deviceProperties, "mode")
	if got, want := mode["enum"], []any{"auto", "minimal", "host"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("mode enum = %#v, want %#v", got, want)
	}

	allow := nestedMap(t, deviceProperties, "allow")
	items := nestedMap(t, allow, "items")
	if got, want := items["pattern"], "^/dev/.+"; got != want {
		t.Fatalf("allow item pattern = %#v, want %#v", got, want)
	}
}

func nestedMap(t *testing.T, value map[string]any, key string) map[string]any {
	t.Helper()

	nested, ok := value[key].(map[string]any)
	if !ok {
		t.Fatalf("key %q is not an object: %#v", key, value[key])
	}
	return nested
}

func schemaFilePath(t *testing.T) string {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("failed to resolve caller path")
	}

	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	return filepath.Join(repoRoot, "docs", "schema", "fence.schema.json")
}
