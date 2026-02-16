package configschema

import (
	"os"
	"path/filepath"
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

func schemaFilePath(t *testing.T) string {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("failed to resolve caller path")
	}

	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	return filepath.Join(repoRoot, "docs", "schema", "fence.schema.json")
}
