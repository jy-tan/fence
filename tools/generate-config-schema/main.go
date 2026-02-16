package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Use-Tusk/fence/internal/configschema"
)

func main() {
	data, err := configschema.Generate()
	if err != nil {
		fail("generate schema", err)
	}

	outputPath := filepath.Join("docs", "schema", "fence.schema.json")
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o750); err != nil {
		fail("create schema directory", err)
	}
	if err := os.WriteFile(outputPath, append(data, '\n'), 0o600); err != nil {
		fail("write schema file", err)
	}
}

func fail(step string, err error) {
	_, _ = fmt.Fprintf(os.Stderr, "failed to %s: %v\n", step, err)
	os.Exit(1)
}
