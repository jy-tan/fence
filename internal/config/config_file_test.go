package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalConfigJSON_OmitsEmptySections(t *testing.T) {
	cfg := &Config{}
	cfg.Command.Allow = []string{"npm install"}

	data, err := MarshalConfigJSON(cfg)
	require.NoError(t, err)

	output := string(data)
	assert.Contains(t, output, `"npm install"`)
	assert.NotContains(t, output, `"network"`)
	assert.NotContains(t, output, `"filesystem"`)
}

func TestFormatConfigForFile_WithHeaderLines(t *testing.T) {
	cfg := &Config{}
	cfg.Extends = "code"

	output, err := FormatConfigForFile(cfg, FileWriteOptions{
		HeaderLines: []string{
			"// line 1",
			"// line 2",
		},
	})
	require.NoError(t, err)

	assert.Contains(t, output, "// line 1\n// line 2\n{")
	assert.Contains(t, output, `"extends": "code"`)
}

func TestWriteConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "fence.json")

	cfg := &Config{}
	cfg.Command.Deny = []string{"curl"}

	err := WriteConfigFile(cfg, path, FileWriteOptions{})
	require.NoError(t, err)

	data, err := os.ReadFile(path) //nolint:gosec // reading test output file
	require.NoError(t, err)
	assert.Contains(t, string(data), `"curl"`)
}
