package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Use-Tusk/fence/internal/config"
)

func TestManagerSetServiceStoresOptions(t *testing.T) {
	cfg := &config.Config{}
	m := NewManager(cfg, false, false)

	opts := ServiceOptions{
		ExposedPorts:   []int{8080, 8081},
		ExecutionModel: ServiceBindsOnHost,
	}
	m.SetService(opts)

	if len(m.service.ExposedPorts) != 2 || m.service.ExposedPorts[0] != 8080 || m.service.ExposedPorts[1] != 8081 {
		t.Errorf("SetService did not preserve ExposedPorts: got %v", m.service.ExposedPorts)
	}
	if m.service.ExecutionModel != ServiceBindsOnHost {
		t.Errorf("SetService did not preserve ExecutionModel: got %v", m.service.ExecutionModel)
	}
}

func TestManagerSetServiceDefaultExecutionModel(t *testing.T) {
	cfg := &config.Config{}
	m := NewManager(cfg, false, false)

	// Zero-value ServiceOptions means ServiceBindsInSandbox (the default
	// for the iota enum).
	m.SetService(ServiceOptions{ExposedPorts: []int{3000}})

	if m.service.ExecutionModel != ServiceBindsInSandbox {
		t.Errorf("default ExecutionModel should be ServiceBindsInSandbox; got %v", m.service.ExecutionModel)
	}
}

func TestManagerExposeHostPathRejectsEmpty(t *testing.T) {
	cfg := &config.Config{}
	m := NewManager(cfg, false, false)

	if err := m.ExposeHostPath("", false); err == nil {
		t.Error("ExposeHostPath(\"\") should return an error")
	}
}

func TestManagerExposeHostPathAccumulates(t *testing.T) {
	cfg := &config.Config{}
	m := NewManager(cfg, false, false)

	tmpDir := t.TempDir()
	pathA := filepath.Join(tmpDir, "a.yml")
	pathB := filepath.Join(tmpDir, "b.yml")
	for _, p := range []string{pathA, pathB} {
		if err := os.WriteFile(p, []byte("hi"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	if err := m.ExposeHostPath(pathA, false); err != nil {
		t.Fatalf("ExposeHostPath(pathA): %v", err)
	}
	if err := m.ExposeHostPath(pathB, true); err != nil {
		t.Fatalf("ExposeHostPath(pathB, writable): %v", err)
	}

	if len(m.exposedHostPaths) != 2 {
		t.Fatalf("expected 2 exposed paths; got %d", len(m.exposedHostPaths))
	}
	if m.exposedHostPaths[0].path != pathA || m.exposedHostPaths[0].writable {
		t.Errorf("first exposure mismatch: %+v", m.exposedHostPaths[0])
	}
	if m.exposedHostPaths[1].path != pathB || !m.exposedHostPaths[1].writable {
		t.Errorf("second exposure mismatch: %+v", m.exposedHostPaths[1])
	}
}
