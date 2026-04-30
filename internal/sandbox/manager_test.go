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
		Exposures: []ExposedPort{
			{BindAddress: "127.0.0.1", Port: 8080},
			{BindAddress: "0.0.0.0", Port: 8081},
		},
		ExecutionModel: ServiceBindsOnHost,
	}
	m.SetService(opts)

	want := opts.Exposures
	got := m.service.Exposures
	if !exposuresEqual(got, want) {
		t.Errorf("SetService did not preserve Exposures: got %+v want %+v", got, want)
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
	m.SetService(ServiceOptions{Exposures: []ExposedPort{LoopbackPort(3000)}})

	if m.service.ExecutionModel != ServiceBindsInSandbox {
		t.Errorf("default ExecutionModel should be ServiceBindsInSandbox; got %v", m.service.ExecutionModel)
	}
}

func TestLoopbackPort(t *testing.T) {
	got := LoopbackPort(3000)
	want := ExposedPort{BindAddress: DefaultExposedBindAddress, Port: 3000}
	if got != want {
		t.Errorf("LoopbackPort(3000) = %+v, want %+v", got, want)
	}
}

func TestServiceOptionsResolvedExposures_FillsEmptyBindAddress(t *testing.T) {
	opts := ServiceOptions{
		Exposures: []ExposedPort{
			{Port: 3000}, // empty bind -> loopback default
			{BindAddress: "0.0.0.0", Port: 8080},
			{BindAddress: "::1", Port: 9090},
		},
	}
	got := opts.resolvedExposures()
	want := []ExposedPort{
		{BindAddress: "127.0.0.1", Port: 3000},
		{BindAddress: "0.0.0.0", Port: 8080},
		{BindAddress: "::1", Port: 9090},
	}
	if !exposuresEqual(got, want) {
		t.Errorf("resolvedExposures() = %+v, want %+v", got, want)
	}
}

func TestServiceOptionsResolvedExposures_PreservesExplicitBindAddresses(t *testing.T) {
	opts := ServiceOptions{
		Exposures: []ExposedPort{
			{BindAddress: "192.168.1.10", Port: 8080},
			{BindAddress: "127.0.0.1", Port: 3000},
		},
	}
	got := opts.resolvedExposures()
	if !exposuresEqual(got, opts.Exposures) {
		t.Errorf("resolvedExposures() = %+v, want %+v (no normalization needed)", got, opts.Exposures)
	}
}

func TestServiceOptionsResolvedExposures_EmptyReturnsNil(t *testing.T) {
	if got := (ServiceOptions{}).resolvedExposures(); got != nil {
		t.Errorf("resolvedExposures() on empty options = %+v, want nil", got)
	}
}

func TestServiceOptionsResolvedPorts_OrderMatchesExposures(t *testing.T) {
	opts := ServiceOptions{
		Exposures: []ExposedPort{
			{BindAddress: "0.0.0.0", Port: 8080},
			{Port: 9090},
			LoopbackPort(3000),
		},
	}
	got := opts.resolvedPorts()
	want := []int{8080, 9090, 3000}
	if len(got) != len(want) {
		t.Fatalf("resolvedPorts() returned %d entries, want %d (got=%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("resolvedPorts()[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

func exposuresEqual(a, b []ExposedPort) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
