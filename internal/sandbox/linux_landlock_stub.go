//go:build !linux

package sandbox

import "github.com/Use-Tusk/fence/internal/config"

// ApplyLandlockFromConfig is a no-op on non-Linux platforms.
func ApplyLandlockFromConfig(cfg *config.Config, cwd string, socketPaths []string, debug bool) error {
	return nil
}

// ApplyLandlockFromConfigWithExec is a no-op on non-Linux platforms.
func ApplyLandlockFromConfigWithExec(cfg *config.Config, cwd string, socketPaths []string, executePaths []string, debug bool) error {
	return nil
}

// LandlockRuleset is a stub for non-Linux platforms.
type LandlockRuleset struct{}

// NewLandlockRuleset returns nil on non-Linux platforms.
func NewLandlockRuleset(debug bool) (*LandlockRuleset, error) {
	return nil, nil
}

// Initialize is a no-op on non-Linux platforms.
func (l *LandlockRuleset) Initialize() error { return nil }

// AllowRead is a no-op on non-Linux platforms.
func (l *LandlockRuleset) AllowRead(path string) error { return nil }

// AllowWrite is a no-op on non-Linux platforms.
func (l *LandlockRuleset) AllowWrite(path string) error { return nil }

// AllowReadWrite is a no-op on non-Linux platforms.
func (l *LandlockRuleset) AllowReadWrite(path string) error { return nil }

// Apply is a no-op on non-Linux platforms.
func (l *LandlockRuleset) Apply() error { return nil }

// Close is a no-op on non-Linux platforms.
func (l *LandlockRuleset) Close() error { return nil }

// ExpandGlobPatterns returns the input on non-Linux platforms.
func ExpandGlobPatterns(patterns []string) []string {
	return patterns
}

// GenerateLandlockSetupScript returns empty on non-Linux platforms.
func GenerateLandlockSetupScript(allowWrite, denyWrite, denyRead []string, debug bool) string {
	return ""
}
