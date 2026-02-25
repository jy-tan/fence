package sandbox

import "github.com/Use-Tusk/fence/internal/config"

// hasWildcardAllowedDomain reports whether direct network access should be
// allowed by sandbox-level network restrictions.
func hasWildcardAllowedDomain(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, d := range cfg.Network.AllowedDomains {
		if d == "*" {
			return true
		}
	}
	return false
}
