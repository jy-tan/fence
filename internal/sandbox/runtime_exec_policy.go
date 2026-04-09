package sandbox

import "github.com/Use-Tusk/fence/internal/config"

func effectiveRuntimeExecPolicy(cfg *config.Config) config.RuntimeExecPolicy {
	if cfg == nil {
		return config.RuntimeExecPolicyPath
	}
	return cfg.Command.EffectiveRuntimeExecPolicy()
}
