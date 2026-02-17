package domain

import "time"

// Policy defines campaign-wide safety constraints.
type Policy struct {
	Safety SafetyPolicy `yaml:"safety,omitempty"`
	Runner RunnerPolicy `yaml:"runner,omitempty"`
}

// SafetyPolicy controls OT-safety enforcement.
type SafetyPolicy struct {
	// AllowAggressive permits tasks marked aggressive: true to run.
	// Default: false (aggressive tasks are rejected)
	AllowAggressive bool `yaml:"allow_aggressive,omitempty"`

	// RequireMaxDuration rejects tasks that don't specify max_duration.
	// Default: true
	RequireMaxDuration *bool `yaml:"require_max_duration,omitempty"`
}

// RunnerPolicy controls execution behavior.
type RunnerPolicy struct {
	// MaxParallelTargets bounds concurrent target processing.
	// Default: 1
	MaxParallelTargets int `yaml:"max_parallel_targets,omitempty"`

	// Defaults apply to all tasks unless overridden.
	Defaults ConnectionDefaults `yaml:"defaults,omitempty"`
}

// ConnectionDefaults control connection behavior for OT safety.
type ConnectionDefaults struct {
	// MaxConnectionsPerTarget bounds concurrent connections to one target.
	// Default: 1 (sequential - safest for OT)
	MaxConnectionsPerTarget int `yaml:"max_connections_per_target,omitempty"`

	// ConnectionTimeout is the dial timeout for new connections.
	// Default: 10s
	ConnectionTimeout time.Duration `yaml:"connection_timeout,omitempty"`

	// ConnectionBackoff is minimum delay between connection attempts.
	// Default: 100ms
	ConnectionBackoff time.Duration `yaml:"connection_backoff,omitempty"`

	// MaxReconnects limits retry attempts on connection failure.
	// Default: 3
	MaxReconnects int `yaml:"max_reconnects,omitempty"`

	// ConnSem is a runtime-only semaphore that bounds concurrent connections per target.
	// Initialized by the runner; not serialized.
	ConnSem chan struct{} `yaml:"-" json:"-"`
}

// RequiresMaxDuration returns true if tasks must specify max_duration.
func (s *SafetyPolicy) RequiresMaxDuration() bool {
	if s.RequireMaxDuration == nil {
		return true // Default: required
	}
	return *s.RequireMaxDuration
}

// DefaultPolicy returns a policy with safe defaults.
func DefaultPolicy() Policy {
	requireMaxDuration := true
	return Policy{
		Safety: SafetyPolicy{
			AllowAggressive:    false,
			RequireMaxDuration: &requireMaxDuration,
		},
		Runner: RunnerPolicy{
			MaxParallelTargets: 1,
			Defaults: ConnectionDefaults{
				MaxConnectionsPerTarget: 1,
				ConnectionTimeout:       10 * time.Second,
				ConnectionBackoff:       100 * time.Millisecond,
				MaxReconnects:           3,
			},
		},
	}
}

// Merge combines this policy with defaults, preferring explicit values.
func (p *Policy) Merge(defaults Policy) Policy {
	result := defaults

	// Safety
	if p.Safety.AllowAggressive {
		result.Safety.AllowAggressive = true
	}
	if p.Safety.RequireMaxDuration != nil {
		result.Safety.RequireMaxDuration = p.Safety.RequireMaxDuration
	}

	// Runner
	if p.Runner.MaxParallelTargets > 0 {
		result.Runner.MaxParallelTargets = p.Runner.MaxParallelTargets
	}
	if p.Runner.Defaults.MaxConnectionsPerTarget > 0 {
		result.Runner.Defaults.MaxConnectionsPerTarget = p.Runner.Defaults.MaxConnectionsPerTarget
	}
	if p.Runner.Defaults.ConnectionTimeout > 0 {
		result.Runner.Defaults.ConnectionTimeout = p.Runner.Defaults.ConnectionTimeout
	}
	if p.Runner.Defaults.ConnectionBackoff > 0 {
		result.Runner.Defaults.ConnectionBackoff = p.Runner.Defaults.ConnectionBackoff
	}
	if p.Runner.Defaults.MaxReconnects > 0 {
		result.Runner.Defaults.MaxReconnects = p.Runner.Defaults.MaxReconnects
	}

	return result
}
