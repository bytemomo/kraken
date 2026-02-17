package domain

import (
	"testing"
	"time"
)

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy()

	// Safety defaults
	if p.Safety.AllowAggressive {
		t.Error("default AllowAggressive should be false")
	}
	if !p.Safety.RequiresMaxDuration() {
		t.Error("default RequiresMaxDuration should be true")
	}

	// Runner defaults
	if p.Runner.MaxParallelTargets != 1 {
		t.Errorf("default MaxParallelTargets should be 1, got %d", p.Runner.MaxParallelTargets)
	}

	// Connection defaults
	if p.Runner.Defaults.MaxConnectionsPerTarget != 1 {
		t.Errorf("default MaxConnectionsPerTarget should be 1, got %d", p.Runner.Defaults.MaxConnectionsPerTarget)
	}
	if p.Runner.Defaults.ConnectionTimeout != 10*time.Second {
		t.Errorf("default ConnectionTimeout should be 10s, got %v", p.Runner.Defaults.ConnectionTimeout)
	}
	if p.Runner.Defaults.ConnectionBackoff != 100*time.Millisecond {
		t.Errorf("default ConnectionBackoff should be 100ms, got %v", p.Runner.Defaults.ConnectionBackoff)
	}
	if p.Runner.Defaults.MaxReconnects != 3 {
		t.Errorf("default MaxReconnects should be 3, got %d", p.Runner.Defaults.MaxReconnects)
	}
}

func TestSafetyPolicy_RequiresMaxDuration(t *testing.T) {
	tests := []struct {
		name     string
		policy   SafetyPolicy
		expected bool
	}{
		{
			name:     "nil pointer defaults to true",
			policy:   SafetyPolicy{RequireMaxDuration: nil},
			expected: true,
		},
		{
			name:     "explicit true",
			policy:   SafetyPolicy{RequireMaxDuration: boolPtr(true)},
			expected: true,
		},
		{
			name:     "explicit false",
			policy:   SafetyPolicy{RequireMaxDuration: boolPtr(false)},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.policy.RequiresMaxDuration()
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestPolicy_Merge_SafetyAllowAggressive(t *testing.T) {
	defaults := DefaultPolicy()

	// User sets allow_aggressive: true
	userPolicy := Policy{
		Safety: SafetyPolicy{AllowAggressive: true},
	}

	merged := userPolicy.Merge(defaults)

	if !merged.Safety.AllowAggressive {
		t.Error("merged policy should have AllowAggressive=true")
	}
}

func TestPolicy_Merge_SafetyRequireMaxDuration(t *testing.T) {
	defaults := DefaultPolicy()

	// User explicitly disables require_max_duration
	userPolicy := Policy{
		Safety: SafetyPolicy{RequireMaxDuration: boolPtr(false)},
	}

	merged := userPolicy.Merge(defaults)

	if merged.Safety.RequiresMaxDuration() {
		t.Error("merged policy should have RequireMaxDuration=false")
	}
}

func TestPolicy_Merge_RunnerMaxParallelTargets(t *testing.T) {
	defaults := DefaultPolicy()

	userPolicy := Policy{
		Runner: RunnerPolicy{MaxParallelTargets: 8},
	}

	merged := userPolicy.Merge(defaults)

	if merged.Runner.MaxParallelTargets != 8 {
		t.Errorf("expected MaxParallelTargets=8, got %d", merged.Runner.MaxParallelTargets)
	}
}

func TestPolicy_Merge_ConnectionDefaults(t *testing.T) {
	defaults := DefaultPolicy()

	userPolicy := Policy{
		Runner: RunnerPolicy{
			Defaults: ConnectionDefaults{
				ConnectionTimeout: 30 * time.Second,
				ConnectionBackoff: 500 * time.Millisecond,
				MaxReconnects:     5,
			},
		},
	}

	merged := userPolicy.Merge(defaults)

	if merged.Runner.Defaults.ConnectionTimeout != 30*time.Second {
		t.Errorf("expected ConnectionTimeout=30s, got %v", merged.Runner.Defaults.ConnectionTimeout)
	}
	if merged.Runner.Defaults.ConnectionBackoff != 500*time.Millisecond {
		t.Errorf("expected ConnectionBackoff=500ms, got %v", merged.Runner.Defaults.ConnectionBackoff)
	}
	if merged.Runner.Defaults.MaxReconnects != 5 {
		t.Errorf("expected MaxReconnects=5, got %d", merged.Runner.Defaults.MaxReconnects)
	}
	// MaxConnectionsPerTarget should use default since not specified
	if merged.Runner.Defaults.MaxConnectionsPerTarget != 1 {
		t.Errorf("expected MaxConnectionsPerTarget=1 (default), got %d", merged.Runner.Defaults.MaxConnectionsPerTarget)
	}
}

func TestPolicy_Merge_PartialOverride(t *testing.T) {
	defaults := DefaultPolicy()

	// Only override some values
	userPolicy := Policy{
		Runner: RunnerPolicy{
			MaxParallelTargets: 4,
			Defaults: ConnectionDefaults{
				ConnectionTimeout: 5 * time.Second,
				// Other values left at zero - should use defaults
			},
		},
	}

	merged := userPolicy.Merge(defaults)

	// Overridden values
	if merged.Runner.MaxParallelTargets != 4 {
		t.Errorf("expected MaxParallelTargets=4, got %d", merged.Runner.MaxParallelTargets)
	}
	if merged.Runner.Defaults.ConnectionTimeout != 5*time.Second {
		t.Errorf("expected ConnectionTimeout=5s, got %v", merged.Runner.Defaults.ConnectionTimeout)
	}

	// Default values preserved
	if merged.Runner.Defaults.ConnectionBackoff != 100*time.Millisecond {
		t.Errorf("expected ConnectionBackoff=100ms (default), got %v", merged.Runner.Defaults.ConnectionBackoff)
	}
	if merged.Runner.Defaults.MaxReconnects != 3 {
		t.Errorf("expected MaxReconnects=3 (default), got %d", merged.Runner.Defaults.MaxReconnects)
	}
}

func TestPolicy_Merge_EmptyPolicy(t *testing.T) {
	defaults := DefaultPolicy()
	emptyPolicy := Policy{}

	merged := emptyPolicy.Merge(defaults)

	// All defaults should be preserved
	if merged.Safety.AllowAggressive != defaults.Safety.AllowAggressive {
		t.Error("AllowAggressive should match default")
	}
	if merged.Safety.RequiresMaxDuration() != defaults.Safety.RequiresMaxDuration() {
		t.Error("RequiresMaxDuration should match default")
	}
	if merged.Runner.MaxParallelTargets != defaults.Runner.MaxParallelTargets {
		t.Error("MaxParallelTargets should match default")
	}
	if merged.Runner.Defaults.ConnectionTimeout != defaults.Runner.Defaults.ConnectionTimeout {
		t.Error("ConnectionTimeout should match default")
	}
}

func TestConnectionDefaults_ZeroValuesUseDefaults(t *testing.T) {
	defaults := DefaultPolicy()

	// All zeros - should use defaults
	userPolicy := Policy{
		Runner: RunnerPolicy{
			Defaults: ConnectionDefaults{
				MaxConnectionsPerTarget: 0,
				ConnectionTimeout:       0,
				ConnectionBackoff:       0,
				MaxReconnects:           0,
			},
		},
	}

	merged := userPolicy.Merge(defaults)

	if merged.Runner.Defaults.MaxConnectionsPerTarget != 1 {
		t.Errorf("expected default MaxConnectionsPerTarget=1, got %d", merged.Runner.Defaults.MaxConnectionsPerTarget)
	}
	if merged.Runner.Defaults.ConnectionTimeout != 10*time.Second {
		t.Errorf("expected default ConnectionTimeout=10s, got %v", merged.Runner.Defaults.ConnectionTimeout)
	}
	if merged.Runner.Defaults.ConnectionBackoff != 100*time.Millisecond {
		t.Errorf("expected default ConnectionBackoff=100ms, got %v", merged.Runner.Defaults.ConnectionBackoff)
	}
	if merged.Runner.Defaults.MaxReconnects != 3 {
		t.Errorf("expected default MaxReconnects=3, got %d", merged.Runner.Defaults.MaxReconnects)
	}
}

func TestCampaign_EffectivePolicy(t *testing.T) {
	campaign := Campaign{
		ID: "test",
		Policy: Policy{
			Safety: SafetyPolicy{AllowAggressive: true},
			Runner: RunnerPolicy{MaxParallelTargets: 4},
		},
	}

	effective := campaign.EffectivePolicy()

	if !effective.Safety.AllowAggressive {
		t.Error("effective policy should have AllowAggressive=true")
	}
	if effective.Runner.MaxParallelTargets != 4 {
		t.Errorf("expected MaxParallelTargets=4, got %d", effective.Runner.MaxParallelTargets)
	}
	// Defaults should be applied
	if effective.Runner.Defaults.ConnectionTimeout != 10*time.Second {
		t.Errorf("expected default ConnectionTimeout, got %v", effective.Runner.Defaults.ConnectionTimeout)
	}
}

func TestCampaign_EffectivePolicy_EmptyCampaign(t *testing.T) {
	campaign := Campaign{ID: "test"}

	effective := campaign.EffectivePolicy()

	// Should return all defaults
	defaults := DefaultPolicy()
	if effective.Safety.AllowAggressive != defaults.Safety.AllowAggressive {
		t.Error("should use default AllowAggressive")
	}
	if effective.Runner.MaxParallelTargets != defaults.Runner.MaxParallelTargets {
		t.Error("should use default MaxParallelTargets")
	}
}

func boolPtr(b bool) *bool {
	return &b
}
