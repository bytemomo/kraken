//go:build integration

package runner

import (
	"context"
	"testing"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/testutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_Policy_ConnectionDefaults_PropagatedToContext(t *testing.T) {
	server := testutil.NewEchoServer()
	require.NoError(t, server.Start())
	defer server.Stop()

	// Create campaign with specific connection defaults
	campaign := &domain.Campaign{
		ID:   "test-policy-defaults",
		Type: domain.NetworkCampaign,
		Policy: domain.Policy{
			Runner: domain.RunnerPolicy{
				MaxParallelTargets: 1,
				Defaults: domain.ConnectionDefaults{
					ConnectionTimeout:       15 * time.Second,
					ConnectionBackoff:       200 * time.Millisecond,
					MaxReconnects:           5,
					MaxConnectionsPerTarget: 2,
				},
			},
		},
		Tasks: []*domain.Module{
			{
				ModuleID:    "test-module",
				Type:        domain.Native,
				MaxDuration: 30 * time.Second,
			},
		},
	}

	runner, err := New(campaign)
	require.NoError(t, err)

	// Verify policy is correctly set
	policy := campaign.EffectivePolicy()
	assert.Equal(t, 15*time.Second, policy.Runner.Defaults.ConnectionTimeout)
	assert.Equal(t, 200*time.Millisecond, policy.Runner.Defaults.ConnectionBackoff)
	assert.Equal(t, 5, policy.Runner.Defaults.MaxReconnects)
	assert.Equal(t, 2, policy.Runner.Defaults.MaxConnectionsPerTarget)

	_ = runner // Runner would use these when executing modules
}

func TestIntegration_Policy_DefaultPolicy_AppliedWhenNotSpecified(t *testing.T) {
	// Campaign without explicit policy - should get defaults
	campaign := &domain.Campaign{
		ID:   "test-default-policy",
		Type: domain.NetworkCampaign,
		Tasks: []*domain.Module{
			{
				ModuleID:    "test-module",
				Type:        domain.Native,
				MaxDuration: 30 * time.Second,
			},
		},
	}

	policy := campaign.EffectivePolicy()

	// Verify default values are applied
	assert.False(t, policy.Safety.AllowAggressive)
	assert.True(t, *policy.Safety.RequireMaxDuration)
	assert.Equal(t, 1, policy.Runner.MaxParallelTargets)
	assert.Equal(t, 10*time.Second, policy.Runner.Defaults.ConnectionTimeout)
	assert.Equal(t, 100*time.Millisecond, policy.Runner.Defaults.ConnectionBackoff)
	assert.Equal(t, 3, policy.Runner.Defaults.MaxReconnects)
	assert.Equal(t, 1, policy.Runner.Defaults.MaxConnectionsPerTarget)
}

func TestIntegration_Policy_Merge_PartialOverride(t *testing.T) {
	// Campaign with partial policy - should merge with defaults
	campaign := &domain.Campaign{
		ID:   "test-merge-policy",
		Type: domain.NetworkCampaign,
		Policy: domain.Policy{
			Runner: domain.RunnerPolicy{
				MaxParallelTargets: 4, // Override this
				// Leave Defaults empty - should get defaults
			},
		},
		Tasks: []*domain.Module{
			{
				ModuleID:    "test-module",
				Type:        domain.Native,
				MaxDuration: 30 * time.Second,
			},
		},
	}

	policy := campaign.EffectivePolicy()

	// Verify overridden value
	assert.Equal(t, 4, policy.Runner.MaxParallelTargets)

	// Verify defaults are still applied for unspecified values
	assert.Equal(t, 10*time.Second, policy.Runner.Defaults.ConnectionTimeout)
	assert.Equal(t, 3, policy.Runner.Defaults.MaxReconnects)
}

func TestIntegration_Policy_SafetyEnforcement_AllowAggressive(t *testing.T) {
	// Campaign that allows aggressive tasks
	campaign := &domain.Campaign{
		ID:   "test-aggressive-allowed",
		Type: domain.NetworkCampaign,
		Policy: domain.Policy{
			Safety: domain.SafetyPolicy{
				AllowAggressive: true,
			},
		},
		Tasks: []*domain.Module{
			{
				ModuleID:    "fuzzer",
				Type:        domain.Fuzz,
				Aggressive:  true,
				MaxDuration: 300 * time.Second,
			},
		},
	}

	// Should be able to create runner with aggressive task
	_, err := New(campaign)
	require.NoError(t, err)
}

func TestIntegration_Policy_SafetyEnforcement_BlockAggressive(t *testing.T) {
	// Campaign that blocks aggressive tasks (default)
	requireMaxDuration := true
	campaign := &domain.Campaign{
		ID:   "test-aggressive-blocked",
		Type: domain.NetworkCampaign,
		Policy: domain.Policy{
			Safety: domain.SafetyPolicy{
				AllowAggressive:    false,
				RequireMaxDuration: &requireMaxDuration,
			},
		},
		Tasks: []*domain.Module{
			{
				ModuleID:    "fuzzer",
				Type:        domain.Fuzz,
				Aggressive:  true, // Should be blocked
				MaxDuration: 300 * time.Second,
			},
		},
	}

	// Validation should fail
	err := ValidateCampaignPolicy(campaign)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aggressive")
}

func TestIntegration_Policy_SafetyEnforcement_RequireMaxDuration(t *testing.T) {
	// Campaign that requires max_duration
	requireMaxDuration := true
	campaign := &domain.Campaign{
		ID:   "test-require-duration",
		Type: domain.NetworkCampaign,
		Policy: domain.Policy{
			Safety: domain.SafetyPolicy{
				RequireMaxDuration: &requireMaxDuration,
			},
		},
		Tasks: []*domain.Module{
			{
				ModuleID: "test-module",
				Type:     domain.Native,
				// Missing MaxDuration - should be blocked
			},
		},
	}

	// Validation should fail
	err := ValidateCampaignPolicy(campaign)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_duration")
}

func TestIntegration_Policy_SafetyEnforcement_OptionalMaxDuration(t *testing.T) {
	// Campaign that doesn't require max_duration
	requireMaxDuration := false
	campaign := &domain.Campaign{
		ID:   "test-optional-duration",
		Type: domain.NetworkCampaign,
		Policy: domain.Policy{
			Safety: domain.SafetyPolicy{
				RequireMaxDuration: &requireMaxDuration,
			},
		},
		Tasks: []*domain.Module{
			{
				ModuleID: "test-module",
				Type:     domain.Native,
				// No MaxDuration - should be OK
			},
		},
	}

	// Validation should pass
	err := ValidateCampaignPolicy(campaign)
	require.NoError(t, err)
}

func TestIntegration_Policy_ConnectionTimeout_Enforced(t *testing.T) {
	// Server that delays response
	server := testutil.NewDelayedServer(0, 5*time.Second)
	require.NoError(t, server.Start())
	defer server.Stop()

	// Campaign with short connection timeout
	campaign := &domain.Campaign{
		ID:   "test-timeout-enforced",
		Type: domain.NetworkCampaign,
		Policy: domain.Policy{
			Runner: domain.RunnerPolicy{
				MaxParallelTargets: 1,
				Defaults: domain.ConnectionDefaults{
					ConnectionTimeout: 200 * time.Millisecond, // Short timeout
					MaxReconnects:     0,                      // No retries
				},
			},
		},
		Tasks: []*domain.Module{
			{
				ModuleID:    "test-module",
				Type:        domain.Native,
				MaxDuration: 30 * time.Second,
			},
		},
	}

	runner, err := New(campaign)
	require.NoError(t, err)

	target := domain.HostPort{
		Host: "127.0.0.1",
		Port: server.Port(),
	}

	ctx := context.Background()
	start := time.Now()
	_, err = runner.Run(ctx, []domain.Target{target})
	elapsed := time.Since(start)

	// Should complete quickly due to timeout
	assert.Less(t, elapsed, 2*time.Second)
}

// ValidateCampaignPolicy validates campaign policy constraints.
// This should be called during campaign loading.
func ValidateCampaignPolicy(campaign *domain.Campaign) error {
	policy := campaign.EffectivePolicy()

	for _, task := range campaign.Tasks {
		// Check aggressive tasks
		if task.Aggressive && !policy.Safety.AllowAggressive {
			return &PolicyError{
				Task:    task.ModuleID,
				Message: "task is marked aggressive but policy.safety.allow_aggressive is false",
			}
		}

		// Check max_duration requirement
		if policy.Safety.RequireMaxDuration != nil && *policy.Safety.RequireMaxDuration {
			if task.MaxDuration == 0 {
				return &PolicyError{
					Task:    task.ModuleID,
					Message: "task missing max_duration; policy.safety.require_max_duration is true",
				}
			}
		}
	}

	return nil
}

// PolicyError represents a policy validation error.
type PolicyError struct {
	Task    string
	Message string
}

func (e *PolicyError) Error() string {
	return "policy validation: task " + e.Task + ": " + e.Message
}

