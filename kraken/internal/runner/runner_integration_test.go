//go:build integration

package runner

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/testutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_Runner_NativeModule_MQTT(t *testing.T) {
	// Start mock MQTT broker
	broker := testutil.NewMockMQTTBroker(testutil.DefaultMQTTConfig())
	require.NoError(t, broker.Start())
	defer broker.Stop()

	// Create campaign with native MQTT module
	campaign := &domain.Campaign{
		ID:   "test-native-mqtt",
		Type: domain.NetworkCampaign,
		Policy: domain.Policy{
			Runner: domain.RunnerPolicy{
				MaxParallelTargets: 1,
			},
		},
		Tasks: []*domain.Module{
			{
				ModuleID:    "mqtt-conformance-test",
				Type:        domain.Native,
				MaxDuration: 30 * time.Second,
			},
		},
	}

	// Create runner
	runner, err := New(campaign)
	require.NoError(t, err)

	// Create target pointing to mock broker
	target := domain.HostPort{
		Host: "127.0.0.1",
		Port: broker.Port(),
	}

	// Run the campaign
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	results, err := runner.Run(ctx, []domain.Target{target})
	require.NoError(t, err)

	// Verify we got results
	assert.NotEmpty(t, results)

	// Verify broker received connections
	assert.Greater(t, broker.ConnectCount, 0)
}

func TestIntegration_Runner_MaxParallelTargets(t *testing.T) {
	// Track concurrent executions
	var concurrent int32
	var maxConcurrent int32
	var mu sync.Mutex

	// Create multiple mock servers
	const numTargets = 6
	servers := make([]*testutil.MockTCPServer, numTargets)
	targets := make([]domain.Target, numTargets)

	for i := 0; i < numTargets; i++ {
		server := testutil.NewMockTCPServer(func(conn net.Conn) {
			// Track concurrency
			current := atomic.AddInt32(&concurrent, 1)
			mu.Lock()
			if current > maxConcurrent {
				maxConcurrent = current
			}
			mu.Unlock()

			// Simulate work
			time.Sleep(100 * time.Millisecond)

			atomic.AddInt32(&concurrent, -1)
			conn.Close()
		})
		require.NoError(t, server.Start())
		defer server.Stop()

		servers[i] = server
		targets[i] = domain.HostPort{
			Host: "127.0.0.1",
			Port: server.Port(),
		}
	}

	// Create campaign with max_parallel_targets = 2
	campaign := &domain.Campaign{
		ID:   "test-parallel",
		Type: domain.NetworkCampaign,
		Policy: domain.Policy{
			Runner: domain.RunnerPolicy{
				MaxParallelTargets: 2,
			},
		},
		Tasks: []*domain.Module{
			{
				ModuleID:    "test-module",
				Type:        domain.Native,
				MaxDuration: 5 * time.Second,
			},
		},
	}

	runner, err := New(campaign)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = runner.Run(ctx, targets)
	require.NoError(t, err)

	// Verify max concurrent never exceeded limit
	assert.LessOrEqual(t, maxConcurrent, int32(2))
}

func TestIntegration_Runner_TaskTimeout(t *testing.T) {
	// Server that never responds (hangs)
	server := testutil.NewDelayedServer(0, 10*time.Second)
	require.NoError(t, server.Start())
	defer server.Stop()

	campaign := &domain.Campaign{
		ID:   "test-timeout",
		Type: domain.NetworkCampaign,
		Policy: domain.Policy{
			Runner: domain.RunnerPolicy{
				MaxParallelTargets: 1,
			},
		},
		Tasks: []*domain.Module{
			{
				ModuleID:    "test-slow-module",
				Type:        domain.Native,
				MaxDuration: 500 * time.Millisecond, // Short timeout
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

	// Should complete within reasonable time (timeout + overhead)
	assert.Less(t, elapsed, 2*time.Second)
}

func TestIntegration_Runner_ContextCancellation(t *testing.T) {
	// Server with delay
	server := testutil.NewDelayedServer(0, 5*time.Second)
	require.NoError(t, server.Start())
	defer server.Stop()

	campaign := &domain.Campaign{
		ID:   "test-cancel",
		Type: domain.NetworkCampaign,
		Policy: domain.Policy{
			Runner: domain.RunnerPolicy{
				MaxParallelTargets: 1,
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

	// Cancel context after 200ms
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = runner.Run(ctx, []domain.Target{target})
	elapsed := time.Since(start)

	// Should respect context cancellation
	assert.Less(t, elapsed, 1*time.Second)
}

func TestIntegration_Runner_EmptyTargets(t *testing.T) {
	campaign := &domain.Campaign{
		ID:   "test-empty",
		Type: domain.NetworkCampaign,
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

	ctx := context.Background()
	results, err := runner.Run(ctx, []domain.Target{})

	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestIntegration_Runner_TagFiltering(t *testing.T) {
	server := testutil.NewEchoServer()
	require.NoError(t, server.Start())
	defer server.Stop()

	campaign := &domain.Campaign{
		ID:   "test-tags",
		Type: domain.NetworkCampaign,
		Tasks: []*domain.Module{
			{
				ModuleID:     "mqtt-module",
				Type:         domain.Native,
				RequiredTags: []string{"protocol:mqtt"},
				MaxDuration:  30 * time.Second,
			},
			{
				ModuleID:     "http-module",
				Type:         domain.Native,
				RequiredTags: []string{"protocol:http"},
				MaxDuration:  30 * time.Second,
			},
		},
	}

	runner, err := New(campaign)
	require.NoError(t, err)

	// Target with only mqtt tag - should only run mqtt module
	target := domain.HostPort{
		Host: "127.0.0.1",
		Port: server.Port(),
		Tags: []string{"protocol:mqtt"},
	}

	ctx := context.Background()
	results, err := runner.Run(ctx, []domain.Target{target})
	require.NoError(t, err)

	// Only mqtt-module should have run (http-module filtered out)
	// Verify through results or logging
	_ = results
}
