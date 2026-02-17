//go:build integration

package transport

import (
	"context"
	"testing"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/testutil"
	cnd "bytemomo/trident/conduit"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for kraken's BuildStreamConduit function - verifies it correctly
// builds trident conduits from kraken's domain.ConduitConfig.

func TestIntegration_BuildStreamConduit_TCP_ReturnsCorrectStack(t *testing.T) {
	server := testutil.NewEchoServer()
	require.NoError(t, server.Start())
	defer server.Stop()

	config := &domain.ConduitConfig{
		Kind: cnd.KindStream,
		Stack: []domain.StackLayer{
			{Name: "tcp"},
		},
	}

	conduit, err := BuildStreamConduit(server.Addr(), config)
	require.NoError(t, err)
	require.NotNil(t, conduit)

	// Verify kraken correctly translates config to conduit
	assert.Equal(t, []string{"tcp"}, conduit.Stack())
	assert.Equal(t, cnd.KindStream, conduit.Kind())
}

func TestIntegration_BuildStreamConduit_TLS_ReturnsCorrectStack(t *testing.T) {
	cert, err := testutil.GenerateSelfSignedCert("127.0.0.1", "localhost")
	require.NoError(t, err)

	server := testutil.NewMockTLSServer(cert, nil)
	require.NoError(t, server.Start())
	defer server.Stop()

	config := &domain.ConduitConfig{
		Kind: cnd.KindStream,
		Stack: []domain.StackLayer{
			{Name: "tcp"},
			{Name: "tls", Params: map[string]any{"skip_verify": true}},
		},
	}

	conduit, err := BuildStreamConduit(server.Addr(), config)
	require.NoError(t, err)
	require.NotNil(t, conduit)

	// Verify kraken correctly builds TLS stack
	stack := conduit.Stack()
	assert.Contains(t, stack, "tls")
	assert.Contains(t, stack, "tcp")
}

func TestIntegration_BuildStreamConduit_TLS_SkipVerifyParam(t *testing.T) {
	cert, err := testutil.GenerateSelfSignedCert("127.0.0.1", "localhost")
	require.NoError(t, err)

	server := testutil.NewMockTLSServer(cert, nil)
	require.NoError(t, server.Start())
	defer server.Stop()

	// With skip_verify: true - should succeed
	configSkip := &domain.ConduitConfig{
		Kind: cnd.KindStream,
		Stack: []domain.StackLayer{
			{Name: "tcp"},
			{Name: "tls", Params: map[string]any{"skip_verify": true}},
		},
	}

	conduit, err := BuildStreamConduit(server.Addr(), configSkip)
	require.NoError(t, err)

	ctx := context.Background()
	err = conduit.Dial(ctx)
	require.NoError(t, err)
	conduit.Close()

	// Without skip_verify - should fail with self-signed cert
	configVerify := &domain.ConduitConfig{
		Kind: cnd.KindStream,
		Stack: []domain.StackLayer{
			{Name: "tcp"},
			{Name: "tls"}, // No skip_verify
		},
	}

	conduit2, err := BuildStreamConduit(server.Addr(), configVerify)
	require.NoError(t, err)

	err = conduit2.Dial(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate")
}

// Tests for kraken's DialWithRetry function - OT-safe connection handling

func TestIntegration_DialWithRetry_Success(t *testing.T) {
	server := testutil.NewEchoServer()
	require.NoError(t, server.Start())
	defer server.Stop()

	config := &domain.ConduitConfig{
		Kind:  cnd.KindStream,
		Stack: []domain.StackLayer{{Name: "tcp"}},
	}

	conduit, err := BuildStreamConduit(server.Addr(), config)
	require.NoError(t, err)

	opts := DialOptions{
		Timeout:    5 * time.Second,
		Backoff:    100 * time.Millisecond,
		MaxRetries: 3,
	}

	ctx := context.Background()
	err = DialWithRetry(ctx, conduit, opts)
	require.NoError(t, err)
	conduit.Close()
}

func TestIntegration_DialWithRetry_RetriesOnFailure(t *testing.T) {
	// Server that fails first 2 connections, then succeeds
	server := testutil.NewFlakyServer(2, nil)
	require.NoError(t, server.Start())
	defer server.Stop()

	config := &domain.ConduitConfig{
		Kind:  cnd.KindStream,
		Stack: []domain.StackLayer{{Name: "tcp"}},
	}

	conduit, err := BuildStreamConduit(server.Addr(), config)
	require.NoError(t, err)

	opts := DialOptions{
		Timeout:    1 * time.Second,
		Backoff:    50 * time.Millisecond,
		MaxRetries: 3, // Should succeed on 3rd attempt
	}

	ctx := context.Background()
	err = DialWithRetry(ctx, conduit, opts)
	require.NoError(t, err)
	conduit.Close()
}

func TestIntegration_DialWithRetry_ExhaustsRetries(t *testing.T) {
	// Server that always rejects
	server := testutil.NewFlakyServer(100, nil)
	require.NoError(t, server.Start())
	defer server.Stop()

	config := &domain.ConduitConfig{
		Kind:  cnd.KindStream,
		Stack: []domain.StackLayer{{Name: "tcp"}},
	}

	conduit, err := BuildStreamConduit(server.Addr(), config)
	require.NoError(t, err)

	opts := DialOptions{
		Timeout:    500 * time.Millisecond,
		Backoff:    50 * time.Millisecond,
		MaxRetries: 2,
	}

	ctx := context.Background()
	err = DialWithRetry(ctx, conduit, opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "3 attempts") // 1 initial + 2 retries
}

func TestIntegration_DialWithRetry_RespectsContextCancellation(t *testing.T) {
	server := testutil.NewDelayedServer(0, 5*time.Second)
	require.NoError(t, server.Start())
	defer server.Stop()

	config := &domain.ConduitConfig{
		Kind:  cnd.KindStream,
		Stack: []domain.StackLayer{{Name: "tcp"}},
	}

	conduit, err := BuildStreamConduit(server.Addr(), config)
	require.NoError(t, err)

	opts := DialOptions{
		Timeout:    10 * time.Second,
		Backoff:    100 * time.Millisecond,
		MaxRetries: 5,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err = DialWithRetry(ctx, conduit, opts)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestIntegration_DialWithRetry_RespectsTimeout(t *testing.T) {
	// Non-routable address to trigger timeout
	config := &domain.ConduitConfig{
		Kind:  cnd.KindStream,
		Stack: []domain.StackLayer{{Name: "tcp"}},
	}

	conduit, err := BuildStreamConduit("10.255.255.1:12345", config)
	require.NoError(t, err)

	opts := DialOptions{
		Timeout:    200 * time.Millisecond,
		Backoff:    50 * time.Millisecond,
		MaxRetries: 1,
	}

	ctx := context.Background()
	start := time.Now()
	err = DialWithRetry(ctx, conduit, opts)
	elapsed := time.Since(start)

	require.Error(t, err)
	// Should complete within reasonable time
	assert.Less(t, elapsed, 2*time.Second)
}

// Tests for kraken's DialOptions helpers

func TestIntegration_DialOptionsFromDefaults(t *testing.T) {
	defaults := &domain.ConnectionDefaults{
		ConnectionTimeout: 15 * time.Second,
		ConnectionBackoff: 200 * time.Millisecond,
		MaxReconnects:     5,
	}

	opts := DialOptionsFromDefaults(defaults)

	assert.Equal(t, 15*time.Second, opts.Timeout)
	assert.Equal(t, 200*time.Millisecond, opts.Backoff)
	assert.Equal(t, 5, opts.MaxRetries)
}

func TestIntegration_DefaultDialOptions(t *testing.T) {
	opts := DefaultDialOptions()

	// Verify reasonable defaults for OT safety
	assert.Greater(t, opts.Timeout, time.Duration(0))
	assert.Greater(t, opts.Backoff, time.Duration(0))
	assert.GreaterOrEqual(t, opts.MaxRetries, 0)
}
