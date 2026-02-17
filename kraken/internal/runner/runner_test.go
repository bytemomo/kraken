package runner

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/runner/contextkeys"
	"github.com/sirupsen/logrus"
)

func TestRunnerStopsModuleExecutionOnContextCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exec := &cancelingExecutor{cancel: cancel}

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	r := &Runner{
		Log:             logrus.NewEntry(logger),
		Executors:       []ModuleExecutor{exec},
		Store:           noopResultStore{},
		ResultDirectory: "results",
	}

	campaign := domain.Campaign{
		Tasks: []*domain.Module{
			{ModuleID: "first", MaxDuration: 30 * time.Second},
			{ModuleID: "second", MaxDuration: 30 * time.Second},
		},
	}

	classified := []domain.ClassifiedTarget{
		{Target: domain.HostPort{Host: "localhost", Port: 443}},
	}

	results, err := r.Execute(ctx, campaign, classified)
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected results for 1 target, got %d", len(results))
	}

	executed := exec.Executed()
	if len(executed) != 1 {
		t.Fatalf("expected only one module execution, got %v", executed)
	}

	if executed[0] != "first" {
		t.Fatalf("expected first module to run, got %s", executed[0])
	}
}

type cancelingExecutor struct {
	cancel context.CancelFunc

	mu       sync.Mutex
	executed []string
}

func (e *cancelingExecutor) Supports(*domain.Module) bool { return true }

func (e *cancelingExecutor) Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.Target, timeout time.Duration) (domain.RunResult, error) {
	e.mu.Lock()
	e.executed = append(e.executed, m.ModuleID)
	callIndex := len(e.executed)
	e.mu.Unlock()

	if callIndex == 1 && e.cancel != nil {
		e.cancel()
		<-ctx.Done()
	}

	return domain.RunResult{Target: t}, ctx.Err()
}

func (e *cancelingExecutor) Executed() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, len(e.executed))
	copy(out, e.executed)
	return out
}

type noopResultStore struct{}

func (noopResultStore) Save(domain.Target, domain.RunResult) error { return nil }

func TestFilterStepsByTags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		steps    []*domain.Module
		tags     []domain.Tag
		expected []string
	}{
		{
			name: "no required tags matches all",
			steps: []*domain.Module{
				{ModuleID: "mod1", RequiredTags: nil},
				{ModuleID: "mod2", RequiredTags: []string{}},
			},
			tags:     []domain.Tag{"protocol:mqtt"},
			expected: []string{"mod1", "mod2"},
		},
		{
			name: "single required tag matches",
			steps: []*domain.Module{
				{ModuleID: "mqtt-mod", RequiredTags: []string{"protocol:mqtt"}},
				{ModuleID: "http-mod", RequiredTags: []string{"protocol:http"}},
			},
			tags:     []domain.Tag{"protocol:mqtt"},
			expected: []string{"mqtt-mod"},
		},
		{
			name: "multiple required tags all must match",
			steps: []*domain.Module{
				{ModuleID: "tls-mqtt", RequiredTags: []string{"protocol:mqtt", "transport:tls"}},
				{ModuleID: "tcp-mqtt", RequiredTags: []string{"protocol:mqtt", "transport:tcp"}},
			},
			tags:     []domain.Tag{"protocol:mqtt", "transport:tls"},
			expected: []string{"tls-mqtt"},
		},
		{
			name: "no matching tags",
			steps: []*domain.Module{
				{ModuleID: "mod1", RequiredTags: []string{"protocol:mqtt"}},
			},
			tags:     []domain.Tag{"protocol:http"},
			expected: nil,
		},
		{
			name:     "empty steps",
			steps:    []*domain.Module{},
			tags:     []domain.Tag{"protocol:mqtt"},
			expected: nil,
		},
		{
			name: "empty tags filters to modules with no requirements",
			steps: []*domain.Module{
				{ModuleID: "no-reqs", RequiredTags: nil},
				{ModuleID: "has-reqs", RequiredTags: []string{"protocol:mqtt"}},
			},
			tags:     []domain.Tag{},
			expected: []string{"no-reqs"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := filterStepsByTags(tc.steps, tc.tags)
			resultIDs := stepIDs(result)

			if len(resultIDs) != len(tc.expected) {
				t.Fatalf("expected %v, got %v", tc.expected, resultIDs)
			}

			for i, id := range resultIDs {
				if id != tc.expected[i] {
					t.Errorf("index %d: expected %s, got %s", i, tc.expected[i], id)
				}
			}
		})
	}
}

func TestStepIDs(t *testing.T) {
	t.Parallel()

	steps := []*domain.Module{
		{ModuleID: "first"},
		{ModuleID: "second"},
		{ModuleID: "third"},
	}

	ids := stepIDs(steps)

	expected := []string{"first", "second", "third"}
	if len(ids) != len(expected) {
		t.Fatalf("expected %d ids, got %d", len(expected), len(ids))
	}

	for i, id := range ids {
		if id != expected[i] {
			t.Errorf("index %d: expected %s, got %s", i, expected[i], id)
		}
	}
}

func TestStepIDs_Empty(t *testing.T) {
	t.Parallel()

	ids := stepIDs([]*domain.Module{})
	if len(ids) != 0 {
		t.Fatalf("expected empty slice, got %v", ids)
	}
}

func TestMax(t *testing.T) {
	t.Parallel()

	tests := []struct {
		a, b, expected int
	}{
		{1, 2, 2},
		{2, 1, 2},
		{0, 0, 0},
		{-1, 1, 1},
		{5, 5, 5},
	}

	for _, tc := range tests {
		result := max(tc.a, tc.b)
		if result != tc.expected {
			t.Errorf("max(%d, %d) = %d, want %d", tc.a, tc.b, result, tc.expected)
		}
	}
}

func TestRunnerNoExecutorFound(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	r := &Runner{
		Log:             logrus.NewEntry(logger),
		Executors:       []ModuleExecutor{}, // No executors
		Store:           noopResultStore{},
		ResultDirectory: "results",
	}

	campaign := domain.Campaign{
		Tasks: []*domain.Module{
			{ModuleID: "test-module", Type: "native", MaxDuration: 30 * time.Second},
		},
	}

	classified := []domain.ClassifiedTarget{
		{Target: domain.HostPort{Host: "localhost", Port: 1883}},
	}

	results, err := r.Execute(ctx, campaign, classified)
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	// Should have a log entry about no executor found
	if len(results[0].Logs) == 0 {
		t.Error("expected log entry about no executor found")
	}
}

type mockExecutor struct {
	supportsFn func(*domain.Module) bool
	runFn      func(context.Context, *domain.Module, map[string]any, domain.Target, time.Duration) (domain.RunResult, error)
}

func (m *mockExecutor) Supports(mod *domain.Module) bool {
	if m.supportsFn != nil {
		return m.supportsFn(mod)
	}
	return true
}

func (m *mockExecutor) Run(ctx context.Context, mod *domain.Module, params map[string]any, t domain.Target, timeout time.Duration) (domain.RunResult, error) {
	if m.runFn != nil {
		return m.runFn(ctx, mod, params, t, timeout)
	}
	return domain.RunResult{Target: t}, nil
}

func TestRunnerExecutesAllModulesForTarget(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	var executed []string
	var mu sync.Mutex

	exec := &mockExecutor{
		runFn: func(ctx context.Context, m *domain.Module, params map[string]any, t domain.Target, timeout time.Duration) (domain.RunResult, error) {
			mu.Lock()
			executed = append(executed, m.ModuleID)
			mu.Unlock()
			return domain.RunResult{Target: t}, nil
		},
	}

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	r := &Runner{
		Log:             logrus.NewEntry(logger),
		Executors:       []ModuleExecutor{exec},
		Store:           noopResultStore{},
		ResultDirectory: "results",
	}

	campaign := domain.Campaign{
		Tasks: []*domain.Module{
			{ModuleID: "first", MaxDuration: 30 * time.Second},
			{ModuleID: "second", MaxDuration: 30 * time.Second},
			{ModuleID: "third", MaxDuration: 30 * time.Second},
		},
	}

	classified := []domain.ClassifiedTarget{
		{Target: domain.HostPort{Host: "localhost", Port: 1883}},
	}

	_, err := r.Execute(ctx, campaign, classified)
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	if len(executed) != 3 {
		t.Fatalf("expected 3 modules executed, got %d: %v", len(executed), executed)
	}
}

func TestRunnerExecutorReturnsFindings(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	exec := &mockExecutor{
		runFn: func(ctx context.Context, m *domain.Module, params map[string]any, t domain.Target, timeout time.Duration) (domain.RunResult, error) {
			return domain.RunResult{
				Target: t,
				Findings: []domain.Finding{
					{ModuleID: m.ModuleID, Title: "test-finding"},
				},
			}, nil
		},
	}

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	r := &Runner{
		Log:             logrus.NewEntry(logger),
		Executors:       []ModuleExecutor{exec},
		Store:           noopResultStore{},
		ResultDirectory: "results",
	}

	campaign := domain.Campaign{
		Tasks: []*domain.Module{
			{ModuleID: "test-module", MaxDuration: 30 * time.Second},
		},
	}

	classified := []domain.ClassifiedTarget{
		{Target: domain.HostPort{Host: "localhost", Port: 1883}},
	}

	results, err := r.Execute(ctx, campaign, classified)
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if len(results[0].Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results[0].Findings))
	}

	if results[0].Findings[0].Title != "test-finding" {
		t.Errorf("expected finding title 'test-finding', got %s", results[0].Findings[0].Title)
	}
}

func TestRunnerMultipleTargets(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	exec := &mockExecutor{}

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	r := &Runner{
		Log:             logrus.NewEntry(logger),
		Executors:       []ModuleExecutor{exec},
		Store:           noopResultStore{},
		ResultDirectory: "results",
	}

	requireMaxDuration := false
	campaign := domain.Campaign{
		Policy: domain.Policy{
			Safety: domain.SafetyPolicy{
				RequireMaxDuration: &requireMaxDuration,
			},
			Runner: domain.RunnerPolicy{
				MaxParallelTargets: 2,
			},
		},
		Tasks: []*domain.Module{
			{ModuleID: "test-module"},
		},
	}

	classified := []domain.ClassifiedTarget{
		{Target: domain.HostPort{Host: "host1", Port: 1883}},
		{Target: domain.HostPort{Host: "host2", Port: 1883}},
		{Target: domain.HostPort{Host: "host3", Port: 1883}},
	}

	results, err := r.Execute(ctx, campaign, classified)
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
}

// --- Policy Enforcement Tests ---

func TestRunnerUsesEffectivePolicy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	var maxConcurrent int32
	var currentConcurrent int32
	var mu sync.Mutex

	exec := &mockExecutor{
		runFn: func(ctx context.Context, m *domain.Module, params map[string]any, tgt domain.Target, timeout time.Duration) (domain.RunResult, error) {
			mu.Lock()
			currentConcurrent++
			if currentConcurrent > maxConcurrent {
				maxConcurrent = currentConcurrent
			}
			mu.Unlock()

			time.Sleep(50 * time.Millisecond) // Simulate work

			mu.Lock()
			currentConcurrent--
			mu.Unlock()

			return domain.RunResult{Target: tgt}, nil
		},
	}

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	r := &Runner{
		Log:             logrus.NewEntry(logger),
		Executors:       []ModuleExecutor{exec},
		Store:           noopResultStore{},
		ResultDirectory: "results",
	}

	requireMaxDuration := false
	campaign := domain.Campaign{
		Policy: domain.Policy{
			Safety: domain.SafetyPolicy{
				RequireMaxDuration: &requireMaxDuration,
			},
			Runner: domain.RunnerPolicy{
				MaxParallelTargets: 2, // Only 2 concurrent
			},
		},
		Tasks: []*domain.Module{
			{ModuleID: "test-module"},
		},
	}

	// 5 targets with max 2 concurrent
	classified := []domain.ClassifiedTarget{
		{Target: domain.HostPort{Host: "host1", Port: 1883}},
		{Target: domain.HostPort{Host: "host2", Port: 1883}},
		{Target: domain.HostPort{Host: "host3", Port: 1883}},
		{Target: domain.HostPort{Host: "host4", Port: 1883}},
		{Target: domain.HostPort{Host: "host5", Port: 1883}},
	}

	_, err := r.Execute(ctx, campaign, classified)
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	if maxConcurrent > 2 {
		t.Errorf("max concurrent exceeded policy limit: got %d, want <= 2", maxConcurrent)
	}
}

func TestRunnerDefaultPolicyMaxParallelTargets(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	var maxConcurrent int32
	var currentConcurrent int32
	var mu sync.Mutex

	exec := &mockExecutor{
		runFn: func(ctx context.Context, m *domain.Module, params map[string]any, tgt domain.Target, timeout time.Duration) (domain.RunResult, error) {
			mu.Lock()
			currentConcurrent++
			if currentConcurrent > maxConcurrent {
				maxConcurrent = currentConcurrent
			}
			mu.Unlock()

			time.Sleep(50 * time.Millisecond)

			mu.Lock()
			currentConcurrent--
			mu.Unlock()

			return domain.RunResult{Target: tgt}, nil
		},
	}

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	r := &Runner{
		Log:             logrus.NewEntry(logger),
		Executors:       []ModuleExecutor{exec},
		Store:           noopResultStore{},
		ResultDirectory: "results",
	}

	// Empty policy - should use default (MaxParallelTargets=1)
	requireMaxDuration := false
	campaign := domain.Campaign{
		Policy: domain.Policy{
			Safety: domain.SafetyPolicy{
				RequireMaxDuration: &requireMaxDuration,
			},
		},
		Tasks: []*domain.Module{
			{ModuleID: "test-module"},
		},
	}

	classified := []domain.ClassifiedTarget{
		{Target: domain.HostPort{Host: "host1", Port: 1883}},
		{Target: domain.HostPort{Host: "host2", Port: 1883}},
		{Target: domain.HostPort{Host: "host3", Port: 1883}},
	}

	_, err := r.Execute(ctx, campaign, classified)
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	// Default MaxParallelTargets is 1
	if maxConcurrent > 1 {
		t.Errorf("default policy should limit to 1 concurrent, got %d", maxConcurrent)
	}
}

func TestRunnerPassesConnectionDefaultsToContext(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	var receivedDefaults *domain.ConnectionDefaults

	exec := &mockExecutor{
		runFn: func(ctx context.Context, m *domain.Module, params map[string]any, tgt domain.Target, timeout time.Duration) (domain.RunResult, error) {
			// Check if connection defaults are in context
			if v := ctx.Value(contextkeys.ConnectionDefaults); v != nil {
				receivedDefaults = v.(*domain.ConnectionDefaults)
			}
			return domain.RunResult{Target: tgt}, nil
		},
	}

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	r := &Runner{
		Log:             logrus.NewEntry(logger),
		Executors:       []ModuleExecutor{exec},
		Store:           noopResultStore{},
		ResultDirectory: "results",
	}

	campaign := domain.Campaign{
		Policy: domain.Policy{
			Runner: domain.RunnerPolicy{
				Defaults: domain.ConnectionDefaults{
					ConnectionTimeout: 5 * time.Second,
					ConnectionBackoff: 200 * time.Millisecond,
					MaxReconnects:     5,
				},
			},
		},
		Tasks: []*domain.Module{
			{ModuleID: "test-module", MaxDuration: 30 * time.Second},
		},
	}

	classified := []domain.ClassifiedTarget{
		{Target: domain.HostPort{Host: "localhost", Port: 1883}},
	}

	_, err := r.Execute(ctx, campaign, classified)
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	if receivedDefaults == nil {
		t.Fatal("expected connection defaults in context")
	}

	if receivedDefaults.ConnectionTimeout != 5*time.Second {
		t.Errorf("expected ConnectionTimeout=5s, got %v", receivedDefaults.ConnectionTimeout)
	}
	if receivedDefaults.ConnectionBackoff != 200*time.Millisecond {
		t.Errorf("expected ConnectionBackoff=200ms, got %v", receivedDefaults.ConnectionBackoff)
	}
	if receivedDefaults.MaxReconnects != 5 {
		t.Errorf("expected MaxReconnects=5, got %d", receivedDefaults.MaxReconnects)
	}
}

func TestRunnerPolicyMergesWithDefaults(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	var receivedDefaults *domain.ConnectionDefaults

	exec := &mockExecutor{
		runFn: func(ctx context.Context, m *domain.Module, params map[string]any, tgt domain.Target, timeout time.Duration) (domain.RunResult, error) {
			if v := ctx.Value(contextkeys.ConnectionDefaults); v != nil {
				receivedDefaults = v.(*domain.ConnectionDefaults)
			}
			return domain.RunResult{Target: tgt}, nil
		},
	}

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	r := &Runner{
		Log:             logrus.NewEntry(logger),
		Executors:       []ModuleExecutor{exec},
		Store:           noopResultStore{},
		ResultDirectory: "results",
	}

	// Only specify timeout, rest should use defaults
	campaign := domain.Campaign{
		Policy: domain.Policy{
			Runner: domain.RunnerPolicy{
				Defaults: domain.ConnectionDefaults{
					ConnectionTimeout: 30 * time.Second,
				},
			},
		},
		Tasks: []*domain.Module{
			{ModuleID: "test-module", MaxDuration: 30 * time.Second},
		},
	}

	classified := []domain.ClassifiedTarget{
		{Target: domain.HostPort{Host: "localhost", Port: 1883}},
	}

	_, err := r.Execute(ctx, campaign, classified)
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	if receivedDefaults == nil {
		t.Fatal("expected connection defaults in context")
	}

	// Overridden value
	if receivedDefaults.ConnectionTimeout != 30*time.Second {
		t.Errorf("expected ConnectionTimeout=30s, got %v", receivedDefaults.ConnectionTimeout)
	}

	// Default values (merged)
	if receivedDefaults.ConnectionBackoff != 100*time.Millisecond {
		t.Errorf("expected default ConnectionBackoff=100ms, got %v", receivedDefaults.ConnectionBackoff)
	}
	if receivedDefaults.MaxReconnects != 3 {
		t.Errorf("expected default MaxReconnects=3, got %d", receivedDefaults.MaxReconnects)
	}
}
