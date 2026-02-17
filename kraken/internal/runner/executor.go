package runner

import (
	"context"
	"time"

	"bytemomo/kraken/internal/domain"
)

// ModuleExecutor is an interface for running modules.
type ModuleExecutor interface {
	// Supports returns true if the executor supports the given module.
	Supports(m *domain.Module) bool
	// Run runs the given module.
	Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.Target, timeout time.Duration) (domain.RunResult, error)
}
