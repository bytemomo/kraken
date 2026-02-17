package adapter

import (
	"context"
	"fmt"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/pkg/modulepb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

// GRPCModuleAdapter is a runner for gRPC modules.
type GRPCModuleAdapter struct {
}

// NewGRPCModuleAdapter creates a new gRPC module adapter.
func NewGRPCModuleAdapter() *GRPCModuleAdapter {
	return &GRPCModuleAdapter{}
}

// Supports returns true if the module is a gRPC module.
func (a *GRPCModuleAdapter) Supports(m *domain.Module) bool {
	if m == nil {
		return false
	}

	return m.ExecConfig.GRPC != nil && m.Type == domain.Grpc
}

// Run runs the gRPC module via the RunWithConduit streaming RPC.
// The runner dials the conduit and proxies I/O so the module does not manage transport.
func (a *GRPCModuleAdapter) Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.Target, timeout time.Duration) (domain.RunResult, error) {
	endpoint := m.ExecConfig.GRPC.ServerAddr
	if endpoint == "" {
		return domain.RunResult{}, fmt.Errorf("grpc endpoint missing in exec.grpc.server_addr")
	}

	if m.ExecConfig.Conduit == nil {
		return domain.RunResult{}, fmt.Errorf("grpc modules require conduit config in exec.conduit")
	}

	dialCtx := ctx
	var cancel context.CancelFunc
	var dialOpts []grpc.DialOption
	dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if m.ExecConfig.GRPC.DialTimeout != nil && *m.ExecConfig.GRPC.DialTimeout > 0 {
		dialCtx, cancel = context.WithTimeout(ctx, *m.ExecConfig.GRPC.DialTimeout)
		dialOpts = append(dialOpts, grpc.WithBlock())
	}
	if cancel != nil {
		defer cancel()
	}

	conn, err := grpc.DialContext(dialCtx, endpoint, dialOpts...)
	if err != nil {
		return domain.RunResult{}, err
	}
	defer conn.Close()

	timeoutMs := uint32(timeout.Milliseconds())

	paramsVals := make(map[string]*structpb.Value, len(params))
	for k, v := range params {
		pv, err := structpb.NewValue(v)
		if err != nil {
			return domain.RunResult{}, fmt.Errorf("failed to convert param %q: %w", k, err)
		}
		paramsVals[k] = pv
	}

	cl := modulepb.NewKrakenModuleClient(conn)

	factory, kind, err := buildConduitFactory(ctx, t, m)
	if err != nil {
		return domain.RunResult{Target: t}, fmt.Errorf("build conduit factory: %w", err)
	}
	conduit, cleanup, stack, err := factory(timeout)
	if err != nil {
		return domain.RunResult{Target: t}, fmt.Errorf("dial initial conduit: %w", err)
	}

	return runWithConduit(ctx, cl, timeoutMs, paramsVals, t, conduit, cleanup, kind, stack, factory)
}
