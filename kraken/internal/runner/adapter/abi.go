package adapter

import (
	"context"
	"fmt"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/loader"
	"bytemomo/kraken/internal/runner/contextkeys"
	"bytemomo/kraken/internal/transport"
	cnd "bytemomo/trident/conduit"
)

// ABIModuleAdapter is a runner for ABI modules.
type ABIModuleAdapter struct{}

// NewABIModuleAdapter creates a new ABI module adapter.
func NewABIModuleAdapter() *ABIModuleAdapter {
	return &ABIModuleAdapter{}
}

// Supports returns true if the module is an ABI module.
func (a *ABIModuleAdapter) Supports(m *domain.Module) bool {
	if m == nil {
		return false
	}
	return m.ExecConfig.ABI != nil && (m.Type == domain.Lib || m.Type == domain.Native)
}

// Run runs the ABI module.
func (a *ABIModuleAdapter) Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.Target, timeout time.Duration) (domain.RunResult, error) {
	mergedParams := make(map[string]any)
	for k, v := range m.ExecConfig.Params {
		mergedParams[k] = v
	}
	for k, v := range params {
		mergedParams[k] = v
	}

	abiConfig := &domain.ABIConfig{
		LibraryPath: m.ExecConfig.ABI.LibraryPath,
		Symbol:      m.ExecConfig.ABI.Symbol,
	}

	abiCtx := context.WithValue(ctx, contextkeys.ABIConfig, abiConfig)

	var conduit interface{}
	var closeConduit func()
	var stackLayers []string

	// For ABI v2 modules, prepare a conduit factory so modules can request reconnections.
	var factory contextkeys.ConduitFactoryFunc

	if m.ExecConfig.ABI.Version == domain.ModuleV2 && m.ExecConfig.Conduit != nil {
		cfg := m.ExecConfig.Conduit
		dialOpts := a.dialOptionsFromContext(ctx)

		// Build conduit factory based on target type
		switch target := t.(type) {
		case domain.HostPort:
			addr := fmt.Sprintf("%s:%d", target.Host, target.Port)
			factory = a.buildNetworkConduitFactory(addr, cfg.Kind, cfg.Stack, dialOpts)
		case domain.EtherCATMaster:
			if cfg.Kind != cnd.KindFrame {
				return domain.RunResult{Target: t}, fmt.Errorf("EtherCAT targets require KindFrame conduit, got %v", cfg.Kind)
			}
			factory = a.buildFrameConduitFactory(target.Interface, dialOpts)
		}

		if factory != nil {
			var err error
			conduit, closeConduit, stackLayers, err = factory(timeout)
			if err != nil {
				return domain.RunResult{Target: t}, fmt.Errorf("failed to dial conduit: %w", err)
			}
			if closeConduit != nil {
				defer closeConduit()
			}

			abiCtx = context.WithValue(abiCtx, contextkeys.ConduitFactory, factory)
			abiCtx = context.WithValue(abiCtx, contextkeys.StackLayers, stackLayers)
		}
	}

	module, err := loader.Load(abiConfig.LibraryPath)
	if err != nil {
		return domain.RunResult{}, fmt.Errorf("failed to load module: %w", err)
	}
	defer module.Close()

	return module.Run(abiCtx, mergedParams, t, timeout, conduit)
}

func (a *ABIModuleAdapter) dialOptionsFromContext(ctx context.Context) transport.DialOptions {
	if v := ctx.Value(contextkeys.ConnectionDefaults); v != nil {
		if defaults, ok := v.(*domain.ConnectionDefaults); ok {
			return transport.DialOptionsFromDefaults(defaults)
		}
	}
	return transport.DefaultDialOptions()
}

// buildNetworkConduitFactory creates a conduit factory for network (Stream/Datagram) targets.
func (a *ABIModuleAdapter) buildNetworkConduitFactory(addr string, kind cnd.Kind, stack []domain.LayerHint, dialOpts transport.DialOptions) contextkeys.ConduitFactoryFunc {
	return func(timeout time.Duration) (interface{}, func(), []string, error) {
		dialCtx := context.Background()
		if timeout > 0 {
			var cancel context.CancelFunc
			dialCtx, cancel = context.WithTimeout(context.Background(), timeout)
			defer cancel()
		}

		layers := make([]string, 0, len(stack))
		for _, l := range stack {
			layers = append(layers, l.Name)
		}

		switch kind {
		case cnd.KindStream:
			if err := transport.AcquireConnSlot(dialCtx, dialOpts.ConnSem); err != nil {
				return nil, nil, nil, err
			}
			streamConduit, err := transport.BuildStreamConduit(addr, stack)
			if err != nil {
				transport.ReleaseConnSlot(dialOpts.ConnSem)
				return nil, nil, nil, err
			}
			if err := transport.DialWithRetry(dialCtx, streamConduit, dialOpts); err != nil {
				streamConduit.Close()
				transport.ReleaseConnSlot(dialOpts.ConnSem)
				return nil, nil, nil, err
			}
			return streamConduit.Underlying(), func() {
				streamConduit.Close()
				transport.ReleaseConnSlot(dialOpts.ConnSem)
			}, layers, nil
		case cnd.KindDatagram:
			if err := transport.AcquireConnSlot(dialCtx, dialOpts.ConnSem); err != nil {
				return nil, nil, nil, err
			}
			datagramConduit, err := transport.BuildDatagramConduit(addr, stack)
			if err != nil {
				transport.ReleaseConnSlot(dialOpts.ConnSem)
				return nil, nil, nil, err
			}
			if err := transport.DialWithRetry(dialCtx, datagramConduit, dialOpts); err != nil {
				datagramConduit.Close()
				transport.ReleaseConnSlot(dialOpts.ConnSem)
				return nil, nil, nil, err
			}
			return datagramConduit.Underlying(), func() {
				datagramConduit.Close()
				transport.ReleaseConnSlot(dialOpts.ConnSem)
			}, layers, nil
		default:
			return nil, nil, nil, fmt.Errorf("unsupported conduit kind for network target: %v", kind)
		}
	}
}

// buildFrameConduitFactory creates a conduit factory for EtherCAT (Frame) targets.
func (a *ABIModuleAdapter) buildFrameConduitFactory(iface string, dialOpts transport.DialOptions) contextkeys.ConduitFactoryFunc {
	return func(timeout time.Duration) (interface{}, func(), []string, error) {
		dialCtx := context.Background()
		if timeout > 0 {
			var cancel context.CancelFunc
			dialCtx, cancel = context.WithTimeout(context.Background(), timeout)
			defer cancel()
		}

		if err := transport.AcquireConnSlot(dialCtx, dialOpts.ConnSem); err != nil {
			return nil, nil, nil, err
		}
		frameConduit := transport.BuildEtherCATConduit(iface)
		if err := transport.DialWithRetry(dialCtx, frameConduit, dialOpts); err != nil {
			frameConduit.Close()
			transport.ReleaseConnSlot(dialOpts.ConnSem)
			return nil, nil, nil, err
		}
		return frameConduit.Underlying(), func() {
			frameConduit.Close()
			transport.ReleaseConnSlot(dialOpts.ConnSem)
		}, []string{"eth"}, nil
	}
}
