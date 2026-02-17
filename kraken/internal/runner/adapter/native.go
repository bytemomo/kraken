package adapter

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/native"
	"bytemomo/kraken/internal/runner/contextkeys"
	"bytemomo/kraken/internal/transport"
	cnd "bytemomo/trident/conduit"
	"bytemomo/trident/conduit/datalink"
)

// NativeBuiltinAdapter executes Go-native modules compiled into the binary.
type NativeBuiltinAdapter struct{}

// NewNativeBuiltinAdapter creates a new adapter.
func NewNativeBuiltinAdapter() *NativeBuiltinAdapter {
	return &NativeBuiltinAdapter{}
}

// Supports returns true if the module references a builtin implementation.
func (n *NativeBuiltinAdapter) Supports(m *domain.Module) bool {
	return m != nil &&
		m.Type == domain.Native &&
		m.ExecConfig.ABI == nil &&
		m.ExecConfig.GRPC == nil &&
		m.ExecConfig.Container == nil
}

// Run runs the builtin module function.
func (n *NativeBuiltinAdapter) Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.Target, timeout time.Duration) (domain.RunResult, error) {
	desc, ok := native.Lookup(m.ModuleID)
	if !ok {
		// Try stripping conduit template suffix (e.g., "mqtt-dict-attack-tcp" -> "mqtt-dict-attack")
		baseID := stripTemplateSuffix(m.ModuleID)
		if baseID != m.ModuleID {
			desc, ok = native.Lookup(baseID)
		}
		if !ok {
			return domain.RunResult{Target: t}, fmt.Errorf("unknown builtin module %q", m.ModuleID)
		}
	}
	fn := desc.Run

	kind := desc.Kind
	stack := desc.Stack
	if m.ExecConfig.Conduit != nil && m.ExecConfig.Conduit.Kind != 0 {
		kind = m.ExecConfig.Conduit.Kind
		stack = m.ExecConfig.Conduit.Stack
	}

	resources, err := n.buildResources(ctx, t, kind, stack)
	if err != nil {
		return domain.RunResult{Target: t}, err
	}

	return fn(ctx, m, t, resources, params, timeout)
}

func (n *NativeBuiltinAdapter) buildResources(ctx context.Context, target domain.Target, kind cnd.Kind, stack []domain.LayerHint) (native.Resources, error) {
	var res native.Resources
	if kind == 0 {
		return res, nil
	}

	dialOpts := n.dialOptionsFromContext(ctx)

	switch target.Kind() {
	case domain.TargetKindNetwork:
		return n.buildNetworkResources(target.(domain.HostPort), kind, stack, dialOpts)
	case domain.TargetKindEtherCAT:
		return n.buildEtherCATResources(target.(domain.EtherCATMaster), kind, dialOpts)
	default:
		return res, fmt.Errorf("unsupported target kind: %s", target.Kind())
	}
}

func (n *NativeBuiltinAdapter) dialOptionsFromContext(ctx context.Context) transport.DialOptions {
	if v := ctx.Value(contextkeys.ConnectionDefaults); v != nil {
		if defaults, ok := v.(*domain.ConnectionDefaults); ok {
			return transport.DialOptionsFromDefaults(defaults)
		}
	}
	return transport.DefaultDialOptions()
}

func (n *NativeBuiltinAdapter) buildNetworkResources(hp domain.HostPort, kind cnd.Kind, stack []domain.LayerHint, dialOpts transport.DialOptions) (native.Resources, error) {
	var res native.Resources
	addr := fmt.Sprintf("%s:%d", hp.Host, hp.Port)

	switch kind {
	case cnd.KindStream:
		layerStack := stack
		opts := dialOpts
		res.StreamFactory = func(ctx context.Context) (interface{}, func(), error) {
			if err := transport.AcquireConnSlot(ctx, opts.ConnSem); err != nil {
				return nil, nil, err
			}
			conduit, err := transport.BuildStreamConduit(addr, layerStack)
			if err != nil {
				transport.ReleaseConnSlot(opts.ConnSem)
				return nil, nil, err
			}
			if err := transport.DialWithRetry(ctx, conduit, opts); err != nil {
				conduit.Close()
				transport.ReleaseConnSlot(opts.ConnSem)
				return nil, nil, err
			}
			return conduit.Underlying(), func() {
				conduit.Close()
				transport.ReleaseConnSlot(opts.ConnSem)
			}, nil
		}
	case cnd.KindDatagram:
		layerStack := stack
		opts := dialOpts
		res.DatagramFactory = func(ctx context.Context) (interface{}, func(), error) {
			if err := transport.AcquireConnSlot(ctx, opts.ConnSem); err != nil {
				return nil, nil, err
			}
			conduit, err := transport.BuildDatagramConduit(addr, layerStack)
			if err != nil {
				transport.ReleaseConnSlot(opts.ConnSem)
				return nil, nil, err
			}
			if err := transport.DialWithRetry(ctx, conduit, opts); err != nil {
				conduit.Close()
				transport.ReleaseConnSlot(opts.ConnSem)
				return nil, nil, err
			}
			return conduit.Underlying(), func() {
				conduit.Close()
				transport.ReleaseConnSlot(opts.ConnSem)
			}, nil
		}
	default:
		return res, fmt.Errorf("unsupported conduit kind %d for network target", kind)
	}

	return res, nil
}

// stripTemplateSuffix removes conduit template suffixes like "-tcp" or "-tls" from module IDs.
func stripTemplateSuffix(id string) string {
	suffixes := []string{"-tcp", "-tls", "-dtls", "-udp"}
	for _, suffix := range suffixes {
		if strings.HasSuffix(id, suffix) {
			return strings.TrimSuffix(id, suffix)
		}
	}
	return id
}

func (n *NativeBuiltinAdapter) buildEtherCATResources(master domain.EtherCATMaster, kind cnd.Kind, dialOpts transport.DialOptions) (native.Resources, error) {
	var res native.Resources

	if kind != cnd.KindFrame {
		return res, fmt.Errorf("EtherCAT targets require KindFrame conduit, got %d", kind)
	}

	iface := master.Interface
	broadcast := net.HardwareAddr([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	opts := dialOpts

	res.FrameFactory = func(ctx context.Context) (interface{}, func(), error) {
		if err := transport.AcquireConnSlot(ctx, opts.ConnSem); err != nil {
			return nil, nil, err
		}
		conduit := datalink.Ethernet(iface, broadcast, datalink.EtherTypeEtherCAT)
		if err := transport.DialWithRetry(ctx, conduit, opts); err != nil {
			conduit.Close()
			transport.ReleaseConnSlot(opts.ConnSem)
			return nil, nil, err
		}
		return conduit.Underlying(), func() {
			conduit.Close()
			transport.ReleaseConnSlot(opts.ConnSem)
		}, nil
	}

	return res, nil
}
