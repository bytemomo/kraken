package native

import (
	"context"
	"time"

	"bytemomo/kraken/internal/domain"

	cnd "bytemomo/trident/conduit"
)

// StreamFactory creates a new stream conduit handle for a module along with a cleanup func.
type StreamFactory func(ctx context.Context) (interface{}, func(), error)

// DatagramFactory creates a new datagram conduit handle for UDP-based modules.
type DatagramFactory func(ctx context.Context) (interface{}, func(), error)

// FrameFactory creates a new frame (Layer 2) conduit handle for EtherCAT modules.
type FrameFactory func(ctx context.Context) (interface{}, func(), error)

// Resources exposes helpers available to native builtin modules.
type Resources struct {
	StreamFactory   StreamFactory
	DatagramFactory DatagramFactory
	FrameFactory    FrameFactory
}

// ModuleFunc is the signature implemented by builtin Go modules.
type ModuleFunc func(ctx context.Context, mod *domain.Module, target domain.Target, res Resources, params map[string]any, timeout time.Duration) (domain.RunResult, error)

// Descriptor defines how a native module should be run.
type Descriptor struct {
	Run   ModuleFunc
	Kind  cnd.Kind
	Stack []domain.LayerHint

	Description string // Optional
}

var registry = map[string]Descriptor{}

// Register stores the module implementation under the provided ID.
func Register(id string, desc Descriptor) {
	if id == "" || desc.Run == nil {
		return
	}
	registry[id] = desc
}

// Lookup returns the registered module descriptor.
func Lookup(id string) (Descriptor, bool) {
	fn, ok := registry[id]
	return fn, ok
}

// List returns all registered native modules.
func List() []struct {
	ID         string
	Descriptor Descriptor
} {
	entries := make([]struct {
		ID         string
		Descriptor Descriptor
	}, 0, len(registry))
	for id, desc := range registry {
		entries = append(entries, struct {
			ID         string
			Descriptor Descriptor
		}{ID: id, Descriptor: desc})
	}
	return entries
}
