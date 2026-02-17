package transport

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"bytemomo/kraken/internal/domain"

	cnd "bytemomo/trident/conduit"
	"bytemomo/trident/conduit/datalink"
	tridentlog "bytemomo/trident/conduit/logging"
	tridenttransport "bytemomo/trident/conduit/transport"
	tlscond "bytemomo/trident/conduit/transport/tls"
)

// DialOptions contains connection parameters for OT safety.
type DialOptions struct {
	Timeout    time.Duration
	Backoff    time.Duration
	MaxRetries int
	ConnSem    chan struct{}
}

// DefaultDialOptions returns safe defaults for OT environments.
func DefaultDialOptions() DialOptions {
	return DialOptions{
		Timeout:    10 * time.Second,
		Backoff:    100 * time.Millisecond,
		MaxRetries: 3,
	}
}

// DialOptionsFromDefaults converts domain.ConnectionDefaults to DialOptions.
func DialOptionsFromDefaults(d *domain.ConnectionDefaults) DialOptions {
	if d == nil {
		return DefaultDialOptions()
	}
	opts := DefaultDialOptions()
	if d.ConnectionTimeout > 0 {
		opts.Timeout = d.ConnectionTimeout
	}
	if d.ConnectionBackoff > 0 {
		opts.Backoff = d.ConnectionBackoff
	}
	if d.MaxReconnects > 0 {
		opts.MaxRetries = d.MaxReconnects
	}
	opts.ConnSem = d.ConnSem
	return opts
}

// AcquireConnSlot blocks until a connection slot is available or ctx is cancelled.
// No-op if sem is nil.
func AcquireConnSlot(ctx context.Context, sem chan struct{}) error {
	if sem == nil {
		return nil
	}
	select {
	case sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ReleaseConnSlot releases a connection slot. No-op if sem is nil.
func ReleaseConnSlot(sem chan struct{}) {
	if sem == nil {
		return
	}
	<-sem
}

// DialWithRetry dials a conduit with retry logic for OT safety.
func DialWithRetry[T any](ctx context.Context, conduit cnd.Conduit[T], opts DialOptions) error {
	var lastErr error
	for attempt := 0; attempt <= opts.MaxRetries; attempt++ {
		if attempt > 0 {
			// Apply backoff between retries
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(opts.Backoff):
			}
		}

		// Create timeout context for this dial attempt
		dialCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
		lastErr = conduit.Dial(dialCtx)
		cancel()

		if lastErr == nil {
			return nil
		}
	}
	return fmt.Errorf("dial failed after %d attempts: %w", opts.MaxRetries+1, lastErr)
}

// BuildStreamConduit builds the requested stack of stream layers.
func BuildStreamConduit(addr string, stack []domain.LayerHint) (cnd.Conduit[cnd.Stream], error) {
	var current cnd.Conduit[cnd.Stream] = tridenttransport.TCP(addr)

	for _, layer := range stack {
		switch strings.ToLower(layer.Name) {
		case "", "tcp":
			continue
		case "tls":
			tlsConfig := BuildTLSConfig(layer.Params)
			current = tlscond.NewTlsClient(current, tlsConfig)
		default:
			return nil, fmt.Errorf("unknown stream layer: %s", layer.Name)
		}
	}

	return tridentlog.NewLoggingConduit(addr, current), nil
}

// BuildFrameConduit builds an Ethernet frame conduit for Layer 2 communication.
// Used for EtherCAT and other raw Ethernet protocols.
//
// Parameters:
//   - iface: network interface name (e.g., "eth0")
//   - destMAC: destination MAC address (use nil for broadcast ff:ff:ff:ff:ff:ff)
//   - etherType: Ethernet frame type (e.g., 0x88A4 for EtherCAT)
func BuildFrameConduit(iface string, destMAC net.HardwareAddr, etherType uint16) cnd.Conduit[cnd.Frame] {
	if destMAC == nil {
		destMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	}
	return datalink.Ethernet(iface, destMAC, etherType)
}

// BuildEtherCATConduit builds a Frame conduit configured for EtherCAT protocol.
func BuildEtherCATConduit(iface string) cnd.Conduit[cnd.Frame] {
	return BuildFrameConduit(iface, nil, datalink.EtherTypeEtherCAT)
}

// BuildDatagramConduit builds the requested stack of datagram layers.
func BuildDatagramConduit(addr string, stack []domain.LayerHint) (cnd.Conduit[cnd.Datagram], error) {
	var current cnd.Conduit[cnd.Datagram] = tridenttransport.UDP(addr)

	for _, layer := range stack {
		switch strings.ToLower(layer.Name) {
		case "", "udp":
			continue
		case "dtls":
			dtlsConfig := BuildDTLSConfig(layer.Params)
			current = tlscond.NewDtlsClient(current, dtlsConfig)
		default:
			return nil, fmt.Errorf("unknown datagram layer: %s", layer.Name)
		}
	}

	return tridentlog.NewLoggingConduit(addr, current), nil
}
