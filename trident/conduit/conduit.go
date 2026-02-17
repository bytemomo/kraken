package conduit

import (
	"bytemomo/trident/conduit/utils"
	"context"
	"net"
	"net/netip"
	"time"
)

// Kind identifies the operational layer of a Conduit.
type Kind int

const (
	KindUnknown Kind = iota
	// KindStream represents a byte-stream oriented conduit (e.g., TCP, TLS).
	KindStream
	// KindDatagram represents a message-oriented conduit (e.g., UDP, DTLS).
	KindDatagram
	// KindNetwork represents raw IP packet level (Layer 3).
	KindNetwork
	// KindFrame represents Ethernet frame level (Layer 2).
	KindFrame
)

func (k *Kind) UnmarshalText(text []byte) error {
	switch string(text) {
	case "stream":
		*k = KindStream
	case "datagram":
		*k = KindDatagram
	case "network":
		*k = KindNetwork
	case "frame":
		*k = KindFrame
	default:
		*k = KindUnknown
	}
	return nil
}

func (k *Kind) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	return k.UnmarshalText([]byte(s))
}

// Metadata provides optional information about a completed I/O operation.
type Metadata struct {
	// Start is the time before the I/O operation.
	Start time.Time
	// End is the time after the I/O operation.
	End time.Time
	// IfIndex is the network interface index.
	IfIndex int
	// Proto is the protocol number (e.g., EtherType or IP).
	Proto int
}

// SendOptions provides parameters for a single send operation.
type SendOptions struct{}

// RecvOptions provides parameters for a single receive operation.
type RecvOptions struct {
	// MaxBytes hint for buffer allocation.
	MaxBytes int
}

// Buffer is an interface for a recyclable memory buffer.
type Buffer interface {
	// Bytes returns the byte slice.
	Bytes() []byte
	Grow(n int) []byte
	Shrink(n int) []byte
	// Release returns the buffer to its pool.
	Release()
}

// GetBuf retrieves a buffer from the pool.
func GetBuf(size int) Buffer {
	return utils.GetBuf(size)
}

// Message envelopes per layer

// StreamChunk represents data from a stream conduit.
type StreamChunk struct {
	Data Buffer
	MD   Metadata
}

// DatagramMsg represents a message from a datagram conduit.
type DatagramMsg struct {
	Data Buffer
	Src  netip.AddrPort
	Dst  netip.AddrPort
	MD   Metadata
}

// IPPacket represents an IP packet from a network conduit.
type IPPacket struct {
	Data Buffer
	Src  netip.Addr
	Dst  netip.Addr
	// Proto is the IP protocol number.
	Proto int
	V6    bool
	MD    Metadata
}

// FramePkt represents an Ethernet frame.
type FramePkt struct {
	Data      Buffer
	Src       net.HardwareAddr
	Dst       net.HardwareAddr
	EtherType uint16
	IfIndex   int
	MD        Metadata
}

// Conduit contract

// Conduit represents a connection at a specific network layer.
type Conduit[V any] interface {
	// Dial establishes the connection.
	Dial(ctx context.Context) error
	// Close tears down the connection.
	Close() error

	Kind() Kind
	// Stack returns the protocol stack layers.
	Stack() []string

	// Underlying returns the layer-specific interface for I/O.
	Underlying() V
}

// L4: Stream (TCP/TLS)

// Stream is an interface for byte-stream protocols (e.g., TCP, TLS).
type Stream interface {
	// Recv reads data from the stream.
	Recv(ctx context.Context, opts *RecvOptions) (*StreamChunk, error)
	// Send writes data to the stream.
	Send(ctx context.Context, p []byte, buf Buffer, opts *SendOptions) (n int, md Metadata, err error)

	Close() error
	// CloseWrite shuts down the sending side.
	CloseWrite() error

	SetDeadline(t time.Time) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

// L4: Datagram (UDP/DTLS)

// Datagram is an interface for message-oriented protocols (e.g., UDP, DTLS).
type Datagram interface {
	Recv(ctx context.Context, opts *RecvOptions) (*DatagramMsg, error)
	Send(ctx context.Context, msg *DatagramMsg, opts *SendOptions) (n int, md Metadata, err error)

	SetDeadline(t time.Time) error
	LocalAddr() netip.AddrPort
	RemoteAddr() netip.AddrPort
}

// L3: Network (Raw IP)

// Network is an interface for raw IP packet manipulation (Layer 3).
type Network interface {
	Recv(ctx context.Context, opts *RecvOptions) (*IPPacket, error)
	Send(ctx context.Context, pkt *IPPacket, opts *SendOptions) (n int, md Metadata, err error)

	SetDeadline(t time.Time) error
	LocalAddr() netip.Addr
	Proto() int
	IsIPv6() bool
}

// L2: Frame (Ethernet)

// Frame is an interface for raw Ethernet frame manipulation (Layer 2).
type Frame interface {
	Recv(ctx context.Context, opts *RecvOptions) (*FramePkt, error)
	Send(ctx context.Context, pkt *FramePkt, opts *SendOptions) (n int, md Metadata, err error)

	SetDeadline(t time.Time) error
	Interface() *net.Interface
}
