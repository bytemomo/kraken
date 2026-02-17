package datalink

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"bytemomo/trident/conduit"
	"bytemomo/trident/conduit/utils"
)

const (
	EtherTypeEtherCAT = 0x88A4
)

// EthernetConduit is a conduit that operates at the Ethernet frame level (Layer 2).
// It allows sending and receiving raw Ethernet frames on a specific network interface.
// This requires elevated privileges to run.
type EthernetConduit struct {
	ifc       *net.Interface
	mu        sync.Mutex
	handle    *pcap.Handle
	dst       net.HardwareAddr
	etherType uint16
}

type ethFrame EthernetConduit

// Ethernet creates a new Ethernet datalink-level conduit.
//
// ifaceName is the name of the network interface to bind to (e.g., "eth0").
// defaultDst is the default destination MAC address for Send operations.
// etherType specifies the EtherType to listen for. If 0, all EtherTypes are captured.
func Ethernet(ifaceName string, defaultDst net.HardwareAddr, etherType uint16) conduit.Conduit[conduit.Frame] {
	return &EthernetConduit{
		ifc:       &net.Interface{Name: ifaceName},
		dst:       defaultDst,
		etherType: etherType,
	}
}

func (e *EthernetConduit) Dial(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handle != nil {
		return nil
	}

	ifc, err := net.InterfaceByName(e.ifc.Name)
	if err != nil {
		return err
	}
	e.ifc = ifc

	// Open pcap handle: snaplen=1600, promiscuous=true, timeout=1ms (for non-blocking behavior)
	handle, err := pcap.OpenLive(e.ifc.Name, 1600, true, time.Millisecond)
	if err != nil {
		return err
	}

	// Set BPF filter if specific EtherType requested
	if e.etherType != 0 {
		filter := "ether proto 0x" + itoa16(e.etherType)
		if err := handle.SetBPFFilter(filter); err != nil {
			handle.Close()
			return err
		}
	}

	e.handle = handle
	return nil
}

func (e *EthernetConduit) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handle != nil {
		e.handle.Close()
		e.handle = nil
	}
	return nil
}

func (e *EthernetConduit) Kind() conduit.Kind        { return conduit.KindFrame }
func (e *EthernetConduit) Stack() []string           { return []string{"eth"} }
func (e *EthernetConduit) Underlying() conduit.Frame { return (*ethFrame)(e) }

func (e *ethFrame) h() (*pcap.Handle, error) {
	if e.handle == nil {
		return nil, errors.New("eth: not open")
	}
	return e.handle, nil
}

func (e *ethFrame) SetDeadline(t time.Time) error {
	// pcap doesn't support deadlines directly, we handle timeouts in Recv via context
	return nil
}

func (e *ethFrame) Interface() *net.Interface { return e.ifc }

func (e *ethFrame) Recv(ctx context.Context, opts *conduit.RecvOptions) (*conduit.FramePkt, error) {
	h, err := e.h()
	if err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(h, h.LinkType())
	packetSource.NoCopy = true

	start := time.Now()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}

			data := packet.Data()
			if len(data) < 14 {
				continue
			}

			src, dst, et := parseEthernetHeader(data)

			buf := utils.GetBuf(len(data))
			copy(buf.Bytes(), data)

			md := conduit.Metadata{Start: start, End: time.Now(), IfIndex: e.ifc.Index}
			return &conduit.FramePkt{
				Data:      buf,
				Src:       src,
				Dst:       dst,
				EtherType: et,
				IfIndex:   e.ifc.Index,
				MD:        md,
			}, nil
		}
	}
}

func (e *ethFrame) Send(ctx context.Context, pkt *conduit.FramePkt, opts *conduit.SendOptions) (int, conduit.Metadata, error) {
	h, err := e.h()
	if err != nil {
		return 0, conduit.Metadata{}, err
	}

	dst := pkt.Dst
	if dst == nil {
		dst = e.dst
	}
	etherType := pkt.EtherType
	if etherType == 0 {
		etherType = e.etherType
	}
	if len(dst) != 6 {
		return 0, conduit.Metadata{}, errors.New("eth: dst MAC required")
	}

	src := e.ifc.HardwareAddr
	frame := buildEthernetFrame(src, dst, etherType, pkt.Data.Bytes())

	start := time.Now()

	if err := h.WritePacketData(frame); err != nil {
		return 0, conduit.Metadata{}, err
	}

	md := conduit.Metadata{Start: start, End: time.Now(), IfIndex: e.ifc.Index}
	return len(frame), md, nil
}

func buildEthernetFrame(src, dst net.HardwareAddr, etherType uint16, payload []byte) []byte {
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], dst)
	copy(frame[6:12], src)
	frame[12] = byte(etherType >> 8)
	frame[13] = byte(etherType)
	copy(frame[14:], payload)
	if len(frame) < 60 {
		frame = append(frame, make([]byte, 60-len(frame))...)
	}
	return frame
}

func parseEthernetHeader(b []byte) (src, dst net.HardwareAddr, etherType uint16) {
	if len(b) < 14 {
		return nil, nil, 0
	}
	dst = net.HardwareAddr(append([]byte(nil), b[0:6]...))
	src = net.HardwareAddr(append([]byte(nil), b[6:12]...))
	etherType = uint16(b[12])<<8 | uint16(b[13])
	return
}

// itoa16 converts a uint16 to hex string (without 0x prefix)
func itoa16(n uint16) string {
	const hex = "0123456789abcdef"
	buf := make([]byte, 4)
	buf[0] = hex[(n>>12)&0xf]
	buf[1] = hex[(n>>8)&0xf]
	buf[2] = hex[(n>>4)&0xf]
	buf[3] = hex[n&0xf]
	return string(buf)
}
