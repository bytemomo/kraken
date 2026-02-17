package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"bytemomo/trident/conduit"
	"bytemomo/trident/conduit/utils"
)

// UdpConduit implements conduit.Conduit for connected UDP sockets.
type UdpConduit struct {
	addr string

	mu   sync.Mutex
	c    *net.UDPConn
	peer netip.AddrPort
}

// udpDatagram implements conduit.Datagram.
type udpDatagram UdpConduit

// UDP returns a new UDP datagram conduit.
func UDP(addr string) conduit.Conduit[conduit.Datagram] { return &UdpConduit{addr: addr} }

func (u *UdpConduit) Dial(ctx context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.c != nil {
		return nil
	}
	raddr, err := net.ResolveUDPAddr("udp", u.addr)
	if err != nil {
		return err
	}
	c, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}
	u.c = c
	u.peer = udpAddrToAddrPort(raddr)
	return nil
}

func (u *UdpConduit) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.c != nil {
		_ = u.c.Close()
		u.c = nil
		u.peer = netip.AddrPort{}
	}
	return nil
}

func (u *UdpConduit) Kind() conduit.Kind { return conduit.KindDatagram }
func (u *UdpConduit) Stack() []string    { return []string{"udp"} }

func (u *UdpConduit) Underlying() conduit.Datagram { return (*udpDatagram)(u) }

func (u *udpDatagram) pkt() (*net.UDPConn, error) {
	if u.c == nil {
		return nil, errors.New("udp: not connected/bound")
	}
	return u.c, nil
}

func (u *udpDatagram) Recv(ctx context.Context, opts *conduit.RecvOptions) (*conduit.DatagramMsg, error) {
	c, err := u.pkt()
	if err != nil {
		return nil, err
	}

	size := 64 * 1024
	if opts != nil && opts.MaxBytes > 0 {
		size = opts.MaxBytes
	}

	buf := utils.GetBuf(size)
	b := buf.Bytes()

	start := time.Now()
	cancel := armPCDeadline(ctx, c, true)

	n := 0
	var src netip.AddrPort
	var rerr error

	type readerAddrPort interface {
		ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error)
	}

	if rap, ok := any(c).(readerAddrPort); ok {
		n, src, rerr = rap.ReadFromUDPAddrPort(b)
	} else {
		n1, a, e := c.ReadFromUDP(b)
		n, rerr = n1, e
		if a != nil {
			src = udpAddrToAddrPort(a)
		}
	}
	cancel()

	if n > 0 {
		buf.ShrinkTo(n)
	} else {
		buf.Release()
	}

	local := udpAddrToAddrPortFromAddr(c.LocalAddr())
	if u.peer.IsValid() && !src.IsValid() {
		src = u.peer
	}

	md := conduit.Metadata{
		Start: start,
		End:   time.Now(),
		Proto: 17, // UDP
	}

	if n <= 0 {
		return &conduit.DatagramMsg{Data: nil, Src: src, Dst: local, MD: md}, rerr
	}

	return &conduit.DatagramMsg{Data: buf, Src: src, Dst: local, MD: md}, rerr
}

func (u *udpDatagram) Send(ctx context.Context, msg *conduit.DatagramMsg, _ *conduit.SendOptions) (int, conduit.Metadata, error) {
	if msg == nil {
		return 0, conduit.Metadata{}, errors.New("udp: message is nil")
	}

	c, err := u.pkt()
	if err != nil {
		return 0, conduit.Metadata{}, err
	}

	var payload []byte
	if msg.Data != nil {
		payload = msg.Data.Bytes()
	} else {
		payload = nil
	}

	dst := msg.Dst
	if !dst.IsValid() {
		dst = u.peer
	}
	if !dst.IsValid() {
		return 0, conduit.Metadata{}, errors.New("udp: destination not specified and socket is unconnected")
	}

	start := time.Now()
	cancel := armPCDeadline(ctx, c, false)

	n, werr := writeToUDP(c, payload, dst, u.peer.IsValid())
	cancel()

	md := conduit.Metadata{
		Start: start,
		End:   time.Now(),
		Proto: 17, // UDP
	}
	return n, md, werr
}

func (u *udpDatagram) SetDeadline(t time.Time) error {
	c, err := u.pkt()
	if err != nil {
		return err
	}
	return c.SetDeadline(t)
}

func (u *udpDatagram) LocalAddr() netip.AddrPort {
	c, _ := u.pkt()
	if c == nil {
		return netip.AddrPort{}
	}
	return udpAddrToAddrPortFromAddr(c.LocalAddr())
}

func (u *udpDatagram) RemoteAddr() netip.AddrPort { return u.peer }

func udpAddrToAddrPort(a *net.UDPAddr) netip.AddrPort {
	if a == nil {
		return netip.AddrPort{}
	}
	ip, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		return netip.AddrPort{}
	}
	if a.Zone != "" && ip.Is6() {
		ip = ip.WithZone(a.Zone)
	}
	return netip.AddrPortFrom(ip, uint16(a.Port))
}

func udpAddrToAddrPortFromAddr(a net.Addr) netip.AddrPort {
	ua, _ := a.(*net.UDPAddr)
	return udpAddrToAddrPort(ua)
}

func writeToUDP(c *net.UDPConn, payload []byte, dst netip.AddrPort, connected bool) (int, error) {
	if connected {
		return c.Write(payload)
	}

	type writerAddrPort interface {
		WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
	}

	if wap, ok := any(c).(writerAddrPort); ok {
		return wap.WriteToUDPAddrPort(payload, dst)
	}

	ua := &net.UDPAddr{IP: dst.Addr().AsSlice(), Port: int(dst.Port()), Zone: dst.Addr().Zone()}
	return c.WriteToUDP(payload, ua)
}

func armPCDeadline(ctx context.Context, pc net.PacketConn, isRead bool) (cancel func()) {
	dl, ok := ctx.Deadline()
	if !ok {
		return func() {}
	}

	if isRead {
		_ = pc.SetReadDeadline(dl)
		return func() { _ = pc.SetReadDeadline(time.Time{}) }
	}
	_ = pc.SetWriteDeadline(dl)
	return func() { _ = pc.SetWriteDeadline(time.Time{}) }
}