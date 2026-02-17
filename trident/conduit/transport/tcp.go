package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"bytemomo/trident/conduit"
	"bytemomo/trident/conduit/utils"
)

// =====================================================================================
// TCP Conduit
// =====================================================================================

// TcpConduit implements the conduit.Conduit interface for TCP connections.
// It manages the lifecycle of a net.Conn and provides a Stream interface for I/O.
type TcpConduit struct {
	addr string

	mu sync.Mutex
	c  net.Conn
}

type tcpStream TcpConduit

// TCP returns a new TCP stream conduit.
func TCP(addr string) conduit.Conduit[conduit.Stream] {
	return &TcpConduit{addr: addr}
}

func (t *TcpConduit) Dial(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.c != nil {
		return nil
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return err
	}
	t.c = c
	return nil
}

func (t *TcpConduit) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.c == nil {
		return nil
	}
	c := t.c
	t.c = nil

	if tc, ok := c.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return c.Close()
}

func (t *TcpConduit) Kind() conduit.Kind         { return conduit.KindStream }
func (t *TcpConduit) Stack() []string            { return []string{"tcp"} }
func (t *TcpConduit) Underlying() conduit.Stream { return (*tcpStream)(t) }

// =====================================================================================
// tcpStream implements conduit.Stream
// =====================================================================================

func (t *tcpStream) conn() (net.Conn, error) {
	if t.c == nil {
		return nil, errors.New("tcp: not connected")
	}
	return t.c, nil
}

func (t *tcpStream) Close() error { return (*TcpConduit)(t).Close() }

func (t *tcpStream) CloseWrite() error {
	c, err := t.conn()
	if err != nil {
		return err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return nil
}

func armDeadline(ctx context.Context, c net.Conn, isRead bool) (cancel func()) {
	dl, ok := ctx.Deadline()
	if !ok {
		return func() {}
	}

	if isRead {
		_ = c.SetReadDeadline(dl)
		return func() { _ = c.SetReadDeadline(time.Time{}) }
	}
	_ = c.SetWriteDeadline(dl)
	return func() { _ = c.SetWriteDeadline(time.Time{}) }
}

func (t *tcpStream) Recv(ctx context.Context, opts *conduit.RecvOptions) (*conduit.StreamChunk, error) {
	c, err := t.conn()
	if err != nil {
		return nil, err
	}

	size := 32 * 1024
	if opts != nil && opts.MaxBytes > 0 {
		size = opts.MaxBytes
	}
	buf := utils.GetBuf(size)
	b := buf.Bytes()

	start := time.Now()
	cancel := armDeadline(ctx, c, true)
	n, rerr := c.Read(b)
	cancel()

	if n > 0 {
		buf.ShrinkTo(n)
	} else {
		buf.Release()
	}

	md := conduit.Metadata{
		Start: start,
		End:   time.Now(),
		Proto: 6, // TCP
	}

	if errors.Is(rerr, io.EOF) || errors.Is(rerr, net.ErrClosed) {
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseRead()
		}
		(*TcpConduit)(t).mu.Lock()
		_ = c.Close()
		if (*TcpConduit)(t).c == c {
			(*TcpConduit)(t).c = nil
		}
		(*TcpConduit)(t).mu.Unlock()
	}

	if ctxErr := ctx.Err(); ctxErr != nil && rerr == nil {
		rerr = ctxErr
	}

	if n <= 0 {
		return &conduit.StreamChunk{Data: nil, MD: md}, rerr
	}
	return &conduit.StreamChunk{Data: buf, MD: md}, rerr
}

func (t *tcpStream) Send(ctx context.Context, p []byte, buf conduit.Buffer, _ *conduit.SendOptions) (int, conduit.Metadata, error) {
	c, err := t.conn()
	if err != nil {
		return 0, conduit.Metadata{}, err
	}

	var payload []byte
	if buf != nil {
		payload = buf.Bytes()
	} else {
		payload = p
	}

	start := time.Now()
	cancel := armDeadline(ctx, c, false)
	n, werr := c.Write(payload)
	cancel()

	md := conduit.Metadata{
		Start: start,
		End:   time.Now(),
		Proto: 6, // TCP
	}

	if ctxErr := ctx.Err(); ctxErr != nil && werr == nil {
		werr = ctxErr
	}
	return n, md, werr
}

func (t *tcpStream) SetDeadline(tt time.Time) error {
	c, err := t.conn()
	if err != nil {
		return err
	}
	return c.SetDeadline(tt)
}

func (t *tcpStream) LocalAddr() net.Addr {
	c, _ := t.conn()
	if c == nil {
		return nil
	}
	return c.LocalAddr()
}

func (t *tcpStream) RemoteAddr() net.Addr {
	c, _ := t.conn()
	if c == nil {
		return nil
	}
	return c.RemoteAddr()
}
