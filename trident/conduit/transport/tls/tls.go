package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"bytemomo/trident/conduit"
	"bytemomo/trident/conduit/utils"
)

// TlsClient is a conduit that wraps another stream-based conduit (like TCP)
// to provide a TLS-encrypted channel.
type TlsClient struct {
	inner conduit.Conduit[conduit.Stream]
	cfg   *tls.Config

	mu   sync.Mutex
	conn *tls.Conn
}

// tlsStream implements conduit.Stream.
type tlsStream TlsClient

// NewTlsClient creates a new TLS client conduit.
func NewTlsClient(inner conduit.Conduit[conduit.Stream], cfg *tls.Config) conduit.Conduit[conduit.Stream] {
	return &TlsClient{inner: inner, cfg: cfg}
}

func (t *TlsClient) Dial(ctx context.Context) error {
	if err := t.inner.Dial(ctx); err != nil {
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		return nil
	}

	base := &streamToConn{S: t.inner.Underlying()}
	c := tls.Client(base, t.cfg)
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if err := c.HandshakeContext(ctx); err != nil {
		_ = c.Close()
		return err
	}
	t.conn = c
	return nil
}

func (t *TlsClient) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		_ = t.conn.Close()
		t.conn = nil
	}
	return t.inner.Close()
}

func (t *TlsClient) Kind() conduit.Kind { return conduit.KindStream }

func (t *TlsClient) Stack() []string {
	return append([]string{"tls"}, t.inner.Stack()...)
}

func (t *TlsClient) Underlying() conduit.Stream { return (*tlsStream)(t) }

func (t *tlsStream) c() (*tls.Conn, error) {
	if t.conn == nil {
		return nil, errors.New("tls: not connected")
	}
	return t.conn, nil
}

func (t *tlsStream) Recv(ctx context.Context, opts *conduit.RecvOptions) (*conduit.StreamChunk, error) {
	c, err := t.c()
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
	cancel := armDeadlinee(ctx, c, true)
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
		Proto: 6,
	}

	if ctxErr := ctx.Err(); ctxErr != nil && rerr == nil {
		rerr = ctxErr
	}

	if n <= 0 {
		return &conduit.StreamChunk{Data: nil, MD: md}, rerr
	}
	return &conduit.StreamChunk{Data: buf, MD: md}, rerr
}

func (t *tlsStream) Send(ctx context.Context, p []byte, buf conduit.Buffer, _ *conduit.SendOptions) (int, conduit.Metadata, error) {
	c, err := t.c()
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
	cancel := armDeadlinee(ctx, c, false)
	n, werr := c.Write(payload)
	cancel()

	md := conduit.Metadata{
		Start: start,
		End:   time.Now(),
		Proto: 6,
	}
	if ctxErr := ctx.Err(); ctxErr != nil && werr == nil {
		werr = ctxErr
	}
	return n, md, werr
}

func (t *tlsStream) Close() error {
	tlsC, err := t.c()
	if err != nil {
		return err
	}
	return tlsC.Close()
}

func (t *tlsStream) CloseWrite() error {
	tlsC, err := t.c()
	if err != nil {
		return err
	}
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := any(tlsC).(closeWriter); ok {
		return cw.CloseWrite()
	}

	if uc, ok := underlyingNetConn(tlsC); ok {
		if tc, ok := uc.(*net.TCPConn); ok {
			return tc.CloseWrite()
		}
	}
	return nil
}

func (t *tlsStream) SetDeadline(tt time.Time) error {
	c, err := t.c()
	if err != nil {
		return err
	}
	return c.SetDeadline(tt)
}

func (t *tlsStream) LocalAddr() net.Addr {
	c, _ := t.c()
	if c == nil {
		return nil
	}
	return c.LocalAddr()
}

func (t *tlsStream) RemoteAddr() net.Addr {
	c, _ := t.c()
	if c == nil {
		return nil
	}
	return c.RemoteAddr()
}

// streamToConn adapts a conduit.Stream to net.Conn for the TLS handshake.
type streamToConn struct {
	S conduit.Stream

	mu           sync.Mutex
	rdl, wdl     time.Time
	bothDeadline time.Time
}

func (w *streamToConn) deadline(isRead bool) (time.Time, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	dl := w.bothDeadline
	if isRead {
		if !w.rdl.IsZero() {
			dl = w.rdl
		}
	} else {
		if !w.wdl.IsZero() {
			dl = w.wdl
		}
	}
	if dl.IsZero() {
		return time.Time{}, false
	}
	return dl, true
}

func (w *streamToConn) Read(p []byte) (int, error) {
	ctx := context.Background()
	if dl, ok := w.deadline(true); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, dl)
		defer cancel()
	}
	chunk, err := w.S.Recv(ctx, &conduit.RecvOptions{MaxBytes: len(p)})
	if err != nil && (chunk == nil || chunk.Data == nil) {
		return 0, err
	}
	n := 0
	if chunk != nil && chunk.Data != nil {
		b := chunk.Data.Bytes()
		if len(b) > len(p) {
			b = b[:len(p)]
		}
		n = copy(p, b)
		chunk.Data.Release()
	}
	return n, err
}

func (w *streamToConn) Write(p []byte) (int, error) {
	ctx := context.Background()
	if dl, ok := w.deadline(false); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, dl)
		defer cancel()
	}
	n, _, err := w.S.Send(ctx, p, nil, nil)
	return n, err
}

func (w *streamToConn) Close() error         { return w.S.Close() }
func (w *streamToConn) LocalAddr() net.Addr  { return w.S.LocalAddr() }
func (w *streamToConn) RemoteAddr() net.Addr { return w.S.RemoteAddr() }
func (w *streamToConn) SetDeadline(t time.Time) error {
	w.mu.Lock()
	w.bothDeadline = t
	w.mu.Unlock()
	return w.S.SetDeadline(t)
}

func (w *streamToConn) SetReadDeadline(t time.Time) error {
	w.mu.Lock()
	w.rdl = t
	w.mu.Unlock()
	return w.S.SetDeadline(t)
}

func (w *streamToConn) SetWriteDeadline(t time.Time) error {
	w.mu.Lock()
	w.wdl = t
	w.mu.Unlock()
	return w.S.SetDeadline(t)
}

func underlyingNetConn(c *tls.Conn) (net.Conn, bool) {
	type netConnGetter interface{ NetConn() net.Conn }
	if g, ok := any(c).(netConnGetter); ok {
		return g.NetConn(), true
	}
	return nil, false
}

func armDeadlinee(ctx context.Context, c net.Conn, isRead bool) (cancel func()) {
	if dl, ok := ctx.Deadline(); ok {
		if isRead {
			_ = c.SetReadDeadline(dl)
		} else {
			_ = c.SetWriteDeadline(dl)
		}
	}
	select {
	case <-ctx.Done():
		if isRead {
			_ = c.SetReadDeadline(time.Now().Add(-time.Millisecond))
		} else {
			_ = c.SetWriteDeadline(time.Now().Add(-time.Millisecond))
		}
		return func() {}
	default:
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if isRead {
				_ = c.SetReadDeadline(time.Now().Add(-time.Millisecond))
			} else {
				_ = c.SetWriteDeadline(time.Now().Add(-time.Millisecond))
			}
		case <-done:
		}
	}()
	return func() { close(done) }
}