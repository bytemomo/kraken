package transport_test

import (
	cond "bytemomo/trident/conduit"
	tr "bytemomo/trident/conduit/transport"
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// --- tiny test buffer (implements cond.Buffer) ---
type testBuf struct{ b []byte }

func (tb *testBuf) Bytes() []byte       { return tb.b }
func (tb *testBuf) Grow(n int) []byte   { tb.b = make([]byte, n); return tb.b }
func (tb *testBuf) Shrink(n int) []byte { tb.b = make([]byte, n); return tb.b }
func (tb *testBuf) Release()            { /* no-op for tests */ }

// --- TCP test ---
func TestTCP_RecvSend_Echo(t *testing.T) {
	addr, stop := startTCPEcho(t)
	defer stop()

	c := tr.TCP(addr)
	ctx := mustCtx(t, 3*time.Second)
	if err := c.Dial(ctx); err != nil {
		t.Fatalf("dial: %v", err)
	}

	s := c.Underlying()

	msg := []byte("hello over tcp")
	n, md, err := s.Send(ctx, msg, nil, nil)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if n != len(msg) {
		t.Fatalf("send n=%d want %d", n, len(msg))
	}
	if md.Proto != 6 {
		t.Fatalf("metadata proto=%d want 6", md.Proto)
	}

	chunk, err := s.Recv(ctx, &cond.RecvOptions{MaxBytes: 64})
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if chunk == nil || chunk.Data == nil {
		t.Fatalf("recv empty chunk")
	}
	defer chunk.Data.Release()
	if string(chunk.Data.Bytes()) != string(msg) {
		t.Fatalf("echo mismatch got=%q want=%q", string(chunk.Data.Bytes()), string(msg))
	}

	if err := s.CloseWrite(); err != nil {
		t.Fatalf("closeWrite: %v", err)
	}
	_ = s.Close()
}

func TestTCP_PersistentLoop(t *testing.T) {
	addr, stop := startTCPEcho(t)
	defer stop()

	c := tr.TCP(addr)
	ctx := mustCtx(t, 10*time.Second)
	if err := c.Dial(ctx); err != nil {
		t.Fatalf("dial: %v", err)
	}
	s := c.Underlying()

	const iters = 300
	for i := 0; i < iters; i++ {
		payload := []byte(fmt.Sprintf("tcp-msg-%06d", i))

		// write
		wctx, wcancel := context.WithTimeout(ctx, 2*time.Second)
		n, md, err := s.Send(wctx, payload, nil, nil)
		wcancel()
		if err != nil {
			t.Fatalf("send #%d: %v", i, err)
		}
		if n != len(payload) {
			t.Fatalf("send n=%d want=%d", n, len(payload))
		}
		if md.Proto != 6 {
			t.Fatalf("proto=%d want 6 (tcp)", md.Proto)
		}

		// read echo
		deadline := time.Now().Add(5 * time.Second)
		want := payload
		got := make([]byte, 0, len(want))

		for len(got) < len(want) {
			rctx, rcancel := context.WithDeadline(ctx, deadline)
			chunk, err := s.Recv(rctx, &cond.RecvOptions{MaxBytes: 128})
			rcancel()
			if err != nil {
				t.Fatalf("recv #%d: %v", i, err)
			}
			if chunk != nil && chunk.Data != nil {
				got = append(got, chunk.Data.Bytes()...)
				chunk.Data.Release()
			}
		}
		if string(got) != string(want) {
			t.Fatalf("echo mismatch #%d: got=%q want=%q", i, got, want)
		}
	}

	// graceful shutdown
	_ = s.CloseWrite()
	_ = s.Close()
}

// --- UDP test ---
func TestUDP_RecvSend_Echo(t *testing.T) {
	addr, stop := startUDPEcho(t)
	defer stop()

	c := tr.UDP(addr)
	ctx := mustCtx(t, 3*time.Second)
	if err := c.Dial(ctx); err != nil {
		t.Fatalf("dial: %v", err)
	}

	d := c.Underlying()

	payload := []byte("hello over udp")
	tb := &testBuf{b: append([]byte(nil), payload...)}
	defer tb.Release()

	dstAP, _ := netip.ParseAddrPort(addr)
	msg := &cond.DatagramMsg{
		Data: tb,
		Dst:  dstAP,
	}

	n, md, err := d.Send(ctx, msg, nil)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("send n=%d want %d", n, len(payload))
	}
	if md.Proto != 17 {
		t.Fatalf("metadata proto=%d want 17", md.Proto)
	}

	resp, err := d.Recv(ctx, &cond.RecvOptions{MaxBytes: 64})
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if resp == nil || resp.Data == nil {
		t.Fatalf("recv empty")
	}
	defer resp.Data.Release()
	if string(resp.Data.Bytes()) != string(payload) {
		t.Fatalf("echo mismatch got=%q want=%q", string(resp.Data.Bytes()), string(payload))
	}

	_ = d.SetDeadline(time.Now().Add(50 * time.Millisecond))
	_ = c.Close()
}

func TestUDP_SendNilMessage(t *testing.T) {
	addr, stop := startUDPEcho(t)
	defer stop()

	c := tr.UDP(addr)
	ctx := mustCtx(t, 3*time.Second)
	if err := c.Dial(ctx); err != nil {
		t.Fatalf("dial: %v", err)
	}

	d := c.Underlying()

	if _, _, err := d.Send(ctx, nil, nil); err == nil {
		t.Fatalf("expected error when sending nil message")
	} else if err.Error() != "udp: message is nil" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUDP_PersistentLoop(t *testing.T) {
	addr, stop := startUDPEcho(t)
	defer stop()

	c := tr.UDP(addr)
	ctx := mustCtx(t, 10*time.Second)
	if err := c.Dial(ctx); err != nil {
		t.Fatalf("dial: %v", err)
	}
	d := c.Underlying()

	const iters = 500
	dstAP, _ := netip.ParseAddrPort(addr)

	for i := 0; i < iters; i++ {
		payload := fmt.Appendf([]byte{}, "udp-msg-%06d", i)
		tb := &testBuf{b: append([]byte(nil), payload...)} // copy for safety

		msg := &cond.DatagramMsg{Data: tb}
		wctx, wcancel := context.WithTimeout(ctx, 2*time.Second)
		n, md, err := d.Send(wctx, msg, nil)
		wcancel()
		tb.Release()

		if err != nil {
			t.Fatalf("send #%d: %v", i, err)
		}
		if n != len(payload) {
			t.Fatalf("send n=%d want=%d", n, len(payload))
		}
		if md.Proto != 17 {
			t.Fatalf("proto=%d want 17 (udp)", md.Proto)
		}

		// Receive echo
		rctx, rcancel := context.WithTimeout(ctx, 2*time.Second)
		resp, err := d.Recv(rctx, &cond.RecvOptions{MaxBytes: 128})
		rcancel()
		if err != nil {
			t.Fatalf("recv #%d: %v", i, err)
		}
		if resp == nil || resp.Data == nil {
			t.Fatalf("recv #%d: empty resp", i)
		}
		got := append([]byte(nil), resp.Data.Bytes()...)
		resp.Data.Release()

		if string(got) != string(payload) {
			t.Fatalf("echo mismatch #%d: got=%q want=%q (dst=%s)", i, got, payload, dstAP)
		}
	}

	_ = c.Close()
}

// parallel TCP/UDP stress (quick)
func TestTCP_UDP_Parallel(t *testing.T) {
	t.Parallel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); TestTCP_RecvSend_Echo(t) }()
	go func() { defer wg.Done(); TestUDP_RecvSend_Echo(t) }()
	wg.Wait()
}

// --- helpers ---
func mustCtx(t *testing.T, dur time.Duration) context.Context {
	t.Helper()
	ctx, _ := context.WithTimeout(context.Background(), dur)
	return ctx
}

func startTCPEcho(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(cc net.Conn) {
				defer cc.Close()
				buf := make([]byte, 64<<10)
				for {
					n, err := cc.Read(buf)
					if n > 0 {
						_, _ = cc.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }
}

func startUDPEcho(t *testing.T) (addr string, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64<<10)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], a)
		}
	}()
	return pc.LocalAddr().String(), func() { _ = pc.Close(); <-done }
}
