package adapters_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"bytemomo/trident/conduit"
	"bytemomo/trident/conduit/adapters"
)

func TestStreamWriterWrite(t *testing.T) {
	stub := &stubStream{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := &adapters.StreamWriter{
		Stream: stub,
		Ctx:    ctx,
	}

	n, err := w.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if n != 5 {
		t.Fatalf("Write n=%d want 5", n)
	}
	if len(stub.sent) != 1 || string(stub.sent[0]) != "hello" {
		t.Fatalf("unexpected sent payloads: %#v", stub.sent)
	}
	if stub.lastSendCtx != ctx {
		t.Fatalf("Send context mismatch")
	}
}

func TestStreamReaderSequential(t *testing.T) {
	stub := &stubStream{
		recvQueue: []recvItem{
			{data: []byte("hello "), err: nil},
			{data: []byte("world"), err: io.EOF},
		},
	}

	r := &adapters.StreamReader{Stream: stub}
	defer r.Close()

	buf := make([]byte, 3)

	read := func(want string) {
		n, err := r.Read(buf)
		if err != nil {
			t.Fatalf("Read error: %v", err)
		}
		if string(buf[:n]) != want {
			t.Fatalf("Read got %q want %q", string(buf[:n]), want)
		}
	}

	read("hel")
	read("lo ")
	read("wor")

	n, err := r.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if string(buf[:n]) != "ld" {
		t.Fatalf("final chunk = %q want %q", string(buf[:n]), "ld")
	}

	n, err = r.Read(buf)
	if n != 0 || err != io.EOF {
		t.Fatalf("expected EOF, got n=%d err=%v", n, err)
	}
}

// --- test helpers ---

type recvItem struct {
	data []byte
	err  error
}

type stubStream struct {
	sent        [][]byte
	lastSendCtx context.Context
	recvQueue   []recvItem
}

func (s *stubStream) Recv(ctx context.Context, _ *conduit.RecvOptions) (*conduit.StreamChunk, error) {
	if len(s.recvQueue) == 0 {
		return nil, io.EOF
	}
	item := s.recvQueue[0]
	s.recvQueue = s.recvQueue[1:]
	var buf conduit.Buffer
	if len(item.data) > 0 {
		buf = &testBuffer{b: append([]byte(nil), item.data...)}
	}
	return &conduit.StreamChunk{Data: buf}, item.err
}

func (s *stubStream) Send(ctx context.Context, p []byte, buf conduit.Buffer, _ *conduit.SendOptions) (int, conduit.Metadata, error) {
	s.lastSendCtx = ctx
	payload := append([]byte(nil), p...)
	if buf != nil {
		payload = append([]byte(nil), buf.Bytes()...)
	}
	s.sent = append(s.sent, payload)
	return len(payload), conduit.Metadata{}, nil
}

func (s *stubStream) Close() error      { return nil }
func (s *stubStream) CloseWrite() error { return nil }
func (s *stubStream) SetDeadline(time.Time) error {
	return nil
}
func (s *stubStream) LocalAddr() net.Addr  { return stubAddr("local") }
func (s *stubStream) RemoteAddr() net.Addr { return stubAddr("remote") }

type stubAddr string

func (a stubAddr) Network() string { return "stub" }
func (a stubAddr) String() string  { return string(a) }

type testBuffer struct {
	b []byte
}

func (tb *testBuffer) Bytes() []byte       { return tb.b }
func (tb *testBuffer) Grow(n int) []byte   { tb.b = append(tb.b, make([]byte, n)...); return tb.b }
func (tb *testBuffer) Shrink(n int) []byte { tb.b = tb.b[:len(tb.b)-min(n, len(tb.b))]; return tb.b }
func (tb *testBuffer) Release()            { tb.b = nil }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
