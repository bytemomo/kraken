package adapters

import (
	"context"
	"errors"
	"io"

	"bytemomo/trident/conduit"
)

var (
	errNoStream = errors.New("adapters: stream is nil")
)

// StreamWriter adapts a conduit.Stream to the io.Writer interface.
// A static context and send options can be provided; otherwise context.Background
// and nil options will be used for each write.
type StreamWriter struct {
	Stream conduit.Stream
	Ctx    context.Context
	Opts   *conduit.SendOptions
}

// Write sends p via the wrapped conduit.Stream.
func (w *StreamWriter) Write(p []byte) (int, error) {
	if w == nil || w.Stream == nil {
		return 0, errNoStream
	}
	if len(p) == 0 {
		return 0, nil
	}
	ctx := w.ctx()
	n, _, err := w.Stream.Send(ctx, p, nil, w.Opts)
	return n, err
}

func (w *StreamWriter) ctx() context.Context {
	if w.Ctx != nil {
		return w.Ctx
	}
	return context.Background()
}

// StreamReader adapts a conduit.Stream to the io.Reader interface.
// It buffers any surplus bytes from Recv so successive Read calls see
// a continuous stream of data.
type StreamReader struct {
	Stream conduit.Stream
	Ctx    context.Context
	Opts   *conduit.RecvOptions

	buf        conduit.Buffer
	off        int
	pendingErr error
}

// Read pulls data from the wrapped Stream, copying it into p.
func (r *StreamReader) Read(p []byte) (int, error) {
	if r == nil || r.Stream == nil {
		return 0, errNoStream
	}
	if len(p) == 0 {
		return 0, nil
	}

	for {
		if r.buf != nil {
			n := r.drainBuffer(p)
			if n > 0 {
				return n, nil
			}
			// Buffer exhausted; check pending error.
			if r.pendingErr != nil {
				err := r.pendingErr
				r.pendingErr = nil
				return 0, err
			}
			continue
		}

		if r.pendingErr != nil {
			err := r.pendingErr
			r.pendingErr = nil
			return 0, err
		}

		ctx := r.ctx()
		opts := r.recvOpts(len(p))
		chunk, err := r.Stream.Recv(ctx, opts)
		if err != nil && (chunk == nil || chunk.Data == nil) {
			return 0, err
		}
		if chunk == nil || chunk.Data == nil {
			if err == nil {
				err = io.EOF
			}
			return 0, err
		}

		r.buf = chunk.Data
		r.off = 0
		r.pendingErr = err
	}
}

// Close releases any buffered data.
func (r *StreamReader) Close() error {
	if r.buf != nil {
		r.buf.Release()
		r.buf = nil
		r.off = 0
	}
	r.pendingErr = nil
	return nil
}

func (r *StreamReader) drainBuffer(p []byte) int {
	if r.buf == nil {
		return 0
	}
	data := r.buf.Bytes()
	if r.off >= len(data) {
		r.buf.Release()
		r.buf = nil
		r.off = 0
		return 0
	}
	n := copy(p, data[r.off:])
	r.off += n
	if r.off >= len(data) {
		r.buf.Release()
		r.buf = nil
		r.off = 0
	}
	return n
}

func (r *StreamReader) ctx() context.Context {
	if r.Ctx != nil {
		return r.Ctx
	}
	return context.Background()
}

func (r *StreamReader) recvOpts(max int) *conduit.RecvOptions {
	if r.Opts == nil && max <= 0 {
		return nil
	}
	if r.Opts == nil {
		return &conduit.RecvOptions{MaxBytes: max}
	}
	opts := *r.Opts
	if opts.MaxBytes == 0 && max > 0 {
		opts.MaxBytes = max
	}
	return &opts
}
