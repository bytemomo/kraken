package logging

import (
	"context"
	"net"
	"net/netip"
	"time"

	"bytemomo/trident/conduit"

	"github.com/sirupsen/logrus"
)

// LoggingConduit is a decorator that wraps any conduit to provide detailed logging
// of its operations. This is useful for debugging network interactions.
// It uses the standard fmt package for output, but could be adapted for any
// structured logging library.
type LoggingConduit[V any] struct {
	inner conduit.Conduit[V]
	log   *logrus.Entry
}

// NewLoggingConduit creates a new logging conduit decorator.
//
// name provides a descriptive name for the connection, used as a prefix in log messages.
// inner is the conduit to be wrapped.
func NewLoggingConduit[V any](name string, inner conduit.Conduit[V]) conduit.Conduit[V] {
	log := logrus.WithField("conduit", name)
	return &LoggingConduit[V]{inner: inner, log: log}
}

func (l *LoggingConduit[V]) Dial(ctx context.Context) error {
	l.log.Debug("Dialing...")
	start := time.Now()
	err := l.inner.Dial(ctx)
	duration := time.Since(start)
	if err != nil {
		l.log.WithError(err).WithField("duration", duration).Error("Dial failed")
		return err
	}
	l.log.WithField("duration", duration).Info("Dial successful")
	return nil
}

func (l *LoggingConduit[V]) Close() error {
	l.log.Debug("Closing...")
	err := l.inner.Close()
	if err != nil {
		l.log.WithError(err).Error("Close failed")
		return err
	}
	l.log.Info("Closed.")
	return nil
}

func (l *LoggingConduit[V]) Kind() conduit.Kind {
	kind := l.inner.Kind()
	l.log.WithField("kind", kind).Debug("Kind()")
	return kind
}

func (l *LoggingConduit[V]) Stack() []string {
	stack := l.inner.Stack()
	l.log.WithField("stack", stack).Debug("Stack()")
	return stack
}

func (l *LoggingConduit[V]) Underlying() V {
	innerV := l.inner.Underlying()
	switch v := any(innerV).(type) {
	case conduit.Stream:
		return any(&loggingStream{inner: v, log: l.log}).(V)
	case conduit.Datagram:
		return any(&loggingDatagram{inner: v, log: l.log}).(V)
	case conduit.Network:
		return any(&loggingNetwork{inner: v, log: l.log}).(V)
	case conduit.Frame:
		return any(&loggingFrame{inner: v, log: l.log}).(V)
	default:
		return innerV
	}
}

type loggingNetwork struct {
	inner conduit.Network
	log   *logrus.Entry
}

func (l *loggingNetwork) Recv(ctx context.Context, opts *conduit.RecvOptions) (*conduit.IPPacket, error) {
	l.log.Trace("Recv(network)...")
	start := time.Now()
	pkt, err := l.inner.Recv(ctx, opts)
	duration := time.Since(start)
	if err != nil {
		l.log.WithError(err).WithField("duration", duration).Error("Recv(network) failed")
		return nil, err
	}
	if pkt != nil && pkt.Data != nil {
		l.log.WithFields(logrus.Fields{
			"duration": duration,
			"bytes":    len(pkt.Data.Bytes()),
			"src":      pkt.Src,
		}).Info("Recv(network) successful")
	} else {
		l.log.WithField("duration", duration).Debug("Recv(network) successful: empty packet")
	}
	return pkt, nil
}

func (l *loggingNetwork) Send(ctx context.Context, pkt *conduit.IPPacket, opts *conduit.SendOptions) (int, conduit.Metadata, error) {
	l.log.Trace("Send(network)...")
	start := time.Now()
	n, md, err := l.inner.Send(ctx, pkt, opts)
	duration := time.Since(start)
	if err != nil {
		l.log.WithError(err).WithField("duration", duration).Error("Send(network) failed")
		return 0, md, err
	}
	if pkt != nil && pkt.Data != nil {
		l.log.WithFields(logrus.Fields{
			"duration": duration,
			"bytes":    n,
			"dst":      pkt.Dst,
		}).Info("Send(network) successful")
	} else {
		l.log.WithField("duration", duration).Debug("Send(network) successful: empty packet")
	}
	return n, md, nil
}

func (l *loggingNetwork) SetDeadline(t time.Time) error {
	l.log.WithField("deadline", t).Trace("SetDeadline(network)")
	return l.inner.SetDeadline(t)
}

func (l *loggingNetwork) LocalAddr() netip.Addr {
	addr := l.inner.LocalAddr()
	l.log.WithField("addr", addr).Trace("LocalAddr(network)")
	return addr
}

func (l *loggingNetwork) Proto() int {
	proto := l.inner.Proto()
	l.log.WithField("proto", proto).Trace("Proto(network)")
	return proto
}

func (l *loggingNetwork) IsIPv6() bool {
	isIPv6 := l.inner.IsIPv6()
	l.log.WithField("is_ipv6", isIPv6).Trace("IsIPv6(network)")
	return isIPv6
}

type loggingFrame struct {
	inner conduit.Frame
	log   *logrus.Entry
}

func (l *loggingFrame) Recv(ctx context.Context, opts *conduit.RecvOptions) (*conduit.FramePkt, error) {
	l.log.Trace("Recv(frame)...")
	start := time.Now()
	pkt, err := l.inner.Recv(ctx, opts)
	duration := time.Since(start)
	if err != nil {
		l.log.WithError(err).WithField("duration", duration).Error("Recv(frame) failed")
		return nil, err
	}
	if pkt != nil && pkt.Data != nil {
		l.log.WithFields(logrus.Fields{
			"duration": duration,
			"bytes":    len(pkt.Data.Bytes()),
			"src":      pkt.Src,
		}).Info("Recv(frame) successful")
	} else {
		l.log.WithField("duration", duration).Debug("Recv(frame) successful: empty frame")
	}
	return pkt, nil
}

func (l *loggingFrame) Send(ctx context.Context, pkt *conduit.FramePkt, opts *conduit.SendOptions) (int, conduit.Metadata, error) {
	l.log.Trace("Send(frame)...")
	start := time.Now()
	n, md, err := l.inner.Send(ctx, pkt, opts)
	duration := time.Since(start)
	if err != nil {
		l.log.WithError(err).WithField("duration", duration).Error("Send(frame) failed")
		return 0, md, err
	}
	if pkt != nil && pkt.Data != nil {
		l.log.WithFields(logrus.Fields{
			"duration": duration,
			"bytes":    n,
			"dst":      pkt.Dst,
		}).Info("Send(frame) successful")
	} else {
		l.log.WithField("duration", duration).Debug("Send(frame) successful: empty frame")
	}
	return n, md, nil
}

func (l *loggingFrame) SetDeadline(t time.Time) error {
	l.log.WithField("deadline", t).Trace("SetDeadline(frame)")
	return l.inner.SetDeadline(t)
}

func (l *loggingFrame) Interface() *net.Interface {
	intf := l.inner.Interface()
	l.log.WithField("interface", intf).Trace("Interface(frame)")
	return intf
}

type loggingStream struct {
	inner conduit.Stream
	log   *logrus.Entry
}

func (l *loggingStream) Recv(ctx context.Context, opts *conduit.RecvOptions) (*conduit.StreamChunk, error) {
	l.log.Trace("Recv(stream)...")
	start := time.Now()
	chunk, err := l.inner.Recv(ctx, opts)
	duration := time.Since(start)
	if err != nil {
		l.log.WithError(err).WithField("duration", duration).Error("Recv(stream) failed")
		return nil, err
	}
	if chunk != nil && chunk.Data != nil {
		l.log.WithFields(logrus.Fields{
			"duration": duration,
			"bytes":    len(chunk.Data.Bytes()),
		}).Info("Recv(stream) successful")
	} else {
		l.log.WithField("duration", duration).Debug("Recv(stream) successful: empty chunk")
	}
	return chunk, nil
}

func (l *loggingStream) Send(ctx context.Context, p []byte, buf conduit.Buffer, opts *conduit.SendOptions) (int, conduit.Metadata, error) {
	l.log.Trace("Send(stream)...")
	start := time.Now()
	n, md, err := l.inner.Send(ctx, p, buf, opts)
	duration := time.Since(start)
	if err != nil {
		l.log.WithError(err).WithField("duration", duration).Error("Send(stream) failed")
		return 0, md, err
	}
	l.log.WithFields(logrus.Fields{
		"duration": duration,
		"bytes":    n,
	}).Info("Send(stream) successful")
	return n, md, nil
}

func (l *loggingStream) Close() error {
	l.log.Debug("Close(stream)...")
	return l.inner.Close()
}

func (l *loggingStream) CloseWrite() error {
	l.log.Debug("CloseWrite(stream)...")
	return l.inner.CloseWrite()
}

func (l *loggingStream) SetDeadline(t time.Time) error {
	l.log.WithField("deadline", t).Trace("SetDeadline(stream)")
	return l.inner.SetDeadline(t)
}

func (l *loggingStream) LocalAddr() net.Addr {
	addr := l.inner.LocalAddr()
	l.log.WithField("addr", addr).Trace("LocalAddr(stream)")
	return addr
}

func (l *loggingStream) RemoteAddr() net.Addr {
	addr := l.inner.RemoteAddr()
	l.log.WithField("addr", addr).Trace("RemoteAddr(stream)")
	return addr
}

type loggingDatagram struct {
	inner conduit.Datagram
	log   *logrus.Entry
}

func (l *loggingDatagram) Recv(ctx context.Context, opts *conduit.RecvOptions) (*conduit.DatagramMsg, error) {
	l.log.Trace("Recv(datagram)...")
	start := time.Now()
	msg, err := l.inner.Recv(ctx, opts)
	duration := time.Since(start)
	if err != nil {
		l.log.WithError(err).WithField("duration", duration).Error("Recv(datagram) failed")
		return nil, err
	}
	if msg != nil && msg.Data != nil {
		l.log.WithFields(logrus.Fields{
			"duration": duration,
			"bytes":    len(msg.Data.Bytes()),
			"src":      msg.Src,
		}).Info("Recv(datagram) successful")
	} else {
		l.log.WithField("duration", duration).Debug("Recv(datagram) successful: empty message")
	}
	return msg, nil
}

func (l *loggingDatagram) Send(ctx context.Context, msg *conduit.DatagramMsg, opts *conduit.SendOptions) (int, conduit.Metadata, error) {
	l.log.Trace("Send(datagram)...")
	start := time.Now()
	n, md, err := l.inner.Send(ctx, msg, opts)
	duration := time.Since(start)
	if err != nil {
		l.log.WithError(err).WithField("duration", duration).Error("Send(datagram) failed")
		return 0, md, err
	}
	if msg != nil && msg.Data != nil {
		l.log.WithFields(logrus.Fields{
			"duration": duration,
			"bytes":    n,
			"dst":      msg.Dst,
		}).Info("Send(datagram) successful")
	} else {
		l.log.WithField("duration", duration).Debug("Send(datagram) successful: empty message")
	}
	return n, md, nil
}

func (l *loggingDatagram) SetDeadline(t time.Time) error {
	l.log.WithField("deadline", t).Trace("SetDeadline(datagram)")
	return l.inner.SetDeadline(t)
}

func (l *loggingDatagram) LocalAddr() netip.AddrPort {
	addr := l.inner.LocalAddr()
	l.log.WithField("addr", addr).Trace("LocalAddr(datagram)")
	return addr
}

func (l *loggingDatagram) RemoteAddr() netip.AddrPort {
	addr := l.inner.RemoteAddr()
	l.log.WithField("addr", addr).Trace("RemoteAddr(datagram)")
	return addr
}
