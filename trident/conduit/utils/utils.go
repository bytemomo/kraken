package utils

import (
	"net"
	"net/netip"
	"sync"
)

// ToNetip converts a net.Addr to a netip.Addr.
func ToNetip(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.IPAddr:
		if ip, ok := netip.AddrFromSlice([]byte(v.IP.String())); ok {
			return ip
		}
	case *net.UDPAddr:
		if ip, ok := netip.AddrFromSlice([]byte(v.IP.String())); ok {
			return ip
		}
	case *net.TCPAddr:
		if ip, ok := netip.AddrFromSlice([]byte(v.IP.String())); ok {
			return ip
		}
	}
	return netip.Addr{}
}

// =====================================================================================
// Minimal pooled Buffer implementation
// =====================================================================================

// PooledBuf is a simple, non-thread-safe buffer implementation that uses a sync.Pool
// to reduce allocations. It is intended for use with the conduit interfaces.
type PooledBuf struct {
	B []byte
}

var bufPool = sync.Pool{
	New: func() any { return &PooledBuf{B: make([]byte, 32*1024)} },
}

// GetBuf retrieves a buffer from the pool.
func GetBuf(min int) *PooledBuf {
	p := bufPool.Get().(*PooledBuf)
	if cap(p.B) < min {
		p.B = make([]byte, min)
	} else {
		p.B = p.B[:min]
	}
	return p
}

// Bytes returns the byte slice.
func (p *PooledBuf) Bytes() []byte { return p.B }

// Grow ensures the buffer has at least n capacity.
func (p *PooledBuf) Grow(n int) []byte {
	if cap(p.B) < n {
		p.B = make([]byte, n)
	} else {
		p.B = p.B[:n]
	}
	return p.B
}

func (p *PooledBuf) Shrink(n int) []byte {
	if cap(p.B) > n {
		p.B = p.B[:n]
	} else {
		p.B = make([]byte, n)
	}
	return p.B
}

// ShrinkTo reduces the buffer length.
func (p *PooledBuf) ShrinkTo(n int) { p.B = p.B[:n] }

// Release returns the buffer to the pool.
func (p *PooledBuf) Release() {
	p.B = p.B[:0]
	bufPool.Put(p)
}
