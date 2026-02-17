package testutil

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// MockTCPServer is a simple TCP server for testing.
type MockTCPServer struct {
	listener net.Listener
	handler  func(net.Conn)
	wg       sync.WaitGroup
	closed   bool
	mu       sync.Mutex
}

// NewMockTCPServer creates a TCP server that calls handler for each connection.
// If handler is nil, it echoes received data back.
func NewMockTCPServer(handler func(net.Conn)) *MockTCPServer {
	if handler == nil {
		handler = echoHandler
	}
	return &MockTCPServer{handler: handler}
}

// NewEchoServer creates a TCP server that echoes data back.
func NewEchoServer() *MockTCPServer {
	return NewMockTCPServer(echoHandler)
}

func echoHandler(conn net.Conn) {
	defer conn.Close()
	io.Copy(conn, conn)
}

// Start starts the server on a random port.
func (s *MockTCPServer) Start() error {
	var err error
	s.listener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

func (s *MockTCPServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handler(conn)
		}()
	}
}

// Stop stops the server.
func (s *MockTCPServer) Stop() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	return nil
}

// Addr returns the server address.
func (s *MockTCPServer) Addr() string {
	return s.listener.Addr().String()
}

// Port returns the server port.
func (s *MockTCPServer) Port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

// MockTLSServer wraps MockTCPServer with TLS.
type MockTLSServer struct {
	*MockTCPServer
	config *tls.Config
}

// NewMockTLSServer creates a TLS server with the given certificate.
func NewMockTLSServer(cert tls.Certificate, handler func(net.Conn)) *MockTLSServer {
	if handler == nil {
		handler = echoHandler
	}
	return &MockTLSServer{
		MockTCPServer: &MockTCPServer{handler: handler},
		config: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}
}

// Start starts the TLS server.
func (s *MockTLSServer) Start() error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.listener = tls.NewListener(listener, s.config)

	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

// DelayedServer introduces configurable delays for timeout testing.
type DelayedServer struct {
	*MockTCPServer
	acceptDelay  time.Duration
	responseDelay time.Duration
}

// NewDelayedServer creates a server with configurable delays.
func NewDelayedServer(acceptDelay, responseDelay time.Duration) *DelayedServer {
	ds := &DelayedServer{
		acceptDelay:   acceptDelay,
		responseDelay: responseDelay,
	}
	ds.MockTCPServer = NewMockTCPServer(ds.delayedHandler)
	return ds
}

func (s *DelayedServer) delayedHandler(conn net.Conn) {
	defer conn.Close()
	if s.responseDelay > 0 {
		time.Sleep(s.responseDelay)
	}
	io.Copy(conn, conn)
}

// Start starts the delayed server.
func (s *DelayedServer) Start() error {
	var err error
	s.listener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	s.wg.Add(1)
	go s.delayedAcceptLoop()
	return nil
}

func (s *DelayedServer) delayedAcceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			continue
		}
		if s.acceptDelay > 0 {
			time.Sleep(s.acceptDelay)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handler(conn)
		}()
	}
}

// FlakyServer fails N times before succeeding (for retry testing).
type FlakyServer struct {
	listener     net.Listener
	failCount    int
	currentFails int
	handler      func(net.Conn)
	wg           sync.WaitGroup
	closed       bool
	mu           sync.Mutex
}

// NewFlakyServer creates a server that rejects the first failCount connections.
func NewFlakyServer(failCount int, handler func(net.Conn)) *FlakyServer {
	if handler == nil {
		handler = echoHandler
	}
	return &FlakyServer{
		failCount: failCount,
		handler:   handler,
	}
}

// Start starts the flaky server.
func (s *FlakyServer) Start() error {
	var err error
	s.listener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

func (s *FlakyServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			continue
		}

		s.mu.Lock()
		shouldFail := s.currentFails < s.failCount
		if shouldFail {
			s.currentFails++
		}
		s.mu.Unlock()

		if shouldFail {
			conn.Close()
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handler(conn)
		}()
	}
}

// Stop stops the server.
func (s *FlakyServer) Stop() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	return nil
}

// Addr returns the server address.
func (s *FlakyServer) Addr() string {
	return s.listener.Addr().String()
}

// Port returns the server port.
func (s *FlakyServer) Port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

// Reset resets the fail counter.
func (s *FlakyServer) Reset() {
	s.mu.Lock()
	s.currentFails = 0
	s.mu.Unlock()
}

// ContextServer wraps a handler with context awareness.
type ContextServer struct {
	*MockTCPServer
	ctx    context.Context
	cancel context.CancelFunc
}

// NewContextServer creates a server that respects context cancellation.
func NewContextServer(handler func(context.Context, net.Conn)) *ContextServer {
	cs := &ContextServer{}
	cs.ctx, cs.cancel = context.WithCancel(context.Background())
	cs.MockTCPServer = NewMockTCPServer(func(conn net.Conn) {
		handler(cs.ctx, conn)
	})
	return cs
}

// Stop stops the server and cancels the context.
func (s *ContextServer) Stop() error {
	s.cancel()
	return s.MockTCPServer.Stop()
}
