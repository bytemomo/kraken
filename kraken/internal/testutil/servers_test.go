package testutil

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockTCPServer_EchoServer(t *testing.T) {
	server := NewEchoServer()
	require.NoError(t, server.Start())
	defer server.Stop()

	// Connect to server
	conn, err := net.Dial("tcp", server.Addr())
	require.NoError(t, err)
	defer conn.Close()

	// Send data
	testData := []byte("hello world")
	n, err := conn.Write(testData)
	require.NoError(t, err)
	assert.Equal(t, len(testData), n)

	// Read echoed data
	buf := make([]byte, 1024)
	n, err = conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, testData, buf[:n])
}

func TestMockTCPServer_CustomHandler(t *testing.T) {
	var received []byte
	server := NewMockTCPServer(func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		received = buf[:n]
		conn.Write([]byte("OK"))
	})
	require.NoError(t, server.Start())
	defer server.Stop()

	conn, err := net.Dial("tcp", server.Addr())
	require.NoError(t, err)
	defer conn.Close()

	conn.Write([]byte("test message"))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "OK", string(buf[:n]))
	assert.Equal(t, "test message", string(received))
}

func TestMockTLSServer(t *testing.T) {
	cert, err := GenerateSelfSignedCert("127.0.0.1", "localhost")
	require.NoError(t, err)

	server := NewMockTLSServer(cert, nil)
	require.NoError(t, server.Start())
	defer server.Stop()

	// Verify server is listening
	assert.NotEmpty(t, server.Addr())
	assert.Greater(t, server.Port(), 0)
}

func TestDelayedServer(t *testing.T) {
	server := NewDelayedServer(0, 100*time.Millisecond)
	require.NoError(t, server.Start())
	defer server.Stop()

	conn, err := net.Dial("tcp", server.Addr())
	require.NoError(t, err)
	defer conn.Close()

	// Send data
	start := time.Now()
	conn.Write([]byte("test"))

	// Read response (should be delayed)
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := conn.Read(buf)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Equal(t, "test", string(buf[:n]))
	assert.GreaterOrEqual(t, elapsed, 100*time.Millisecond)
}

func TestFlakyServer(t *testing.T) {
	server := NewFlakyServer(2, nil)
	require.NoError(t, server.Start())
	defer server.Stop()

	// First 2 connections should be closed immediately
	for i := 0; i < 2; i++ {
		conn, err := net.Dial("tcp", server.Addr())
		require.NoError(t, err)

		// Try to read - should fail or return EOF
		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, err = conn.Read(buf)
		assert.Error(t, err) // Connection closed
		conn.Close()
	}

	// Third connection should work
	conn, err := net.Dial("tcp", server.Addr())
	require.NoError(t, err)
	defer conn.Close()

	conn.Write([]byte("hello"))
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf[:n]))
}

func TestFlakyServer_Reset(t *testing.T) {
	server := NewFlakyServer(1, nil)
	require.NoError(t, server.Start())
	defer server.Stop()

	// First connection fails
	conn, _ := net.Dial("tcp", server.Addr())
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	conn.Read(buf)
	conn.Close()

	// Reset counter
	server.Reset()

	// First connection after reset should fail again
	conn, _ = net.Dial("tcp", server.Addr())
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err := conn.Read(buf)
	assert.Error(t, err)
	conn.Close()
}
