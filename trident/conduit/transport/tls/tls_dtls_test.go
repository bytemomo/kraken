package tls_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"bytemomo/trident/conduit"
	tr "bytemomo/trident/conduit/transport"
	tlswrap "bytemomo/trident/conduit/transport/tls"

	"github.com/pion/dtls/v3"
)

// --- TLS test ---
func TestTLS_Stream_Echo(t *testing.T) {
	addr, stop, _ := startTLSEcho(t)
	defer stop()

	_, _, cliCfg := genSelfSignedCert(t)

	inner := tr.TCP(addr)
	tlsC := tlswrap.NewTlsClient(inner, cliCfg)

	ctx := mustCtx(t, 5*time.Second)
	if err := tlsC.Dial(ctx); err != nil {
		t.Fatalf("tls dial: %v", err)
	}

	s := tlsC.Underlying()

	payload := []byte("hello over tls")
	n, md, err := s.Send(ctx, payload, nil, nil)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("send n=%d want %d", n, len(payload))
	}
	if md.Proto != 6 {
		t.Fatalf("proto=%d want 6", md.Proto)
	}

	chunk, err := s.Recv(ctx, &conduit.RecvOptions{MaxBytes: 64})
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if chunk == nil || chunk.Data == nil {
		t.Fatalf("empty chunk")
	}
	defer chunk.Data.Release()
	if string(chunk.Data.Bytes()) != string(payload) {
		t.Fatalf("echo mismatch got=%q want=%q", chunk.Data.Bytes(), payload)
	}

	_ = s.CloseWrite()
	_ = s.Close()
}

// --- DTLS test ---
func TestDTLS_Datagram_Echo(t *testing.T) {
	addr, stop, dcfg := startDTLSEcho(t)
	defer stop()

	inner := tr.UDP(addr)
	dtlsC := tlswrap.NewDtlsClient(inner, &dtls.Config{
		InsecureSkipVerify:   true,
		MTU:                  1200,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	})

	ctx := mustCtx(t, 8*time.Second)
	_ = dcfg
	if err := dtlsC.Dial(ctx); err != nil {
		t.Fatalf("dtls dial: %v", err)
	}

	d := dtlsC.Underlying()

	payload := []byte("hello over dtls")
	tb := &testBuf{b: append([]byte(nil), payload...)}
	defer tb.Release()

	dstAP, _ := netip.ParseAddrPort(addr)
	msg := &conduit.DatagramMsg{Data: tb, Dst: dstAP}
	n, md, err := d.Send(ctx, msg, nil)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("send n=%d want %d", n, len(payload))
	}
	if md.Proto != 17 {
		t.Fatalf("proto=%d want 17", md.Proto)
	}

	resp, err := d.Recv(ctx, &conduit.RecvOptions{MaxBytes: 64})
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if resp == nil || resp.Data == nil {
		t.Fatalf("empty resp")
	}
	defer resp.Data.Release()
	if string(resp.Data.Bytes()) != string(payload) {
		t.Fatalf("echo mismatch got=%q want=%q", resp.Data.Bytes(), payload)
	}
}

// Bonus: run TLS+DTLS in parallel
func TestTLS_DTLS_Parallel(t *testing.T) {
	t.Parallel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); TestTLS_Stream_Echo(t) }()
	go func() { defer wg.Done(); TestDTLS_Datagram_Echo(t) }()
	wg.Wait()
}

// --- tiny test buffer (implements conduit.Buffer) ---
type testBuf struct{ b []byte }

func (tb *testBuf) Bytes() []byte       { return tb.b }
func (tb *testBuf) Grow(n int) []byte   { tb.b = make([]byte, n); return tb.b }
func (tb *testBuf) Shrink(n int) []byte { tb.b = make([]byte, n); return tb.b }
func (tb *testBuf) Release()            {}

// --- helpers ---
func mustCtx(t *testing.T, dur time.Duration) context.Context {
	t.Helper()
	ctx, _ := context.WithTimeout(context.Background(), dur)
	return ctx
}

func genSelfSignedCert(t *testing.T) (tls.Certificate, *tls.Config, *tls.Config) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	templ := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &templ, &templ, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("x509 keypair: %v", err)
	}
	srv := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	cli := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	return cert, srv, cli
}

func startTLSEcho(t *testing.T) (addr string, stop func(), srvCfg *tls.Config) {
	t.Helper()
	_, srvCfg, _ = genSelfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
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
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }, srvCfg
}

func startDTLSEcho(t *testing.T) (addr string, stop func(), cfg *dtls.Config) {
	t.Helper()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}

	cfg = &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		MTU:                  1200,
	}

	// Listen on UDP
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve udp: %v", err)
	}

	listener, err := dtls.Listen("udp", udpAddr, cfg)
	if err != nil {
		t.Fatalf("dtls listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64<<10)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						_, _ = c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return listener.Addr().String(), func() { _ = listener.Close(); <-done }, cfg
}
