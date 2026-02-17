package testutil

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := GenerateSelfSignedCert("127.0.0.1", "localhost")
	require.NoError(t, err)

	// Verify certificate is valid
	assert.NotNil(t, cert.Certificate)
	assert.NotNil(t, cert.PrivateKey)

	// Parse the certificate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	// Verify properties
	assert.Equal(t, "Kraken Test", x509Cert.Subject.Organization[0])
	assert.Equal(t, "localhost", x509Cert.Subject.CommonName)
	assert.Contains(t, x509Cert.DNSNames, "localhost")
	assert.True(t, x509Cert.NotAfter.After(time.Now()))
}

func TestGenerateSelfSignedCert_DefaultHosts(t *testing.T) {
	cert, err := GenerateSelfSignedCert()
	require.NoError(t, err)

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	// Should have default localhost
	assert.Contains(t, x509Cert.DNSNames, "localhost")
}

func TestGenerateCA(t *testing.T) {
	ca, caKey, err := GenerateCA()
	require.NoError(t, err)
	require.NotNil(t, ca)
	require.NotNil(t, caKey)

	// Verify it's a CA
	assert.True(t, ca.IsCA)
	assert.Equal(t, "Kraken Test Root CA", ca.Subject.CommonName)
	assert.True(t, ca.KeyUsage&x509.KeyUsageCertSign != 0)
}

func TestGenerateSignedCert(t *testing.T) {
	// Generate CA
	ca, caKey, err := GenerateCA()
	require.NoError(t, err)

	// Generate signed cert
	cert, err := GenerateSignedCert(ca, caKey, "127.0.0.1", "localhost")
	require.NoError(t, err)

	// Parse the certificate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	// Verify it was signed by CA
	pool := CertPool(ca)
	_, err = x509Cert.Verify(x509.VerifyOptions{
		Roots: pool,
	})
	require.NoError(t, err)
}

func TestGenerateExpiredCert(t *testing.T) {
	cert, err := GenerateExpiredCert("127.0.0.1")
	require.NoError(t, err)

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	// Verify it's expired
	assert.True(t, x509Cert.NotAfter.Before(time.Now()))
}

func TestCertPool(t *testing.T) {
	ca, _, err := GenerateCA()
	require.NoError(t, err)

	pool := CertPool(ca)
	require.NotNil(t, pool)

	// Pool should contain the CA
	subjects := pool.Subjects()
	assert.NotEmpty(t, subjects)
}
