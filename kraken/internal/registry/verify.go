package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	expectedOIDCIssuer       = "https://token.actions.githubusercontent.com"
	expectedIdentityRegexp   = "^https://github.com/bytemomo/kraken-modules/"
)

// verifyBlobSignature verifies that data was signed by the expected identity
// using the Sigstore bundle at bundlePath.
func (c *Client) verifyBlobSignature(data []byte, bundlePath string) error {
	if _, err := os.Stat(bundlePath); os.IsNotExist(err) {
		return fmt.Errorf("sigstore bundle not found: %s", bundlePath)
	}

	// Silence TUF client logs that corrupt TUI
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	opts := tuf.DefaultOptions()
	tufClient, err := tuf.New(opts)
	if err != nil {
		return fmt.Errorf("initialize TUF client: %w", err)
	}

	trustedMaterial, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		return fmt.Errorf("get trusted root: %w", err)
	}

	sev, err := verify.NewVerifier(
		trustedMaterial,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return fmt.Errorf("create verifier: %w", err)
	}

	digest := sha256.Sum256(data)

	certID, err := verify.NewShortCertificateIdentity(
		expectedOIDCIssuer,
		"",
		"",
		expectedIdentityRegexp,
	)
	if err != nil {
		return fmt.Errorf("create certificate identity: %w", err)
	}

	b, err := bundle.LoadJSONFromPath(bundlePath)
	if err != nil {
		return fmt.Errorf("load sigstore bundle: %w", err)
	}

	_, err = sev.Verify(
		b,
		verify.NewPolicy(
			verify.WithArtifactDigest("sha256", digest[:]),
			verify.WithCertificateIdentity(certID),
		),
	)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// VerifySignature verifies the Sigstore bundle for a resolved module's artifact.
func (c *Client) VerifySignature(ctx context.Context, resolved *ResolvedModule) error {
	if resolved.LocalPath == "" {
		return fmt.Errorf("artifact not downloaded")
	}
	if resolved.BundlePath == "" {
		return fmt.Errorf("sigstore bundle path not set")
	}

	data, err := os.ReadFile(resolved.LocalPath)
	if err != nil {
		return fmt.Errorf("read artifact: %w", err)
	}

	return c.verifyBlobSignature(data, resolved.BundlePath)
}

// VerifyIndex verifies the index signature using its Sigstore bundle.
func (c *Client) VerifyIndex(ctx context.Context, indexData []byte) error {
	bundlePath := filepath.Join(c.cacheDir, "index.sigstore.json")
	bundleURL := c.registryURL + "/index.sigstore.json"

	if err := c.downloadFile(ctx, bundleURL, bundlePath); err != nil {
		return fmt.Errorf("download index bundle: %w", err)
	}

	if err := c.verifyBlobSignature(indexData, bundlePath); err != nil {
		os.Remove(bundlePath)
		return fmt.Errorf("index signature verification failed: %w", err)
	}

	return nil
}

// ResolveAndDownload resolves, downloads, fetches manifest, validates, and verifies a module
func (c *Client) ResolveAndDownload(ctx context.Context, moduleID, version string) (*ResolvedModule, error) {
	resolved, err := c.Resolve(ctx, moduleID, version)
	if err != nil {
		return nil, err
	}

	if err := c.EnsureDownloaded(ctx, resolved); err != nil {
		return nil, err
	}

	return resolved, nil
}

// EnsureDownloaded downloads and verifies a module if not already cached
func (c *Client) EnsureDownloaded(ctx context.Context, resolved *ResolvedModule) error {
	// Check if already downloaded and verified
	if resolved.LocalPath != "" && resolved.Manifest != nil {
		if _, err := os.Stat(resolved.LocalPath); err == nil {
			return nil // Already ready
		}
	}

	if err := c.Download(ctx, resolved); err != nil {
		return err
	}

	// Verify artifact signature (mandatory)
	if err := c.VerifySignature(ctx, resolved); err != nil {
		os.Remove(resolved.LocalPath)
		os.Remove(resolved.BundlePath)
		return fmt.Errorf("module %s: %w", resolved.ID, err)
	}

	// Fetch and validate manifest (hash verified inside FetchManifest)
	if err := c.FetchManifest(ctx, resolved); err != nil {
		return fmt.Errorf("module %s: %w", resolved.ID, err)
	}

	if err := c.ValidateManifest(resolved); err != nil {
		return fmt.Errorf("module %s: %w", resolved.ID, err)
	}

	// Verify manifest signature if bundle metadata is available
	if err := c.verifyManifestSignature(ctx, resolved); err != nil {
		return fmt.Errorf("module %s: %w", resolved.ID, err)
	}

	return nil
}

// verifyManifestSignature downloads and verifies the manifest's Sigstore bundle.
// Skipped for older index entries that lack manifest bundle metadata.
func (c *Client) verifyManifestSignature(ctx context.Context, resolved *ResolvedModule) error {
	if resolved.ManifestArtifact == nil || resolved.ManifestArtifact.Bundle == "" {
		return nil // No manifest bundle in index — pre-verification release
	}

	if resolved.ManifestPath == "" {
		return fmt.Errorf("manifest not downloaded")
	}

	index, err := c.GetIndex(ctx)
	if err != nil {
		return err
	}

	tag := resolved.ID + "-v" + resolved.Version
	bundleURL := index.ReleasesURL + "/" + tag + "/" + resolved.ManifestArtifact.Bundle
	bundlePath := c.artifactPath(resolved.ID, resolved.Version, resolved.ManifestArtifact.Bundle)

	if err := c.downloadFile(ctx, bundleURL, bundlePath); err != nil {
		return fmt.Errorf("download manifest bundle: %w", err)
	}

	manifestData, err := os.ReadFile(resolved.ManifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}

	if err := c.verifyBlobSignature(manifestData, bundlePath); err != nil {
		os.Remove(bundlePath)
		return fmt.Errorf("manifest signature verification failed: %w", err)
	}

	return nil
}

// ResolveOnly resolves module metadata without downloading (for lazy loading)
func (c *Client) ResolveOnly(ctx context.Context, moduleID, version string) (*ResolvedModule, error) {
	resolved, err := c.Resolve(ctx, moduleID, version)
	if err != nil {
		return nil, err
	}

	// Fetch manifest (cached, no artifact download needed)
	if err := c.FetchManifest(ctx, resolved); err != nil {
		return nil, fmt.Errorf("module %s: %w", moduleID, err)
	}

	if err := c.ValidateManifest(resolved); err != nil {
		return nil, fmt.Errorf("module %s: %w", moduleID, err)
	}

	return resolved, nil
}

// VerifyHash verifies the artifact SHA256 hash matches expected value
func VerifyHash(path, expectedHex string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	h := sha256.Sum256(data)
	actual := hex.EncodeToString(h[:])

	if actual != expectedHex {
		return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHex, actual)
	}

	return nil
}
