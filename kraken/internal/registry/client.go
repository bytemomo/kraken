package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Client fetches and caches modules from a registry
type Client struct {
	registryURL     string
	cacheDir        string
	httpClient      *http.Client
	skipIndexVerify bool

	indexMu   sync.RWMutex
	index     *Index
	indexTime time.Time
	indexTTL  time.Duration
}

// Config for creating a new registry client
type Config struct {
	RegistryURL      string
	CacheDir         string
	Timeout          time.Duration
	IndexTTL         time.Duration
	SkipIndexVerify  bool // Skip index signature verification (for browse-only use)
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	home, _ := os.UserHomeDir()
	return Config{
		RegistryURL: "https://bytemomo.github.io/kraken-modules",
		CacheDir:    filepath.Join(home, ".kraken", "modules"),
		Timeout:     30 * time.Second,
		IndexTTL:    5 * time.Minute,
	}
}

// NewClient creates a new registry client
func NewClient(cfg Config) (*Client, error) {
	if cfg.CacheDir == "" {
		cfg = DefaultConfig()
	}

	if err := os.MkdirAll(cfg.CacheDir, 0755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}

	return &Client{
		registryURL:     cfg.RegistryURL,
		cacheDir:        cfg.CacheDir,
		skipIndexVerify: cfg.SkipIndexVerify,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		indexTTL: cfg.IndexTTL,
	}, nil
}

// GetIndex returns the index, checking in-memory cache, disk cache, then remote.
func (c *Client) GetIndex(ctx context.Context) (*Index, error) {
	c.indexMu.RLock()
	if c.index != nil && time.Since(c.indexTime) < c.indexTTL {
		idx := c.index
		c.indexMu.RUnlock()
		return idx, nil
	}
	c.indexMu.RUnlock()

	// Try loading from disk cache before hitting the network
	if idx, err := c.loadDiskIndex(); err == nil {
		return idx, nil
	}

	return c.refreshIndex(ctx)
}

// RefreshIndex forces a remote fetch, bypassing both in-memory and disk caches.
func (c *Client) RefreshIndex(ctx context.Context) (*Index, error) {
	c.indexMu.Lock()
	c.index = nil
	c.indexTime = time.Time{}
	c.indexMu.Unlock()

	return c.refreshIndex(ctx)
}

func (c *Client) refreshIndex(ctx context.Context) (*Index, error) {
	c.indexMu.Lock()
	defer c.indexMu.Unlock()

	// Double-check after acquiring write lock
	if c.index != nil && time.Since(c.indexTime) < c.indexTTL {
		return c.index, nil
	}

	indexURL := c.registryURL + "/index.yaml"
	body, err := c.fetchURL(ctx, indexURL)
	if err != nil {
		return nil, fmt.Errorf("fetch index: %w", err)
	}

	// Verify index signature before trusting its contents
	if !c.skipIndexVerify {
		if err := c.VerifyIndex(ctx, body); err != nil {
			return nil, fmt.Errorf("verify index: %w", err)
		}
	}

	var index Index
	if err := yaml.Unmarshal(body, &index); err != nil {
		return nil, fmt.Errorf("parse index: %w", err)
	}

	// Persist to disk so future runs can skip the network fetch
	_ = c.saveDiskIndex(body)

	c.index = &index
	c.indexTime = time.Now()

	return &index, nil
}

func (c *Client) indexCachePath() string {
	return filepath.Join(c.cacheDir, "index.yaml")
}

// loadDiskIndex loads the index from disk if the file exists and is fresh
// (mtime within TTL). The cached file was verified when originally fetched.
func (c *Client) loadDiskIndex() (*Index, error) {
	path := c.indexCachePath()
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if time.Since(info.ModTime()) >= c.indexTTL {
		return nil, fmt.Errorf("disk cache stale")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var index Index
	if err := yaml.Unmarshal(data, &index); err != nil {
		return nil, err
	}

	c.indexMu.Lock()
	c.index = &index
	c.indexTime = info.ModTime()
	c.indexMu.Unlock()

	return &index, nil
}

func (c *Client) saveDiskIndex(data []byte) error {
	path := c.indexCachePath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// Resolve finds a module by ID, optionally at a specific version
func (c *Client) Resolve(ctx context.Context, moduleID, version string) (*ResolvedModule, error) {
	index, err := c.GetIndex(ctx)
	if err != nil {
		return nil, err
	}

	mod, ok := index.Modules[moduleID]
	if !ok {
		return nil, fmt.Errorf("module not found: %s", moduleID)
	}

	if version == "" || version == "latest" {
		version = mod.Latest
	}

	ver, ok := mod.Versions[version]
	if !ok {
		return nil, fmt.Errorf("version not found: %s@%s", moduleID, version)
	}

	platform := GetPlatform()
	artifact, ok := ver.Artifacts[platform]
	if !ok {
		return nil, fmt.Errorf("no artifact for platform %s: %s@%s", platform, moduleID, version)
	}

	// Validate artifact has required bundle field
	if artifact.Bundle == "" {
		return nil, fmt.Errorf("module %s@%s missing sigstore bundle", moduleID, version)
	}

	return &ResolvedModule{
		ID:               moduleID,
		Version:          version,
		Type:             mod.Type,
		Artifact:         artifact,
		ManifestArtifact: ver.Manifest,
	}, nil
}

// Download fetches the artifact and bundle, then verifies integrity
func (c *Client) Download(ctx context.Context, resolved *ResolvedModule) error {
	if resolved.Artifact == nil {
		return fmt.Errorf("no artifact to download")
	}

	localPath := c.artifactPath(resolved.ID, resolved.Version, resolved.Artifact.File)
	bundlePath := c.artifactPath(resolved.ID, resolved.Version, resolved.Artifact.Bundle)

	// Check cache validity: artifact hash AND bundle must both exist and be valid
	if c.isCacheValid(localPath, bundlePath, resolved.Artifact.SHA256) {
		resolved.LocalPath = localPath
		resolved.BundlePath = bundlePath
		return nil
	}

	// Clear any partial cache state
	os.Remove(localPath)
	os.Remove(bundlePath)

	index, _ := c.GetIndex(ctx)
	baseURL := index.ReleasesURL + "/" + resolved.ID + "-v" + resolved.Version

	// Download artifact
	if err := c.downloadFile(ctx, baseURL+"/"+resolved.Artifact.File, localPath); err != nil {
		return fmt.Errorf("download artifact: %w", err)
	}

	// Verify hash immediately after download
	if !c.verifyHash(localPath, resolved.Artifact.SHA256) {
		os.Remove(localPath)
		return fmt.Errorf("hash mismatch for %s", resolved.Artifact.File)
	}

	// Download sigstore bundle (mandatory)
	if err := c.downloadFile(ctx, baseURL+"/"+resolved.Artifact.Bundle, bundlePath); err != nil {
		os.Remove(localPath)
		return fmt.Errorf("download bundle: %w", err)
	}

	// Make artifact executable for ABI modules
	if resolved.Type == "abi" {
		if err := os.Chmod(localPath, 0755); err != nil {
			os.Remove(localPath)
			os.Remove(bundlePath)
			return fmt.Errorf("chmod artifact: %w", err)
		}
	}

	resolved.LocalPath = localPath
	resolved.BundlePath = bundlePath

	return nil
}

// FetchManifest downloads and parses the module manifest, using cache when available.
// Prefers the release-based manifest (with hash verification) when version manifest
// metadata is available, falling back to the module-level manifest_url for older entries.
func (c *Client) FetchManifest(ctx context.Context, resolved *ResolvedModule) error {
	cachePath := c.manifestCachePath(resolved.ID, resolved.Version)

	// Try loading from cache first (verify hash if we have it)
	if manifest, err := c.loadCachedManifest(cachePath); err == nil {
		if resolved.ManifestArtifact == nil || c.verifyHash(cachePath, resolved.ManifestArtifact.SHA256) {
			resolved.Manifest = manifest
			resolved.ManifestPath = cachePath
			return nil
		}
		// Cached manifest hash mismatch — re-fetch
		os.Remove(cachePath)
	}

	manifestURL, err := c.resolveManifestURL(ctx, resolved)
	if err != nil {
		return err
	}

	body, err := c.fetchURL(ctx, manifestURL)
	if err != nil {
		return fmt.Errorf("fetch manifest: %w", err)
	}

	// Verify hash if manifest artifact metadata is available
	if resolved.ManifestArtifact != nil && resolved.ManifestArtifact.SHA256 != "" {
		h := sha256.Sum256(body)
		actual := hex.EncodeToString(h[:])
		if actual != resolved.ManifestArtifact.SHA256 {
			return fmt.Errorf("manifest hash mismatch for %s: expected %s, got %s",
				resolved.ID, resolved.ManifestArtifact.SHA256, actual)
		}
	}

	var manifest Manifest
	if err := yaml.Unmarshal(body, &manifest); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}

	// Cache the manifest for future use
	_ = c.cacheManifest(cachePath, body)

	resolved.Manifest = &manifest
	resolved.ManifestPath = cachePath
	return nil
}

// LoadCachedManifest loads the manifest from disk cache only, without fetching.
// Returns an error if the manifest is not cached.
func (c *Client) LoadCachedManifest(resolved *ResolvedModule) error {
	cachePath := c.manifestCachePath(resolved.ID, resolved.Version)
	manifest, err := c.loadCachedManifest(cachePath)
	if err != nil {
		return err
	}

	if resolved.ManifestArtifact != nil &&
		!c.verifyHash(cachePath, resolved.ManifestArtifact.SHA256) {
		return fmt.Errorf("cached manifest hash mismatch")
	}

	resolved.Manifest = manifest
	resolved.ManifestPath = cachePath
	return nil
}

// resolveManifestURL determines the manifest URL. Prefers release-based URL
// when version manifest metadata exists, falls back to module-level manifest_url.
func (c *Client) resolveManifestURL(ctx context.Context, resolved *ResolvedModule) (string, error) {
	index, err := c.GetIndex(ctx)
	if err != nil {
		return "", err
	}

	// Prefer release-based manifest URL when version has manifest metadata
	if resolved.ManifestArtifact != nil && resolved.ManifestArtifact.File != "" {
		tag := resolved.ID + "-v" + resolved.Version
		return index.ReleasesURL + "/" + tag + "/" + resolved.ManifestArtifact.File, nil
	}

	// Fall back to module-level manifest_url
	mod, ok := index.Modules[resolved.ID]
	if !ok {
		return "", fmt.Errorf("module not found: %s", resolved.ID)
	}

	if mod.ManifestURL == "" {
		return "", fmt.Errorf("module %s has no manifest URL", resolved.ID)
	}

	manifestURL := mod.ManifestURL
	if !strings.HasPrefix(manifestURL, "http://") && !strings.HasPrefix(manifestURL, "https://") {
		manifestURL = c.registryURL + "/" + manifestURL
	}
	return manifestURL, nil
}

// fetchURL performs an HTTP GET and returns the response body.
func (c *Client) fetchURL(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d for %s", resp.StatusCode, url)
	}

	return io.ReadAll(resp.Body)
}

func (c *Client) manifestCachePath(moduleID, version string) string {
	return filepath.Join(c.cacheDir, moduleID, version, "manifest.yaml")
}

func (c *Client) loadCachedManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var manifest Manifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}

	return &manifest, nil
}

func (c *Client) cacheManifest(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ValidateManifest checks manifest consistency with resolved module
func (c *Client) ValidateManifest(resolved *ResolvedModule) error {
	if resolved.Manifest == nil {
		return fmt.Errorf("manifest not loaded")
	}

	m := resolved.Manifest

	// Validate ID matches
	if m.ID != resolved.ID {
		return fmt.Errorf("manifest ID mismatch: expected %s, got %s", resolved.ID, m.ID)
	}

	// Validate type matches
	if m.Type != resolved.Type {
		return fmt.Errorf("manifest type mismatch: expected %s, got %s", resolved.Type, m.Type)
	}

	// Validate type-specific configuration exists
	switch m.Type {
	case "abi":
		if m.ABI == nil {
			return fmt.Errorf("ABI module %s missing abi configuration in manifest", m.ID)
		}
		if m.ABI.API == "" {
			return fmt.Errorf("ABI module %s missing api version in manifest", m.ID)
		}
	case "container":
		if m.Container == nil {
			return fmt.Errorf("container module %s missing container configuration in manifest", m.ID)
		}
	case "grpc":
		if m.GRPC == nil {
			return fmt.Errorf("gRPC module %s missing grpc configuration in manifest", m.ID)
		}
	default:
		return fmt.Errorf("unknown module type: %s", m.Type)
	}

	return nil
}

func (c *Client) downloadFile(ctx context.Context, url, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

func (c *Client) artifactPath(moduleID, version, filename string) string {
	return filepath.Join(c.cacheDir, moduleID, version, filename)
}

// isCacheValid checks artifact hash and bundle file existence
func (c *Client) isCacheValid(artifactPath, bundlePath, expectedHash string) bool {
	// Bundle file must exist
	if _, err := os.Stat(bundlePath); os.IsNotExist(err) {
		return false
	}

	return c.verifyHash(artifactPath, expectedHash)
}

func (c *Client) verifyHash(path, expectedHash string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}

	return hex.EncodeToString(h.Sum(nil)) == expectedHash
}

// GetPlatform returns the current platform string (e.g. "linux-amd64")
func GetPlatform() string {
	os := runtime.GOOS
	arch := runtime.GOARCH

	// Normalize to registry convention
	if arch == "amd64" {
		return os + "-amd64"
	}
	if arch == "arm64" {
		return os + "-arm64"
	}
	return os + "-" + arch
}

// List returns all available modules
func (c *Client) List(ctx context.Context) ([]string, error) {
	index, err := c.GetIndex(ctx)
	if err != nil {
		return nil, err
	}

	modules := make([]string, 0, len(index.Modules))
	for id := range index.Modules {
		modules = append(modules, id)
	}
	return modules, nil
}
