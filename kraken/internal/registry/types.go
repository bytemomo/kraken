package registry

import "time"

// Index represents the registry index.yaml structure
type Index struct {
	Version     int                `yaml:"version"`
	Generated   time.Time          `yaml:"generated"`
	RegistryURL string             `yaml:"registry_url"`
	ReleasesURL string             `yaml:"releases_url"`
	Modules     map[string]*Module `yaml:"modules"`
}

// Module represents a module entry in the index
type Module struct {
	Type        string              `yaml:"type"`
	Latest      string              `yaml:"latest"`
	ManifestURL string              `yaml:"manifest_url"`
	Versions    map[string]*Version `yaml:"versions"`
}

// Version represents a specific version of a module
type Version struct {
	Tag       string               `yaml:"tag"`
	Manifest  *Artifact            `yaml:"manifest,omitempty"`
	Artifacts map[string]*Artifact `yaml:"artifacts"`
}

// Artifact represents a platform-specific artifact
type Artifact struct {
	File   string `yaml:"file"`
	SHA256 string `yaml:"sha256"`
	Bundle string `yaml:"bundle"`
}

// Manifest represents a module's manifest.yaml
type Manifest struct {
	ID          string             `yaml:"id"`
	Version     string             `yaml:"version"`
	Type        string             `yaml:"type"`
	Description string             `yaml:"description"`
	Build       *ManifestBuild     `yaml:"build,omitempty"`
	ABI         *ManifestABI       `yaml:"abi,omitempty"`
	Container   *ManifestContainer `yaml:"container,omitempty"`
	GRPC        *ManifestGRPC      `yaml:"grpc,omitempty"`
	Runtime     ManifestRuntime    `yaml:"runtime"`
	Params      *ParamsSchema      `yaml:"params,omitempty"`
	Findings    []ManifestFinding  `yaml:"findings,omitempty"`
}

// ManifestBuild contains build system configuration
type ManifestBuild struct {
	System    string   `yaml:"system"`
	Platforms []string `yaml:"platforms,omitempty"`
}

// ManifestABI contains ABI-specific configuration
type ManifestABI struct {
	API    string `yaml:"api"`
	Symbol string `yaml:"symbol"`
}

// ManifestContainer contains container-specific configuration
type ManifestContainer struct {
	Dockerfile string `yaml:"dockerfile"`
}

// ManifestGRPC contains gRPC-specific configuration
type ManifestGRPC struct {
	Service     string `yaml:"service"`
	DefaultPort int    `yaml:"default_port"`
}

// ManifestRuntime contains runtime requirements
type ManifestRuntime struct {
	Protocol string `yaml:"protocol"`
	Timeout  string `yaml:"timeout"`
	Memory   string `yaml:"memory"`
}

// ParamsSchema is JSON Schema for module parameters
type ParamsSchema struct {
	Type       string                    `yaml:"type"`
	Properties map[string]ParamProperty  `yaml:"properties,omitempty"`
	Required   []string                  `yaml:"required,omitempty"`
}

// ParamProperty defines a single parameter
type ParamProperty struct {
	Type        string      `yaml:"type"`
	Description string      `yaml:"description,omitempty"`
	Default     interface{} `yaml:"default,omitempty"`
}

// ManifestFinding describes a finding type the module can produce
type ManifestFinding struct {
	ID          string `yaml:"id"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
}

// ResolvedModule contains all info needed to load a module from registry
type ResolvedModule struct {
	ID               string
	Version          string
	Type             string
	LocalPath        string
	Artifact         *Artifact
	BundlePath       string
	ManifestArtifact *Artifact
	ManifestPath     string
	Manifest         *Manifest
}
