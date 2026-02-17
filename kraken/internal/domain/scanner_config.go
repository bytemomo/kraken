package domain

import (
	"time"

	"gopkg.in/yaml.v3"
)

// ServiceDetectType is the type of service detection to perform.
type ServiceDetectType string

const (
	// VersionAll performs a comprehensive service detection.
	VersionAll ServiceDetectType = "ALL"
	// VersionLight performs a light service detection.
	VersionLight ServiceDetectType = "LIGHT"
)

// ServiceDetect is the configuration for service detection.
type ServiceDetect struct {
	Enabled bool              `yaml:"enabled,omitempty"`
	Version ServiceDetectType `yaml:"version,omitempty"`
}

// ScannerConfig is the unified configuration for a scanner instance.
type ScannerConfig struct {
	Type     string                 `yaml:"type"`               // "nmap" or "ethercat"
	Nmap     *NmapScannerConfig     `yaml:"nmap,omitempty"`     // Config when type=nmap
	EtherCAT *EtherCATScannerConfig `yaml:"ethercat,omitempty"` // Config when type=ethercat
}

// UnmarshalYAML handles both new and legacy scanner config formats.
func (s *ScannerConfig) UnmarshalYAML(node *yaml.Node) error {
	// First try the new format with type/nmap/ethercat fields
	type scannerConfigAlias ScannerConfig
	var newFormat scannerConfigAlias
	if err := node.Decode(&newFormat); err != nil {
		return err
	}

	// If we got a type or nested config, use the new format
	if newFormat.Type != "" || newFormat.Nmap != nil || newFormat.EtherCAT != nil {
		*s = ScannerConfig(newFormat)
		return nil
	}

	// Otherwise, try legacy format where nmap fields are at the top level
	var legacy NmapScannerConfig
	if err := node.Decode(&legacy); err != nil {
		return err
	}

	// Check if any legacy fields were populated
	if legacy.Ports != nil || legacy.OpenOnly || legacy.SkipHostDiscovery ||
		legacy.EnableUDP || legacy.ServiceDetect.Enabled || legacy.MinRate > 0 ||
		legacy.Timing != "" || legacy.Timeout > 0 || legacy.Interface != "" {
		s.Type = "nmap"
		s.Nmap = &legacy
		return nil
	}

	// Empty config defaults to nmap
	s.Type = "nmap"
	return nil
}

// NmapScannerConfig is the configuration for the nmap scanner.
type NmapScannerConfig struct {
	Interface string `yaml:"iface,omitempty"`

	SkipHostDiscovery bool `yaml:"skip_host_discovery,omitempty"` // -Pn
	Unprivileged      bool `yaml:"unprivileged,omitempty"`        // -sT (TCP connect scan, no root required)

	EnableUDP bool     `yaml:"enable_udp,omitempty"`
	Ports     []string `yaml:"ports,omitempty"`
	OpenOnly  bool     `yaml:"open_only,omitempty"`

	ServiceDetect ServiceDetect `yaml:"service_detect,omitempty"`

	MinRate int           `yaml:"min_rate,omitempty"`
	Timing  string        `yaml:"timing,omitempty"`
	Timeout time.Duration `yaml:"timeout,omitempty"`
}

// EtherCATScannerConfig is the configuration for the EtherCAT scanner.
type EtherCATScannerConfig struct {
	Interface string        `yaml:"iface"`             // Network interface (required)
	Timeout   time.Duration `yaml:"timeout,omitempty"` // Sniff timeout (default: 10s)
}
