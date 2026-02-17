package domain

import (
	"encoding/json"
	"fmt"
)

// Tag is a string that can be used to tag targets and findings.
type Tag string

// ClassifiedTarget is a target that has been classified with a set of tags.
type ClassifiedTarget struct {
	Target Target
	Tags   []Tag
}

// CampaignType identifies the orchestration style.
type CampaignType string

const (
	CampaignNetwork CampaignType = "network"
	CampaignFuzz CampaignType = "fuzz"
)

// Campaign is a collection of modules that are run against a set of targets.
type Campaign struct {
	ID                 string             `yaml:"id"`
	Name               string             `yaml:"name"`
	Version            string             `yaml:"version"`
	Type               CampaignType       `yaml:"type,omitempty"`
	Policy             Policy             `yaml:"policy,omitempty"`
	Scanners           []*ScannerConfig   `yaml:"scanners,omitempty"`
	ConduitTemplates   []*ConduitTemplate `yaml:"conduit_templates,omitempty"`
	Tasks              []*Module          `yaml:"tasks"`
	AttackTreesDefPath string             `yaml:"attack_trees_def_path,omitempty"`
}

// EffectivePolicy returns the policy with defaults applied.
func (c *Campaign) EffectivePolicy() Policy {
	defaults := DefaultPolicy()
	return c.Policy.Merge(defaults)
}

// EffectiveScanners returns the list of scanner configs, handling legacy single scanner.
func (c *Campaign) EffectiveScanners() []*ScannerConfig {
	if len(c.Scanners) > 0 {
		return c.Scanners
	}
	return nil
}

// EffectiveType returns the campaign type, defaulting to the network flow.
func (c *Campaign) EffectiveType() CampaignType {
	if c == nil || c.Type == "" {
		return CampaignNetwork
	}
	return c.Type
}

// Validate checks that the campaign type is supported.
func (ct CampaignType) Validate() error {
	switch ct {
	case "", CampaignNetwork, CampaignFuzz:
		return nil
	default:
		return fmt.Errorf("invalid campaign type: %s", ct)
	}
}

// RunResult is the result of a module run against a target.
type RunResult struct {
	Target   Target    `json:"target"`
	Findings []Finding `json:"findings"`
	Logs     []string  `json:"logs"`
}

// UnmarshalJSON implements custom unmarshaling for RunResult to handle the Target interface.
func (r *RunResult) UnmarshalJSON(data []byte) error {
	type Alias RunResult
	aux := &struct {
		Target json.RawMessage `json:"target"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	if len(aux.Target) > 0 {
		target, err := unmarshalTarget(aux.Target)
		if err != nil {
			return fmt.Errorf("unmarshal target: %w", err)
		}
		r.Target = target
	}

	return nil
}

// unmarshalTarget unmarshals JSON into the appropriate Target implementation.
func unmarshalTarget(data []byte) (Target, error) {
	// Try HostPort first (most common)
	var hp HostPort
	if err := json.Unmarshal(data, &hp); err == nil && hp.Host != "" {
		return hp, nil
	}

	// Try EtherCATMaster
	var ecat struct {
		Interface  string   `json:"interface"`
		MACAddress string   `json:"mac_address"`
		SlaveCount int      `json:"slave_count"`
		Slaves     []uint16 `json:"slaves"`
	}
	if err := json.Unmarshal(data, &ecat); err == nil && ecat.Interface != "" {
		mac, _ := parseMAC(ecat.MACAddress)
		return EtherCATMaster{
			Interface:  ecat.Interface,
			MACAddress: mac,
			SlaveCount: ecat.SlaveCount,
			Slaves:     ecat.Slaves,
		}, nil
	}

	// For fuzz campaigns or cases with no target, return nil (allowed)
	return nil, nil
}

func parseMAC(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	// Simple parsing - net.ParseMAC is in target.go
	var mac []byte
	for i := 0; i < len(s); i += 3 {
		end := i + 2
		if end > len(s) {
			end = len(s)
		}
		var b byte
		fmt.Sscanf(s[i:end], "%02x", &b)
		mac = append(mac, b)
	}
	return mac, nil
}
