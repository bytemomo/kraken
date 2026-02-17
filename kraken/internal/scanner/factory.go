package scanner

import (
	"context"
	"fmt"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/scanner/ethercat"

	"github.com/sirupsen/logrus"
)

// NewScanner creates a scanner from configuration.
func NewScanner(log *logrus.Entry, cfg *domain.ScannerConfig, targets []string) (Scanner, error) {
	if cfg == nil {
		return nil, fmt.Errorf("scanner config is nil")
	}

	switch cfg.Type {
	case "nmap", "":
		nmapCfg := cfg.Nmap
		if nmapCfg == nil {
			nmapCfg = &domain.NmapScannerConfig{}
		}
		if len(nmapCfg.Ports) == 0 {
			return nil, fmt.Errorf("nmap scanner requires explicit port specification for OT safety")
		}
		if nmapCfg.Timing == "" {
			nmapCfg.Timing = "T3"
		}
		if nmapCfg.Timeout == 0 {
			nmapCfg.Timeout = 5 * time.Minute
		}
		return &NmapScanner{
			Log:     log.WithField("scanner", "nmap"),
			Config:  *nmapCfg,
			Targets: targets,
		}, nil

	case "ethercat":
		if cfg.EtherCAT == nil {
			return nil, fmt.Errorf("ethercat scanner requires ethercat config")
		}
		return ethercat.New(log.WithField("scanner", "ethercat"), *cfg.EtherCAT), nil

	default:
		return nil, fmt.Errorf("unknown scanner type: %s", cfg.Type)
	}
}

// ExecuteAll runs all scanners and merges their results.
func ExecuteAll(ctx context.Context, scanners []Scanner) ([]domain.ClassifiedTarget, error) {
	var allTargets []domain.ClassifiedTarget
	seen := make(map[string]struct{})

	for _, s := range scanners {
		targets, err := s.Execute(ctx)
		if err != nil {
			return nil, fmt.Errorf("scanner %s: %w", s.Type(), err)
		}

		for _, t := range targets {
			key := t.Target.Key()
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			allTargets = append(allTargets, t)
		}
	}

	return allTargets, nil
}
