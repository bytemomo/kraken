package scanner

import (
	"context"
	"fmt"
	"strings"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/protocol"

	nmap "github.com/Ullaakut/nmap/v3"
	"github.com/sirupsen/logrus"
)

// ScannerType identifies the type of scanner.
type ScannerType = string

const (
	ScannerTypeNmap     ScannerType = "nmap"
	ScannerTypeEtherCAT ScannerType = "ethercat"
)

// Scanner is the interface for all scanner implementations.
type Scanner interface {
	Type() string
	Execute(ctx context.Context) ([]domain.ClassifiedTarget, error)
}

// NmapScanner is a wrapper around nmap. It scans network CIDRs for open ports.
type NmapScanner struct {
	Log     *logrus.Entry
	Config  domain.NmapScannerConfig
	Targets []string
}

func (s *NmapScanner) Type() string { return ScannerTypeNmap }

// Execute runs the nmap scanner with the configured options.
func (s *NmapScanner) Execute(ctx context.Context) ([]domain.ClassifiedTarget, error) {
	targets := sanitizeCIDRs(s.Targets)
	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid targets provided")
	}

	log := s.Log.WithFields(logrus.Fields{
		"targets": targets,
		"ports":   s.Config.Ports,
	})
	log.Info("Starting nmap scan")

	opts := []nmap.Option{
		nmap.WithTargets(targets...),
		nmap.WithDisabledDNSResolution(),
	}

	if s.Config.Interface != "" {
		opts = append(opts, nmap.WithInterface(s.Config.Interface))
	}

	if len(s.Config.Ports) != 0 {
		opts = append(opts, nmap.WithPorts(strings.Join(s.Config.Ports, ",")))
	}

	if s.Config.OpenOnly {
		opts = append(opts, nmap.WithOpenOnly()) // --open
	}

	if s.Config.SkipHostDiscovery {
		opts = append(opts, nmap.WithSkipHostDiscovery()) // -Pn
	}

	if s.Config.Unprivileged {
		opts = append(opts, nmap.WithConnectScan()) // -sT
	}

	if s.Config.EnableUDP {
		opts = append(opts, nmap.WithUDPScan()) // -sU
	}

	if s.Config.ServiceDetect.Enabled {
		opts = append(opts, nmap.WithServiceInfo()) // -sV

		switch s.Config.ServiceDetect.Version {
		case domain.VersionAll:
			opts = append(opts, nmap.WithVersionAll())
		case domain.VersionLight:
			opts = append(opts, nmap.WithVersionLight())
		default:
			log.Errorf("Invalid specified version for service detection")
		}
	}

	if s.Config.MinRate > 0 {
		opts = append(opts, nmap.WithMinRate(s.Config.MinRate))
	}

	switch s.Config.Timing {
	case "T0": // slowest
		opts = append(opts, nmap.WithTimingTemplate(nmap.TimingSlowest))
	case "T1": // sneaky
		opts = append(opts, nmap.WithTimingTemplate(nmap.TimingSneaky))
	case "T2": // polite
		opts = append(opts, nmap.WithTimingTemplate(nmap.TimingPolite))
	case "T3": // normal
		opts = append(opts, nmap.WithTimingTemplate(nmap.TimingNormal))
	case "T4": // aggressive
		opts = append(opts, nmap.WithTimingTemplate(nmap.TimingAggressive))
	case "T5": // fastest
		opts = append(opts, nmap.WithTimingTemplate(nmap.TimingFastest))
	default:
		log.Errorf("Wrong timing for scanner: %s", s.Config.Timing)
	}

	if s.Config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Config.Timeout)
		defer cancel()
	}

	log.WithField("options", fmt.Sprintf("%v", opts)).Debug("Creating nmap scanner")
	scanner, err := nmap.NewScanner(ctx, opts...)
	if err != nil {
		log.WithError(err).Error("Failed to create nmap scanner")
		return nil, fmt.Errorf("create nmap scanner: %w", err)
	}

	log.WithField("args", scanner.Args()).Info("Executing nmap scan")
	result, warnings, err := scanner.Run()
	if warnings != nil && len(*warnings) > 0 {
		log.WithField("warnings", *warnings).Warn("Nmap scan produced warnings")
	}
	if err != nil {
		log.WithError(err).Error("Nmap scan failed")
		return nil, fmt.Errorf("run nmap: %w", err)
	}

	log.WithFields(logrus.Fields{
		"hosts":   len(result.Hosts),
		"runtime": result.Stats.Finished.TimeStr,
		"summary": result.Stats.Finished.Summary,
	}).Info("Nmap scan complete")

	var out []domain.ClassifiedTarget
	for _, h := range result.Hosts {
		host := pickHostAddress(h)
		if host == "" {
			continue
		}

		for _, p := range h.Ports {
			state := strings.ToLower(p.State.State)
			if !strings.HasPrefix(state, "open") {
				continue
			}

			t := domain.HostPort{Host: host, Port: uint16(p.ID)}
			tags := protocol.DeriveTagsFromService(t, p.Protocol, p.Service.Name, p.Service.Tunnel, p.Service.Product)

			log.WithFields(logrus.Fields{
				"host": host,
				"port": p.ID,
				"svc":  p.Service.Name,
				"tags": tags,
			}).Debug("Classified target")

			ct := domain.ClassifiedTarget{Target: t, Tags: tags}
			out = append(out, ct)
		}
	}
	log.WithField("count", len(out)).Info("Finished classifying targets")
	return out, nil
}



func sanitizeCIDRs(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

func pickHostAddress(h nmap.Host) string {
	for _, a := range h.Addresses {
		if a.AddrType == "ipv4" {
			return a.Addr
		}
	}
	for _, a := range h.Addresses {
		if a.AddrType == "ipv6" {
			return a.Addr
		}
	}
	if len(h.Addresses) > 0 {
		return h.Addresses[0].Addr
	}
	return ""
}
