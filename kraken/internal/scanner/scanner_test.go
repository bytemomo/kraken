package scanner

import (
	"testing"
	"time"

	"bytemomo/kraken/internal/domain"

	"github.com/sirupsen/logrus"
)

func TestNewScannerNmap(t *testing.T) {
	log := logrus.NewEntry(logrus.New())

	cfg := &domain.ScannerConfig{
		Type: "nmap",
		Nmap: &domain.NmapScannerConfig{
			Ports: []string{"22", "80", "443"},
		},
	}

	s, err := NewScanner(log, cfg, []string{"192.168.1.0/24"})
	if err != nil {
		t.Fatalf("NewScanner returned error: %v", err)
	}

	if s.Type() != ScannerTypeNmap {
		t.Errorf("expected type %q, got %q", ScannerTypeNmap, s.Type())
	}

	nmap, ok := s.(*NmapScanner)
	if !ok {
		t.Fatalf("expected *NmapScanner, got %T", s)
	}

	if len(nmap.Targets) != 1 || nmap.Targets[0] != "192.168.1.0/24" {
		t.Errorf("unexpected targets: %v", nmap.Targets)
	}

	if len(nmap.Config.Ports) != 3 {
		t.Errorf("expected 3 ports, got %d", len(nmap.Config.Ports))
	}
}

func TestNewScannerDefaultType(t *testing.T) {
	log := logrus.NewEntry(logrus.New())

	// Empty type should default to nmap (ports required)
	cfg := &domain.ScannerConfig{
		Nmap: &domain.NmapScannerConfig{
			Ports: []string{"22"},
		},
	}

	s, err := NewScanner(log, cfg, []string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("NewScanner returned error: %v", err)
	}

	if s.Type() != ScannerTypeNmap {
		t.Errorf("expected type %q, got %q", ScannerTypeNmap, s.Type())
	}
}

func TestNewScannerEtherCAT(t *testing.T) {
	log := logrus.NewEntry(logrus.New())

	cfg := &domain.ScannerConfig{
		Type:     "ethercat",
		EtherCAT: &domain.EtherCATScannerConfig{Interface: "eth0"},
	}

	s, err := NewScanner(log, cfg, nil)
	if err != nil {
		t.Fatalf("NewScanner returned error: %v", err)
	}

	if s.Type() != ScannerTypeEtherCAT {
		t.Errorf("expected type %q, got %q", ScannerTypeEtherCAT, s.Type())
	}
}

func TestNewScannerEtherCATMissingConfig(t *testing.T) {
	log := logrus.NewEntry(logrus.New())

	cfg := &domain.ScannerConfig{
		Type: "ethercat",
		// EtherCAT config is nil
	}

	_, err := NewScanner(log, cfg, nil)
	if err == nil {
		t.Fatal("expected error for missing ethercat config")
	}
}

func TestNewScannerUnknownType(t *testing.T) {
	log := logrus.NewEntry(logrus.New())

	cfg := &domain.ScannerConfig{Type: "unknown"}

	_, err := NewScanner(log, cfg, nil)
	if err == nil {
		t.Fatal("expected error for unknown scanner type")
	}
}

func TestNewScannerNilConfig(t *testing.T) {
	log := logrus.NewEntry(logrus.New())

	_, err := NewScanner(log, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestNewScannerNmap_RejectsEmptyPorts(t *testing.T) {
	log := logrus.NewEntry(logrus.New())

	cfg := &domain.ScannerConfig{
		Type: "nmap",
		Nmap: &domain.NmapScannerConfig{},
	}

	_, err := NewScanner(log, cfg, []string{"10.0.0.1"})
	if err == nil {
		t.Fatal("expected error for empty ports")
	}
}

func TestNewScannerNmap_RejectsNilNmapConfig(t *testing.T) {
	log := logrus.NewEntry(logrus.New())

	// nil Nmap config creates empty NmapScannerConfig which has no ports
	cfg := &domain.ScannerConfig{Type: "nmap"}

	_, err := NewScanner(log, cfg, []string{"10.0.0.1"})
	if err == nil {
		t.Fatal("expected error for nil nmap config (no ports)")
	}
}

func TestNewScannerNmap_DefaultTiming(t *testing.T) {
	log := logrus.NewEntry(logrus.New())

	cfg := &domain.ScannerConfig{
		Type: "nmap",
		Nmap: &domain.NmapScannerConfig{
			Ports: []string{"1883"},
		},
	}

	s, err := NewScanner(log, cfg, []string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	nmap := s.(*NmapScanner)
	if nmap.Config.Timing != "T3" {
		t.Errorf("expected default timing T3, got %q", nmap.Config.Timing)
	}
}

func TestNewScannerNmap_DefaultTimeout(t *testing.T) {
	log := logrus.NewEntry(logrus.New())

	cfg := &domain.ScannerConfig{
		Type: "nmap",
		Nmap: &domain.NmapScannerConfig{
			Ports: []string{"1883"},
		},
	}

	s, err := NewScanner(log, cfg, []string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	nmap := s.(*NmapScanner)
	if nmap.Config.Timeout != 5*time.Minute {
		t.Errorf("expected default timeout 5m, got %v", nmap.Config.Timeout)
	}
}

func TestNewScannerNmap_ExplicitValuesPreserved(t *testing.T) {
	log := logrus.NewEntry(logrus.New())

	cfg := &domain.ScannerConfig{
		Type: "nmap",
		Nmap: &domain.NmapScannerConfig{
			Ports:   []string{"22", "80"},
			Timing:  "T2",
			Timeout: 10 * time.Minute,
		},
	}

	s, err := NewScanner(log, cfg, []string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	nmap := s.(*NmapScanner)
	if nmap.Config.Timing != "T2" {
		t.Errorf("expected timing T2, got %q", nmap.Config.Timing)
	}
	if nmap.Config.Timeout != 10*time.Minute {
		t.Errorf("expected timeout 10m, got %v", nmap.Config.Timeout)
	}
}
