package events

import (
	"time"

	"bytemomo/kraken/internal/domain"
)

// Event is a marker interface for all TUI events
type Event interface {
	isEvent()
}

// Scanner events

type ScannerStarted struct {
	ScannerType string
	Config      string
}

func (ScannerStarted) isEvent() {}

type ScannerProgress struct {
	Progress float64
	Status   string
}

func (ScannerProgress) isEvent() {}

type TargetDiscovered struct {
	Target domain.ClassifiedTarget
}

func (TargetDiscovered) isEvent() {}

type ScannerCompleted struct {
	Targets []domain.ClassifiedTarget
	Error   error
}

func (ScannerCompleted) isEvent() {}

// Runner events

type ModuleStarted struct {
	Target  domain.Target
	Module  string
	Timeout time.Duration
}

func (ModuleStarted) isEvent() {}

type ModuleProgress struct {
	Target   domain.Target
	Module   string
	Progress float64
	Elapsed  time.Duration
}

func (ModuleProgress) isEvent() {}

type FindingDiscovered struct {
	Finding domain.Finding
}

func (FindingDiscovered) isEvent() {}

type ModuleCompleted struct {
	Target   domain.Target
	Module   string
	Findings []domain.Finding
	Logs     []string
	Error    error
}

func (ModuleCompleted) isEvent() {}

type TargetCompleted struct {
	Target domain.Target
	Result domain.RunResult
}

func (TargetCompleted) isEvent() {}

type RunCompleted struct {
	Results     []domain.RunResult
	AttackTrees []domain.AttackTreeResult
	Error       error
}

func (RunCompleted) isEvent() {}

// Output events

type OutputDirResolved struct {
	Path string
}

func (OutputDirResolved) isEvent() {}

// Log events

type LogEntry struct {
	Time    time.Time
	Level   string
	Message string
}

func (LogEntry) isEvent() {}

// Registry events

type RegistryRefreshed struct {
	ModuleCount int
	Error       error
}

func (RegistryRefreshed) isEvent() {}

type ModuleDownloadStarted struct {
	ModuleID string
	Version  string
}

func (ModuleDownloadStarted) isEvent() {}

type ModuleDownloadProgress struct {
	ModuleID string
	Progress float64
}

func (ModuleDownloadProgress) isEvent() {}

type ModuleDownloadCompleted struct {
	ModuleID  string
	Version   string
	LocalPath string
	Error     error
}

func (ModuleDownloadCompleted) isEvent() {}
