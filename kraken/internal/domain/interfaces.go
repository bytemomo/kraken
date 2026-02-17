package domain

// ResultRepo is an interface for saving run results.
type ResultRepo interface {
	// Save saves a run result for a target.
	Save(target Target, res RunResult) error
}

// ReportWriter is an interface for writing reports.
type ReportWriter interface {
	// Aggregate aggregates all run results into a report.
	Aggregate(all []RunResult) (string, error)
}
