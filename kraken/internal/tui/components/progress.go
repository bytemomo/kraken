package components

import (
	"fmt"
	"strings"

	"bytemomo/kraken/internal/tui/styles"

	"github.com/charmbracelet/lipgloss"
)

// ProgressBar renders a progress bar
type ProgressBar struct {
	Width    int
	Progress float64 // 0.0 to 1.0
	Label    string
	ShowPct  bool
}

// NewProgressBar creates a new progress bar
func NewProgressBar(width int) ProgressBar {
	return ProgressBar{
		Width:   width,
		ShowPct: true,
	}
}

// SetProgress sets the progress value (0.0 to 1.0)
func (p *ProgressBar) SetProgress(progress float64) {
	if progress < 0 {
		progress = 0
	}
	if progress > 1 {
		progress = 1
	}
	p.Progress = progress
}

// SetLabel sets the label text
func (p *ProgressBar) SetLabel(label string) {
	p.Label = label
}

// View renders the progress bar
func (p ProgressBar) View() string {
	// Calculate bar dimensions
	barWidth := p.Width
	if p.ShowPct {
		barWidth -= 6 // " 100%"
	}
	if p.Label != "" {
		barWidth -= lipgloss.Width(p.Label) + 1
	}
	if barWidth < 10 {
		barWidth = 10
	}

	// Build the bar
	filled := int(float64(barWidth) * p.Progress)
	empty := barWidth - filled

	bar := styles.ProgressFilled.Render(strings.Repeat("█", filled)) +
		styles.ProgressEmpty.Render(strings.Repeat("░", empty))

	// Add label and percentage
	result := ""
	if p.Label != "" {
		result = styles.BaseStyle.Foreground(styles.TextDim).Render(p.Label) + " "
	}
	result += bar
	if p.ShowPct {
		pct := fmt.Sprintf(" %3.0f%%", p.Progress*100)
		result += styles.BaseStyle.Foreground(styles.TextDim).Render(pct)
	}

	return result
}

// Spinner characters for indeterminate progress
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spinner renders an indeterminate spinner
type Spinner struct {
	Frame int
	Label string
}

// NewSpinner creates a new spinner
func NewSpinner() Spinner {
	return Spinner{}
}

// Tick advances the spinner animation
func (s *Spinner) Tick() {
	s.Frame = (s.Frame + 1) % len(spinnerFrames)
}

// View renders the spinner
func (s Spinner) View() string {
	spinner := styles.BaseStyle.Foreground(styles.Secondary).Render(spinnerFrames[s.Frame])
	if s.Label != "" {
		return spinner + " " + styles.BaseStyle.Foreground(styles.TextDim).Render(s.Label)
	}
	return spinner
}
