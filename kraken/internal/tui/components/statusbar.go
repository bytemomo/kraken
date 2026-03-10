package components

import (
	"fmt"
	"strings"

	"bytemomo/kraken/internal/tui/styles"

	"github.com/charmbracelet/lipgloss"
)

// RunState represents the current execution state
type RunState int

const (
	StateIdle RunState = iota
	StateScanning
	StateRunning
	StateCompleted
	StateFailed
)

func (s RunState) String() string {
	switch s {
	case StateIdle:
		return "Ready"
	case StateScanning:
		return "Scanning"
	case StateRunning:
		return "Running"
	case StateCompleted:
		return "Completed"
	case StateFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// StatusBar renders the bottom status bar
type StatusBar struct {
	Width        int
	State        RunState
	CampaignID   string
	TargetCount  int
	FindingCount int
	OutputDir    string
	HelpText     string
}

// NewStatusBar creates a new status bar component
func NewStatusBar() StatusBar {
	return StatusBar{
		State:    StateIdle,
		HelpText: "1-4: views • ←→: panels • ↑↓: scroll • q: quit",
	}
}

// SetWidth sets the status bar width
func (s *StatusBar) SetWidth(width int) {
	s.Width = width
}

// View renders the status bar
func (s StatusBar) View() string {
	// Left side: state and campaign
	stateStyle := styles.BaseStyle
	switch s.State {
	case StateScanning:
		stateStyle = stateStyle.Foreground(styles.Warning).Bold(true)
	case StateRunning:
		stateStyle = stateStyle.Foreground(styles.Primary).Bold(true)
	case StateCompleted:
		stateStyle = stateStyle.Foreground(styles.Success)
	case StateFailed:
		stateStyle = stateStyle.Foreground(styles.Error)
	default:
		stateStyle = stateStyle.Foreground(styles.Muted)
	}

	left := stateStyle.Render("◉ " + s.State.String())
	if s.CampaignID != "" {
		left += styles.BaseStyle.Foreground(styles.Muted).Render(" │ ")
		left += styles.BaseStyle.Foreground(styles.Text).Render(s.CampaignID)
	}

	// Center: stats
	center := ""
	if s.TargetCount > 0 || s.FindingCount > 0 {
		stats := fmt.Sprintf("Targets: %d │ Findings: %d", s.TargetCount, s.FindingCount)
		if s.OutputDir != "" {
			stats += " │ Output: " + s.OutputDir
		}
		center = styles.BaseStyle.Foreground(styles.TextDim).Render(stats)
	}

	// Right side: help text
	right := styles.HelpStyle.Render(s.HelpText)

	// Calculate spacing
	leftWidth := lipgloss.Width(left)
	centerWidth := lipgloss.Width(center)
	rightWidth := lipgloss.Width(right)

	totalContent := leftWidth + centerWidth + rightWidth
	availableSpace := s.Width - totalContent - 4 // padding

	if availableSpace < 0 {
		availableSpace = 0
	}

	leftSpace := availableSpace / 2
	rightSpace := availableSpace - leftSpace

	var result string
	if center != "" {
		result = lipgloss.JoinHorizontal(
			lipgloss.Top,
			left,
			strings.Repeat(" ", leftSpace),
			center,
			strings.Repeat(" ", rightSpace),
			right,
		)
	} else {
		spacing := s.Width - leftWidth - rightWidth - 2
		if spacing < 0 {
			spacing = 0
		}
		result = lipgloss.JoinHorizontal(
			lipgloss.Top,
			left,
			strings.Repeat(" ", spacing),
			right,
		)
	}

	return styles.StatusBarStyle.Width(s.Width).Render(result)
}
