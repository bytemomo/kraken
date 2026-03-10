package results

import (
	"fmt"
	"strings"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/tui/components"
	"bytemomo/kraken/internal/tui/keys"
	"bytemomo/kraken/internal/tui/styles"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Focus represents which panel is focused
type Focus int

const (
	FocusTargets Focus = iota
	FocusFindings
	FocusDetails
)

// SeveritySummary holds finding counts by severity
type SeveritySummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	Total    int
}

// Model is the results view model
type Model struct {
	width  int
	height int
	focus  Focus
	keys   keys.KeyMap

	// Data
	results []domain.RunResult
	summary SeveritySummary

	// UI state
	targetTable     components.Table
	findingTable    components.Table
	selectedTarget  domain.Target
	selectedFinding *domain.Finding
	detailsScroll   int

	// Grouped data
	findingsByTarget map[string][]domain.Finding
	targetList       []domain.Target
}

// New creates a new results view model
func New(keyMap keys.KeyMap) Model {
	targetTable := components.NewTable([]components.Column{
		{Title: "Target", Width: 30},
		{Title: "Total", Width: 8},
		{Title: "Crit", Width: 6},
		{Title: "High", Width: 6},
	})

	findingTable := components.NewTable([]components.Column{
		{Title: "Result", Width: 10},
		{Title: "Severity", Width: 10},
		{Title: "Finding ID", Width: 30},
		{Title: "Module", Width: 25},
	})

	findingTable.CellStyleFunc = resultsCellStyle

	return Model{
		keys:             keyMap,
		targetTable:      targetTable,
		findingTable:     findingTable,
		focus:            FocusTargets,
		findingsByTarget: make(map[string][]domain.Finding),
	}
}

func resultsCellStyle(rowIdx, colIdx int, value string) lipgloss.Style {
	switch colIdx {
	case 0: // Result column
		if strings.Contains(value, "Success") {
			return styles.BaseStyle.Foreground(styles.Success)
		}
		return styles.BaseStyle.Foreground(styles.Error)
	case 1: // Severity column
		return styles.SeverityStyle(strings.ToLower(value))
	default:
		return styles.TableRowStyle
	}
}

// Init initializes the model
func (m Model) Init() tea.Cmd {
	return nil
}

// SetSize sets the view dimensions
func (m *Model) SetSize(width, height int) {
	m.width = width
	m.height = height

	leftWidth := width/3 - 2
	rightWidth := width*2/3 - 4

	tableHeight := height - 10

	m.targetTable.SetSize(leftWidth-4, tableHeight)
	m.findingTable.SetSize(rightWidth-4, tableHeight/2-2)
}

// SetResults sets the results to display
func (m *Model) SetResults(results []domain.RunResult) {
	m.results = results
	m.computeSummary()
	m.groupFindings()
	m.updateTables()
}

// Clear resets all results
func (m *Model) Clear() {
	m.results = nil
	m.summary = SeveritySummary{}
	m.findingsByTarget = make(map[string][]domain.Finding)
	m.targetList = nil
	m.selectedTarget = nil
	m.selectedFinding = nil
	m.targetTable.SetRows(nil)
	m.findingTable.SetRows(nil)
}

// AddFinding adds a finding (for live updates)
func (m *Model) AddFinding(finding domain.Finding) {
	m.summary.Total++
	switch finding.Severity {
	case "critical":
		m.summary.Critical++
	case "high":
		m.summary.High++
	case "medium":
		m.summary.Medium++
	case "low":
		m.summary.Low++
	default:
		m.summary.Info++
	}

	targetKey := finding.Target.String()
	if _, exists := m.findingsByTarget[targetKey]; !exists {
		m.targetList = append(m.targetList, finding.Target)
	}
	m.findingsByTarget[targetKey] = append(
		m.findingsByTarget[targetKey], finding,
	)

	m.updateTables()
}

func (m *Model) computeSummary() {
	m.summary = SeveritySummary{}
	for _, result := range m.results {
		for _, f := range result.Findings {
			m.summary.Total++
			switch f.Severity {
			case "critical":
				m.summary.Critical++
			case "high":
				m.summary.High++
			case "medium":
				m.summary.Medium++
			case "low":
				m.summary.Low++
			default:
				m.summary.Info++
			}
		}
	}
}

func (m *Model) groupFindings() {
	m.findingsByTarget = make(map[string][]domain.Finding)
	m.targetList = nil

	for _, result := range m.results {
		targetKey := result.Target.String()
		if _, exists := m.findingsByTarget[targetKey]; !exists {
			m.targetList = append(m.targetList, result.Target)
		}
		m.findingsByTarget[targetKey] = append(
			m.findingsByTarget[targetKey], result.Findings...,
		)
	}
}

func (m *Model) updateTables() {
	rows := make([]components.Row, len(m.targetList))
	for i, target := range m.targetList {
		targetKey := target.String()
		findings := m.findingsByTarget[targetKey]

		critCount := 0
		highCount := 0
		for _, f := range findings {
			if f.Severity == "critical" {
				critCount++
			} else if f.Severity == "high" {
				highCount++
			}
		}

		rows[i] = components.Row{
			targetKey,
			fmt.Sprintf("%d", len(findings)),
			fmt.Sprintf("%d", critCount),
			fmt.Sprintf("%d", highCount),
		}
	}
	m.targetTable.SetRows(rows)
	m.updateFindingTable()
}

func (m *Model) updateFindingTable() {
	if m.selectedTarget == nil {
		if len(m.targetList) > 0 {
			m.selectedTarget = m.targetList[0]
		} else {
			m.findingTable.SetRows(nil)
			return
		}
	}

	targetKey := m.selectedTarget.String()
	findings := m.findingsByTarget[targetKey]

	rows := make([]components.Row, len(findings))
	for i, f := range findings {
		result := "● Failed"
		if f.Success {
			result = "● Success"
		}
		rows[i] = components.Row{
			result, strings.ToUpper(f.Severity), f.ID, f.ModuleID,
		}
	}
	m.findingTable.SetRows(rows)

	if m.selectedFinding == nil && len(findings) > 0 {
		m.selectedFinding = &findings[0]
	}
}

// Update handles messages
func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Left):
			if m.focus > FocusTargets {
				m.focus--
				m.updateTableFocus()
			}
		case key.Matches(msg, m.keys.Right):
			if m.focus < FocusDetails {
				m.focus++
				m.updateTableFocus()
			}
		case key.Matches(msg, m.keys.Tab):
			m.focus = (m.focus + 1) % 3
			m.updateTableFocus()
		case key.Matches(msg, m.keys.Up):
			switch m.focus {
			case FocusTargets:
				m.targetTable.MoveUp()
				if m.targetTable.Selected >= 0 &&
					m.targetTable.Selected < len(m.targetList) {
					m.selectedTarget = m.targetList[m.targetTable.Selected]
					m.selectedFinding = nil
					m.updateFindingTable()
				}
			case FocusFindings:
				m.findingTable.MoveUp()
				m.updateSelectedFinding()
			case FocusDetails:
				if m.detailsScroll > 0 {
					m.detailsScroll--
				}
			}
		case key.Matches(msg, m.keys.Down):
			switch m.focus {
			case FocusTargets:
				m.targetTable.MoveDown()
				if m.targetTable.Selected >= 0 &&
					m.targetTable.Selected < len(m.targetList) {
					m.selectedTarget = m.targetList[m.targetTable.Selected]
					m.selectedFinding = nil
					m.updateFindingTable()
				}
			case FocusFindings:
				m.findingTable.MoveDown()
				m.updateSelectedFinding()
			case FocusDetails:
				m.detailsScroll++
			}
		case key.Matches(msg, m.keys.Enter):
			if m.focus == FocusTargets {
				m.focus = FocusFindings
				m.updateTableFocus()
			} else if m.focus == FocusFindings {
				m.focus = FocusDetails
				m.updateTableFocus()
			}
		}
	}

	return m, nil
}

func (m *Model) updateTableFocus() {
	m.targetTable.Focused = (m.focus == FocusTargets)
	m.findingTable.Focused = (m.focus == FocusFindings)
}

func (m *Model) updateSelectedFinding() {
	if m.selectedTarget == nil {
		return
	}
	targetKey := m.selectedTarget.String()
	findings := m.findingsByTarget[targetKey]
	if m.findingTable.Selected >= 0 &&
		m.findingTable.Selected < len(findings) {
		f := findings[m.findingTable.Selected]
		m.selectedFinding = &f
		m.detailsScroll = 0
	}
}

// View renders the view
func (m Model) View() string {
	summaryBar := m.renderSummaryBar()
	targetsPanel := m.renderTargetsPanel()

	findingsPanel := m.renderFindingsPanel()
	bottomPanel := m.renderDetailsPanel()
	rightColumn := lipgloss.JoinVertical(
		lipgloss.Left, findingsPanel, bottomPanel,
	)

	content := lipgloss.JoinHorizontal(
		lipgloss.Top, targetsPanel, " ", rightColumn,
	)

	helpText := "←→/Tab: panels  ↑↓: navigate  Enter: select  5: attack trees"
	help := styles.HelpStyle.Render(helpText)

	return lipgloss.JoinVertical(lipgloss.Left, summaryBar, content, help)
}

func (m Model) renderSummaryBar() string {
	title := styles.PanelTitle("RESULTS", 12)

	if m.summary.Total == 0 {
		return title + "  " +
			styles.BaseStyle.Foreground(styles.Muted).Render("No findings")
	}

	parts := []string{title, " "}

	parts = append(parts,
		styles.BaseStyle.Foreground(styles.Text).Render(
			fmt.Sprintf("Total: %d", m.summary.Total),
		))
	parts = append(parts, " │ ")

	if m.summary.Critical > 0 {
		parts = append(parts, styles.CriticalStyle.Render(
			fmt.Sprintf("● CRIT %d", m.summary.Critical)))
		parts = append(parts, "  ")
	}
	if m.summary.High > 0 {
		parts = append(parts, styles.HighStyle.Render(
			fmt.Sprintf("● HIGH %d", m.summary.High)))
		parts = append(parts, "  ")
	}
	if m.summary.Medium > 0 {
		parts = append(parts, styles.MediumStyle.Render(
			fmt.Sprintf("● MED %d", m.summary.Medium)))
		parts = append(parts, "  ")
	}
	if m.summary.Low > 0 {
		parts = append(parts, styles.LowStyle.Render(
			fmt.Sprintf("● LOW %d", m.summary.Low)))
		parts = append(parts, "  ")
	}
	if m.summary.Info > 0 {
		parts = append(parts, styles.InfoStyle.Render(
			fmt.Sprintf("● INFO %d", m.summary.Info)))
	}

	return lipgloss.JoinHorizontal(lipgloss.Left, parts...)
}

func (m Model) renderTargetsPanel() string {
	panelWidth := m.width/3 - 2
	if panelWidth < 30 {
		panelWidth = 30
	}
	panelHeight := m.height - 8

	title := styles.PanelTitle(
		fmt.Sprintf("TARGETS (%d)", len(m.targetList)), panelWidth,
	)

	var content string
	if len(m.targetList) == 0 {
		content = styles.BaseStyle.Foreground(styles.Muted).
			Render("No targets with findings")
	} else {
		content = m.targetTable.View()
	}

	focusStyle := styles.PanelStyle.Width(panelWidth).Height(panelHeight)
	if m.focus == FocusTargets {
		focusStyle = styles.PanelFocusedStyle.Width(panelWidth).
			Height(panelHeight)
	}

	return focusStyle.Render(
		lipgloss.JoinVertical(lipgloss.Left, title, content),
	)
}

func (m Model) renderFindingsPanel() string {
	panelWidth := m.width*2/3 - 4
	if panelWidth < 40 {
		panelWidth = 40
	}
	panelHeight := (m.height - 8) / 2

	titleText := "FINDINGS"
	if m.selectedTarget != nil {
		targetKey := m.selectedTarget.String()
		count := len(m.findingsByTarget[targetKey])
		titleText = fmt.Sprintf("FINDINGS FOR %s (%d)", targetKey, count)
	}
	title := styles.PanelTitle(titleText, panelWidth)

	var content string
	if m.selectedTarget == nil {
		content = styles.BaseStyle.Foreground(styles.Muted).
			Render("Select a target")
	} else {
		content = m.findingTable.View()
	}

	focusStyle := styles.PanelStyle.Width(panelWidth).Height(panelHeight)
	if m.focus == FocusFindings {
		focusStyle = styles.PanelFocusedStyle.Width(panelWidth).
			Height(panelHeight)
	}

	return focusStyle.Render(
		lipgloss.JoinVertical(lipgloss.Left, title, content),
	)
}

func (m Model) renderDetailsPanel() string {
	panelWidth := m.width*2/3 - 4
	if panelWidth < 40 {
		panelWidth = 40
	}
	panelHeight := (m.height - 8) / 2

	title := styles.PanelTitle("FINDING DETAILS", panelWidth)

	var content string
	if m.selectedFinding == nil {
		content = styles.BaseStyle.Foreground(styles.Muted).
			Render("Select a finding to view details")
	} else {
		content = m.renderFindingDetails(panelWidth - 4)
	}

	focusStyle := styles.PanelStyle.Width(panelWidth).Height(panelHeight)
	if m.focus == FocusDetails {
		focusStyle = styles.PanelFocusedStyle.Width(panelWidth).
			Height(panelHeight)
	}

	return focusStyle.Render(
		lipgloss.JoinVertical(lipgloss.Left, title, content),
	)
}

func (m Model) renderFindingDetails(maxWidth int) string {
	f := m.selectedFinding
	if f == nil {
		return ""
	}

	var lines []string

	severityStyle := styles.SeverityStyle(f.Severity)
	lines = append(lines,
		severityStyle.Render(strings.ToUpper(f.Severity))+"  "+
			styles.BaseStyle.Bold(true).Render(f.ID))

	if f.Success {
		lines = append(lines,
			styles.BaseStyle.Foreground(styles.Success).Bold(true).
				Render("● Success"))
	} else {
		lines = append(lines,
			styles.BaseStyle.Foreground(styles.Error).Bold(true).
				Render("● Failed"))
	}

	if f.Title != "" {
		lines = append(lines,
			styles.BaseStyle.Bold(true).Foreground(styles.Text).
				Render(f.Title))
	}
	lines = append(lines, "")

	lines = append(lines, renderField("Module", f.ModuleID))
	lines = append(lines, renderField("Target", f.Target.String()))
	if !f.Timestamp.IsZero() {
		lines = append(lines,
			renderField("Time", f.Timestamp.Format("15:04:05")))
	}

	if f.Description != "" {
		lines = append(lines, "")
		lines = append(lines,
			styles.BaseStyle.Foreground(styles.Secondary).Bold(true).
				Render("Description:"))
		desc := f.Description
		if len(desc) > maxWidth-4 {
			desc = wrapText(desc, maxWidth-4)
		}
		lines = append(lines,
			styles.BaseStyle.Foreground(styles.TextDim).Render(desc))
	}

	if len(f.Evidence) > 0 {
		lines = append(lines, "")
		lines = append(lines,
			styles.BaseStyle.Foreground(styles.Secondary).Bold(true).
				Render("Evidence:"))
		for k, v := range f.Evidence {
			val := fmt.Sprintf("%v", v)
			if len(val) > maxWidth-len(k)-6 {
				val = val[:maxWidth-len(k)-9] + "..."
			}
			lines = append(lines, renderField("  "+k, val))
		}
	}

	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

func wrapText(text string, width int) string {
	if width <= 0 {
		return text
	}

	var result strings.Builder
	words := strings.Fields(text)
	lineLen := 0

	for i, word := range words {
		if lineLen+len(word)+1 > width && lineLen > 0 {
			result.WriteString("\n")
			lineLen = 0
		}
		if lineLen > 0 {
			result.WriteString(" ")
			lineLen++
		}
		result.WriteString(word)
		lineLen += len(word)
		_ = i
	}

	return result.String()
}

func renderField(label, value string) string {
	return styles.BaseStyle.Foreground(styles.Muted).Render(label+": ") +
		styles.BaseStyle.Foreground(styles.Text).Render(value)
}
