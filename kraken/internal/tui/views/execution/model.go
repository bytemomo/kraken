package execution

import (
	"fmt"
	"strings"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/tui/components"
	"bytemomo/kraken/internal/tui/events"
	"bytemomo/kraken/internal/tui/keys"
	"bytemomo/kraken/internal/tui/styles"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Focus represents which panel is focused
type Focus int

const (
	FocusProgress Focus = iota
	FocusFindings
	FocusLogs
)

// Model is the execution view model
type Model struct {
	width  int
	height int
	focus  Focus
	keys   keys.KeyMap

	// State
	state      components.RunState
	campaign   *domain.Campaign
	startTime  time.Time
	cancelFunc func()

	// Scanner state
	scannerProgress float64
	scannerStatus   string
	targets         []domain.ClassifiedTarget

	// Runner state
	currentTarget   domain.Target
	currentModule   string
	moduleProgress  float64
	moduleTimeout   time.Duration
	moduleStartTime time.Time
	completedCount  int
	totalTargets    int
	failedModules   int
	successModules  int

	// Findings
	findings     []domain.Finding
	findingTable components.Table

	// Logs
	logView components.LogView

	// Layout
	topPanelHeight int

	// Output
	outputDir string

	// Animation
	spinner components.Spinner
}

// New creates a new execution view model
func New(keyMap keys.KeyMap) Model {
	findingTable := components.NewTable([]components.Column{
		{Title: "Result", Width: 10},
		{Title: "Time", Width: 10},
		{Title: "Severity", Width: 10},
		{Title: "Finding", Width: 25},
		{Title: "Target", Width: 22},
	})

	findingTable.CellStyleFunc = findingCellStyle

	return Model{
		keys:         keyMap,
		state:        components.StateIdle,
		findingTable: findingTable,
		logView:      components.NewLogView(15),
		focus:        FocusProgress,
		spinner:      components.NewSpinner(),
	}
}

func findingCellStyle(rowIdx, colIdx int, value string) lipgloss.Style {
	switch colIdx {
	case 0: // Result column
		if strings.Contains(value, "Success") {
			return styles.BaseStyle.Foreground(styles.Success)
		}
		return styles.BaseStyle.Foreground(styles.Error)
	case 2: // Severity column
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

	contentHeight := height - 4
	m.topPanelHeight = contentHeight * 2 / 5
	if m.topPanelHeight < 10 {
		m.topPanelHeight = 10
	}
	if m.topPanelHeight > 20 {
		m.topPanelHeight = 20
	}

	m.findingTable.SetSize(width/2-4, m.topPanelHeight-4)

	logHeight := contentHeight - m.topPanelHeight - 4
	if logHeight < 8 {
		logHeight = 8
	}
	m.logView.SetSize(width-4, logHeight)
}

// SetCampaign sets the campaign to run
func (m *Model) SetCampaign(campaign *domain.Campaign) {
	m.campaign = campaign
}

// SetOutputDir sets the resolved output directory path
func (m *Model) SetOutputDir(dir string) {
	m.outputDir = dir
}

// State returns the current run state
func (m Model) State() components.RunState {
	return m.state
}

// Tick advances the spinner animation and updates progress
func (m *Model) Tick() {
	m.spinner.Tick()

	// Compute module progress from elapsed time vs timeout
	if m.state == components.StateRunning &&
		!m.moduleStartTime.IsZero() &&
		m.moduleTimeout > 0 {
		elapsed := time.Since(m.moduleStartTime)
		m.moduleProgress = elapsed.Seconds() / m.moduleTimeout.Seconds()
		if m.moduleProgress > 1.0 {
			m.moduleProgress = 1.0
		}
	}
}

// Start begins execution
func (m *Model) Start(cancel func()) {
	m.state = components.StateScanning
	m.startTime = time.Now()
	m.cancelFunc = cancel
	m.scannerProgress = 0
	m.scannerStatus = "Initializing..."
	m.targets = nil
	m.findings = nil
	m.completedCount = 0
	m.failedModules = 0
	m.successModules = 0
	m.logView.Clear()
	m.logView.AddInfo("Campaign started")
}

// Stop stops execution
func (m *Model) Stop() {
	if m.cancelFunc != nil {
		m.cancelFunc()
	}
	m.state = components.StateFailed
	m.logView.AddWarn("Campaign stopped by user")
}

// HandleEvent processes execution events
func (m *Model) HandleEvent(event events.Event) {
	switch e := event.(type) {
	case events.ScannerStarted:
		m.handleScannerStarted(e)
	case events.ScannerProgress:
		m.scannerProgress = e.Progress
		m.scannerStatus = e.Status
	case events.TargetDiscovered:
		m.targets = append(m.targets, e.Target)
		m.logView.AddInfo(fmt.Sprintf("Target discovered: %s", e.Target.Target.String()))
	case events.ScannerCompleted:
		m.handleScannerCompleted(e)
	case events.ModuleStarted:
		m.handleModuleStarted(e)
	case events.ModuleProgress:
		m.moduleProgress = e.Progress
	case events.FindingDiscovered:
		m.handleFindingDiscovered(e)
	case events.ModuleCompleted:
		m.handleModuleCompleted(e)
	case events.TargetCompleted:
		m.completedCount++
		m.logView.AddInfo(fmt.Sprintf("Target completed: %s (%d/%d)",
			e.Target.String(), m.completedCount, m.totalTargets))
	case events.RunCompleted:
		m.handleRunCompleted(e)
	case events.OutputDirResolved:
		m.outputDir = e.Path
	case events.LogEntry:
		m.handleLogEntry(e)
	}
}

func (m *Model) handleScannerStarted(e events.ScannerStarted) {
	m.state = components.StateScanning
	m.scannerStatus = fmt.Sprintf("Running %s scanner...", e.ScannerType)
	m.logView.AddInfo(fmt.Sprintf("Scanner started: %s", e.ScannerType))
}

func (m *Model) handleScannerCompleted(e events.ScannerCompleted) {
	if e.Error != nil {
		m.logView.AddError(fmt.Sprintf("Scanner error: %v", e.Error))
		return
	}
	m.scannerProgress = 1.0
	m.scannerStatus = "Complete"
	m.targets = e.Targets
	m.totalTargets = len(e.Targets)
	m.logView.AddInfo(fmt.Sprintf("Scanner completed: %d targets found", len(e.Targets)))
}

func (m *Model) handleModuleStarted(e events.ModuleStarted) {
	m.state = components.StateRunning
	m.currentTarget = e.Target
	m.currentModule = e.Module
	m.moduleTimeout = e.Timeout
	m.moduleStartTime = time.Now()
	m.moduleProgress = 0
	m.logView.AddInfo(fmt.Sprintf("Module started: %s @ %s", e.Module, e.Target.String()))
}

func (m *Model) handleFindingDiscovered(e events.FindingDiscovered) {
	m.findings = append(m.findings, e.Finding)
	m.updateFindingTable()
	severity := strings.ToUpper(e.Finding.Severity)
	m.logView.AddInfo(fmt.Sprintf("[%s] %s: %s", severity, e.Finding.ID, e.Finding.Title))
}

func (m *Model) handleModuleCompleted(e events.ModuleCompleted) {
	if e.Error != nil {
		m.failedModules++
		m.logView.AddError(fmt.Sprintf("FAILED: %s - %v", e.Module, e.Error))
	} else {
		m.successModules++
		m.logView.AddInfo(fmt.Sprintf("OK: %s (%d findings)", e.Module, len(e.Findings)))
	}
}

func (m *Model) handleRunCompleted(e events.RunCompleted) {
	if e.Error != nil {
		m.state = components.StateFailed
		m.logView.AddError(fmt.Sprintf("Run failed: %v", e.Error))
		return
	}
	m.state = components.StateCompleted
	m.logView.AddInfo("═══════════════════════════════════════")
	m.logView.AddInfo("CAMPAIGN COMPLETED")
	m.logView.AddInfo(fmt.Sprintf("  Targets:  %d", m.totalTargets))
	m.logView.AddInfo(fmt.Sprintf("  Modules:  %d OK, %d FAILED", m.successModules, m.failedModules))
	m.logView.AddInfo(fmt.Sprintf("  Findings: %d", len(m.findings)))
	m.logView.AddInfo("═══════════════════════════════════════")
	m.logView.AddInfo("Press '4' or Tab to view Results")
}

func (m *Model) handleLogEntry(e events.LogEntry) {
	switch e.Level {
	case "error":
		m.logView.AddError(e.Message)
	case "warn":
		m.logView.AddWarn(e.Message)
	default:
		m.logView.AddInfo(e.Message)
	}
}

func (m *Model) updateFindingTable() {
	rows := make([]components.Row, len(m.findings))
	for i, f := range m.findings {
		timeStr := f.Timestamp.Format("15:04:05")
		severity := strings.ToUpper(f.Severity)
		target := f.Target.String()
		if len(target) > 22 {
			target = target[:19] + "..."
		}
		result := "● Failed"
		if f.Success {
			result = "● Success"
		}
		rows[i] = components.Row{result, timeStr, severity, f.ID, target}
	}
	m.findingTable.SetRows(rows)
}

// Findings returns all discovered findings
func (m Model) Findings() []domain.Finding {
	return m.findings
}

// Update handles messages
func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.MouseMsg:
		if msg.Button == tea.MouseButtonWheelUp {
			m.logView.ScrollBy(-3)
		} else if msg.Button == tea.MouseButtonWheelDown {
			m.logView.ScrollBy(3)
		}

	case tea.KeyMsg:
		m.handleKeyMsg(msg)
	}

	return m, nil
}

func (m *Model) handleKeyMsg(msg tea.KeyMsg) {
	switch {
	case key.Matches(msg, m.keys.Stop):
		if m.state == components.StateRunning || m.state == components.StateScanning {
			m.Stop()
		}
	case key.Matches(msg, m.keys.Left):
		if m.focus > FocusProgress {
			m.focus--
			m.findingTable.Focused = (m.focus == FocusFindings)
		}
	case key.Matches(msg, m.keys.Right):
		if m.focus < FocusLogs {
			m.focus++
			m.findingTable.Focused = (m.focus == FocusFindings)
		}
	case key.Matches(msg, m.keys.Up):
		switch m.focus {
		case FocusFindings:
			m.findingTable.MoveUp()
		case FocusLogs:
			m.logView.ScrollUp()
		}
	case key.Matches(msg, m.keys.Down):
		switch m.focus {
		case FocusFindings:
			m.findingTable.MoveDown()
		case FocusLogs:
			m.logView.ScrollDown()
		}
	case key.Matches(msg, m.keys.PageUp):
		if m.focus == FocusLogs {
			m.logView.PageUp()
		}
	case key.Matches(msg, m.keys.PageDown):
		if m.focus == FocusLogs {
			m.logView.PageDown()
		}
	case key.Matches(msg, m.keys.Tab):
		m.focus = (m.focus + 1) % 3
		m.findingTable.Focused = (m.focus == FocusFindings)
	}
}

// View renders the view
func (m Model) View() string {
	header := m.renderHeader()
	progressPanel := m.renderProgressPanel()
	findingsPanel := m.renderFindingsPanel()
	logsPanel := m.renderLogsPanel()

	topRow := lipgloss.JoinHorizontal(lipgloss.Top, progressPanel, " ", findingsPanel)
	help := styles.HelpStyle.Render("←→: panels • ↑↓/scroll: navigate logs • x: stop • 4: results")

	return lipgloss.JoinVertical(lipgloss.Left, header, topRow, logsPanel, help)
}

func (m Model) renderHeader() string {
	var parts []string

	if m.campaign != nil {
		parts = append(parts, styles.PanelTitleStyle.Render("Campaign: "+m.campaign.ID))
	} else {
		parts = append(parts, styles.PanelTitleStyle.Render("Execution"))
	}

	stateStyle := styles.BaseStyle
	switch m.state {
	case components.StateScanning:
		stateStyle = stateStyle.Foreground(styles.Warning).Bold(true)
		parts = append(parts, " ", stateStyle.Render("◉ "+m.state.String()))
		parts = append(parts, " ", m.spinner.View())
	case components.StateRunning:
		stateStyle = stateStyle.Foreground(styles.Primary).Bold(true)
		parts = append(parts, " ", stateStyle.Render("◉ "+m.state.String()))
		parts = append(parts, " ", m.spinner.View())
	case components.StateCompleted:
		stateStyle = stateStyle.Foreground(styles.Success)
		parts = append(parts, " ", stateStyle.Render("◉ "+m.state.String()))
	case components.StateFailed:
		stateStyle = stateStyle.Foreground(styles.Error)
		parts = append(parts, " ", stateStyle.Render("◉ "+m.state.String()))
	default:
		stateStyle = stateStyle.Foreground(styles.Muted)
		parts = append(parts, " ", stateStyle.Render("◉ "+m.state.String()))
	}

	if m.successModules > 0 || m.failedModules > 0 {
		parts = append(parts, "  ")
		parts = append(parts, styles.BaseStyle.Foreground(styles.Success).Render(
			fmt.Sprintf("✓%d", m.successModules)))
		if m.failedModules > 0 {
			parts = append(parts, " ")
			parts = append(parts, styles.BaseStyle.Foreground(styles.Error).Render(
				fmt.Sprintf("✗%d", m.failedModules)))
		}
	}

	if !m.startTime.IsZero() {
		elapsed := time.Since(m.startTime).Truncate(time.Second)
		parts = append(parts, "  ", styles.BaseStyle.Foreground(styles.Muted).Render(elapsed.String()))
	}

	if m.state == components.StateRunning || m.state == components.StateScanning {
		parts = append(parts, "  ", styles.HelpStyle.Render("[x] stop"))
	}

	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

func (m Model) renderProgressPanel() string {
	panelWidth := m.width/2 - 2
	if panelWidth < 40 {
		panelWidth = 40
	}

	var lines []string

	lines = append(lines, styles.PanelTitle("SCANNER", panelWidth))
	scannerBar := components.NewProgressBar(panelWidth - 4)
	scannerBar.SetProgress(m.scannerProgress)
	scannerBar.SetLabel(m.scannerStatus)
	lines = append(lines, scannerBar.View())

	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("Targets found: %d", len(m.targets)))
	for i, t := range m.targets {
		if i >= 5 {
			lines = append(lines, styles.BaseStyle.Foreground(styles.Muted).Render(
				fmt.Sprintf("  ... and %d more", len(m.targets)-5),
			))
			break
		}
		lines = append(lines, styles.BaseStyle.Foreground(styles.TextDim).Render("  "+t.Target.String()))
	}

	if m.currentModule != "" {
		lines = append(lines, "")
		lines = append(lines, styles.PanelTitle("MODULE", panelWidth))
		lines = append(lines, fmt.Sprintf("Target: %s", m.currentTarget.String()))
		lines = append(lines, fmt.Sprintf("Module: %s", m.currentModule))

		moduleBar := components.NewProgressBar(panelWidth - 4)
		moduleBar.SetProgress(m.moduleProgress)
		if !m.moduleStartTime.IsZero() {
			elapsed := time.Since(m.moduleStartTime).Truncate(time.Second)
			moduleBar.SetLabel(fmt.Sprintf("%s / %s", elapsed, m.moduleTimeout))
		}
		lines = append(lines, moduleBar.View())

		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("Completed: %d / %d targets", m.completedCount, m.totalTargets))
	}

	if m.outputDir != "" {
		lines = append(lines, "")
		lines = append(lines, styles.BaseStyle.Foreground(styles.Muted).Render("Output: "+m.outputDir))
	}

	content := lipgloss.JoinVertical(lipgloss.Left, lines...)

	focusStyle := styles.PanelStyle.Width(panelWidth).Height(m.topPanelHeight)
	if m.focus == FocusProgress {
		focusStyle = styles.PanelFocusedStyle.Width(panelWidth).Height(m.topPanelHeight)
	}

	return focusStyle.Render(content)
}

func (m Model) renderFindingsPanel() string {
	panelWidth := m.width/2 - 2
	if panelWidth < 40 {
		panelWidth = 40
	}

	title := styles.PanelTitle(
		fmt.Sprintf("LIVE FINDINGS (%d)", len(m.findings)), panelWidth,
	)

	var content string
	if len(m.findings) == 0 {
		content = styles.BaseStyle.Foreground(styles.Muted).Render("No findings yet...")
	} else {
		content = m.findingTable.View()
	}

	focusStyle := styles.PanelStyle.Width(panelWidth).Height(m.topPanelHeight)
	if m.focus == FocusFindings {
		focusStyle = styles.PanelFocusedStyle.Width(panelWidth).Height(m.topPanelHeight)
	}

	return focusStyle.Render(lipgloss.JoinVertical(lipgloss.Left, title, content))
}

func (m Model) renderLogsPanel() string {
	logsTitle := "LOGS"
	scrollHint := ""
	if len(m.logView.Messages) > m.logView.Height {
		scrollHint = fmt.Sprintf(" (%d/%d)",
			m.logView.Offset+m.logView.Height,
			len(m.logView.Messages))
		hintWidth := lipgloss.Width(scrollHint) + lipgloss.Width(logsTitle)
		if hintWidth >= m.width-6 {
			scrollHint = ""
		}
	}

	title := styles.PanelTitle(logsTitle+scrollHint, m.width-4)
	content := m.logView.View()

	focusStyle := styles.PanelStyle.Width(m.width - 2)
	if m.focus == FocusLogs {
		focusStyle = styles.PanelFocusedStyle.Width(m.width - 2)
	}

	return focusStyle.Render(lipgloss.JoinVertical(lipgloss.Left, title, content))
}
