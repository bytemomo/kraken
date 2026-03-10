package campaign

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"bytemomo/kraken/internal/adapter/yamlconfig"
	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/tui/components"
	"bytemomo/kraken/internal/tui/keys"
	"bytemomo/kraken/internal/tui/styles"

	"github.com/charmbracelet/bubbles/filepicker"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Focus represents which panel is focused
type Focus int

const (
	FocusFilePicker Focus = iota
	FocusConfig
	FocusTasks
	FocusTargets
)

// Model is the campaign view model
type Model struct {
	width      int
	height     int
	focus      Focus
	keys       keys.KeyMap
	filePicker filepicker.Model
	campaign   *domain.Campaign
	path       string
	taskTable  components.Table
	err        error
	showPicker bool

	// Target configuration
	cidrInput      textinput.Model
	cidrs          []string
	ifaceInput     textinput.Model
	iface          string
	outputInput    textinput.Model
	outputDir      string
	availableIfaces []string
	ifaceIndex     int
	inputFocus     int // 0=cidr, 1=iface, 2=output
}

// CampaignLoadedMsg is sent when a campaign is loaded
type CampaignLoadedMsg struct {
	Campaign *domain.Campaign
	Path     string
}

// CampaignLoadErrorMsg is sent when campaign loading fails
type CampaignLoadErrorMsg struct {
	Error error
}

// StartRequestedMsg is sent when user wants to start the campaign
type StartRequestedMsg struct {
	Campaign  *domain.Campaign
	Path      string
	CIDRs     []string
	Interface string
	OutputDir string
}

// New creates a new campaign view model
func New(keyMap keys.KeyMap) Model {
	fp := filepicker.New()
	fp.AllowedTypes = []string{".yaml", ".yml"}
	fp.CurrentDirectory, _ = os.Getwd()
	fp.ShowHidden = false
	fp.Height = 15

	taskTable := components.NewTable([]components.Column{
		{Title: "Module ID", Width: 30},
		{Title: "Type", Width: 12},
		{Title: "Tags", Width: 25},
		{Title: "Duration", Width: 10},
	})

	// CIDR input
	cidrInput := textinput.New()
	cidrInput.Placeholder = "192.168.1.0/24, 10.0.0.0/8"
	cidrInput.Width = 40
	cidrInput.CharLimit = 200

	// Interface input
	ifaceInput := textinput.New()
	ifaceInput.Placeholder = "eth0"
	ifaceInput.Width = 20
	ifaceInput.CharLimit = 50

	// Output directory input
	outputInput := textinput.New()
	outputInput.Placeholder = "./kraken-results"
	outputInput.Width = 40
	outputInput.CharLimit = 200
	outputInput.SetValue("./kraken-results")

	// Get available network interfaces
	ifaces := listNetworkInterfaces()

	return Model{
		keys:            keyMap,
		filePicker:      fp,
		taskTable:       taskTable,
		showPicker:      true,
		focus:           FocusFilePicker,
		cidrInput:       cidrInput,
		ifaceInput:      ifaceInput,
		outputInput:     outputInput,
		outputDir:       "./kraken-results",
		availableIfaces: ifaces,
	}
}

func listNetworkInterfaces() []string {
	var names []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return names
	}
	for _, iface := range ifaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		names = append(names, iface.Name)
	}
	return names
}

// Init initializes the model
func (m Model) Init() tea.Cmd {
	return m.filePicker.Init()
}

// SetSize sets the view dimensions
func (m *Model) SetSize(width, height int) {
	m.width = width
	m.height = height
	m.filePicker.Height = height - 4
	m.taskTable.SetSize(width/2-4, height-16)
}

// SetCampaign sets the loaded campaign
func (m *Model) SetCampaign(campaign *domain.Campaign, path string) {
	m.campaign = campaign
	m.path = path
	m.showPicker = false
	m.focus = FocusTargets
	m.cidrInput.Focus()
	m.updateTaskTable()
}

// Campaign returns the loaded campaign
func (m Model) Campaign() *domain.Campaign {
	return m.campaign
}

// Path returns the campaign path
func (m Model) Path() string {
	return m.path
}

// CIDRs returns the configured CIDRs
func (m Model) CIDRs() []string {
	return m.cidrs
}

// Interface returns the configured interface
func (m Model) Interface() string {
	return m.iface
}

// OutputDir returns the configured output directory
func (m Model) OutputDir() string {
	return m.outputDir
}

func (m *Model) updateTaskTable() {
	if m.campaign == nil {
		return
	}

	rows := make([]components.Row, len(m.campaign.Tasks))
	for i, task := range m.campaign.Tasks {
		tags := strings.Join(task.RequiredTags, ", ")
		if len(tags) > 25 {
			tags = tags[:22] + "..."
		}
		duration := "N/A"
		if task.MaxDuration > 0 {
			duration = task.MaxDuration.String()
		}
		rows[i] = components.Row{
			task.ModuleID,
			string(task.Type),
			tags,
			duration,
		}
	}
	m.taskTable.SetRows(rows)
}

func (m *Model) parseCIDRs() {
	input := m.cidrInput.Value()
	m.cidrs = nil
	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Validate CIDR or single IP
		if _, _, err := net.ParseCIDR(part); err == nil {
			m.cidrs = append(m.cidrs, part)
		} else if ip := net.ParseIP(part); ip != nil {
			// Single IP - convert to /32 or /128
			if ip.To4() != nil {
				m.cidrs = append(m.cidrs, part+"/32")
			} else {
				m.cidrs = append(m.cidrs, part+"/128")
			}
		}
	}
}

// IsTextInputActive returns true if a text input is currently focused
func (m Model) IsTextInputActive() bool {
	return m.focus == FocusTargets && !m.showPicker
}

// Update handles messages
func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		// When text input is active, only handle specific control keys
		if m.IsTextInputActive() {
			switch msg.String() {
			case "tab":
				m.inputFocus = (m.inputFocus + 1) % 3
				m.updateInputFocus()
				return m, nil
			case "shift+tab":
				m.inputFocus = (m.inputFocus + 2) % 3
				m.updateInputFocus()
				return m, nil
			case "ctrl+s":
				// Start with ctrl+s when typing
				if m.campaign != nil {
					m.parseCIDRs()
					m.iface = m.ifaceInput.Value()
					m.outputDir = m.outputInput.Value()
					if m.outputDir == "" {
						m.outputDir = "./kraken-results"
					}
					return m, func() tea.Msg {
						return StartRequestedMsg{
							Campaign:  m.campaign,
							Path:      m.path,
							CIDRs:     m.cidrs,
							Interface: m.iface,
							OutputDir: m.outputDir,
						}
					}
				}
			case "esc":
				// Escape exits text input mode
				m.focus = FocusConfig
				m.cidrInput.Blur()
				m.ifaceInput.Blur()
				m.outputInput.Blur()
				return m, nil
			case "up":
				// Only for interface selector
				if m.inputFocus == 1 && len(m.availableIfaces) > 0 {
					m.ifaceIndex = (m.ifaceIndex - 1 + len(m.availableIfaces)) % len(m.availableIfaces)
					m.iface = m.availableIfaces[m.ifaceIndex]
					m.ifaceInput.SetValue(m.iface)
					return m, nil
				}
			case "down":
				// Only for interface selector
				if m.inputFocus == 1 && len(m.availableIfaces) > 0 {
					m.ifaceIndex = (m.ifaceIndex + 1) % len(m.availableIfaces)
					m.iface = m.availableIfaces[m.ifaceIndex]
					m.ifaceInput.SetValue(m.iface)
					return m, nil
				}
			}

			// Pass all other keys to the text input
			var cmd tea.Cmd
			switch m.inputFocus {
			case 0:
				m.cidrInput, cmd = m.cidrInput.Update(msg)
				m.parseCIDRs()
			case 1:
				m.ifaceInput, cmd = m.ifaceInput.Update(msg)
			case 2:
				m.outputInput, cmd = m.outputInput.Update(msg)
			}
			return m, cmd
		}

		// Normal key handling when not typing
		switch {
		case key.Matches(msg, m.keys.Back):
			if !m.showPicker && m.campaign != nil {
				m.showPicker = true
				m.focus = FocusFilePicker
			}
		case key.Matches(msg, m.keys.Open):
			m.showPicker = true
			m.focus = FocusFilePicker
		case key.Matches(msg, m.keys.Start):
			if m.campaign != nil && !m.showPicker {
				m.parseCIDRs()
				m.iface = m.ifaceInput.Value()
				m.outputDir = m.outputInput.Value()
				if m.outputDir == "" {
					m.outputDir = "./kraken-results"
				}
				return m, func() tea.Msg {
					return StartRequestedMsg{
						Campaign:  m.campaign,
						Path:      m.path,
						CIDRs:     m.cidrs,
						Interface: m.iface,
						OutputDir: m.outputDir,
					}
				}
			}
		case key.Matches(msg, m.keys.Left):
			if !m.showPicker && m.focus != FocusTargets {
				if m.focus == FocusTasks {
					m.focus = FocusConfig
					m.taskTable.Focused = false
				} else if m.focus == FocusConfig {
					m.focus = FocusTargets
					m.updateInputFocus()
				}
			}
		case key.Matches(msg, m.keys.Right):
			if !m.showPicker && m.focus != FocusTasks {
				if m.focus == FocusTargets {
					m.focus = FocusConfig
					m.cidrInput.Blur()
					m.ifaceInput.Blur()
					m.outputInput.Blur()
				} else if m.focus == FocusConfig {
					m.focus = FocusTasks
					m.taskTable.Focused = true
				}
			}
		case key.Matches(msg, m.keys.Enter):
			// Enter focuses the target input panel
			if !m.showPicker && m.focus != FocusTargets {
				m.focus = FocusTargets
				m.updateInputFocus()
			}
		case key.Matches(msg, m.keys.Up):
			if m.focus == FocusTasks {
				m.taskTable.MoveUp()
			}
		case key.Matches(msg, m.keys.Down):
			if m.focus == FocusTasks {
				m.taskTable.MoveDown()
			}
		}

	case CampaignLoadedMsg:
		m.SetCampaign(msg.Campaign, msg.Path)
		return m, nil

	case CampaignLoadErrorMsg:
		m.err = msg.Error
		return m, nil
	}

	// Update file picker if showing
	if m.showPicker {
		var cmd tea.Cmd
		m.filePicker, cmd = m.filePicker.Update(msg)
		cmds = append(cmds, cmd)

		if didSelect, path := m.filePicker.DidSelectFile(msg); didSelect {
			return m, loadCampaignCmd(path)
		}
	}

	return m, tea.Batch(cmds...)
}

func (m *Model) updateInputFocus() {
	m.cidrInput.Blur()
	m.ifaceInput.Blur()
	m.outputInput.Blur()

	switch m.inputFocus {
	case 0:
		m.cidrInput.Focus()
	case 1:
		m.ifaceInput.Focus()
	case 2:
		m.outputInput.Focus()
	}
}

func loadCampaignCmd(path string) tea.Cmd {
	return func() tea.Msg {
		campaign, err := yamlconfig.LoadCampaign(path)
		if err != nil {
			return CampaignLoadErrorMsg{Error: err}
		}
		return CampaignLoadedMsg{Campaign: campaign, Path: path}
	}
}

// View renders the view
func (m Model) View() string {
	if m.showPicker {
		return m.renderFilePicker()
	}
	return m.renderCampaignDetails()
}

func (m Model) renderFilePicker() string {
	title := styles.PanelTitleStyle.Render("Select Campaign File")

	var content string
	if m.err != nil {
		content = styles.BaseStyle.Foreground(styles.Error).Render(
			fmt.Sprintf("Error: %v", m.err),
		) + "\n\n"
	}
	content += m.filePicker.View()

	help := styles.HelpStyle.Render("↑/↓: navigate • enter: select • esc: cancel")

	return lipgloss.JoinVertical(lipgloss.Left, title, content, help)
}

func (m Model) renderCampaignDetails() string {
	if m.campaign == nil {
		return styles.BaseStyle.Foreground(styles.Muted).Render("No campaign loaded. Press 'o' to open a campaign file.")
	}

	// Header
	header := styles.PanelTitleStyle.Render(fmt.Sprintf("Campaign: %s", filepath.Base(m.path)))
	if m.campaign.Name != "" {
		header += " " + styles.BaseStyle.Foreground(styles.Muted).Render("("+m.campaign.Name+")")
	}

	// Target configuration panel
	targetPanel := m.renderTargetPanel()

	// Configuration panel
	configPanel := m.renderConfigPanel()

	// Tasks panel
	tasksPanel := m.renderTasksPanel()

	// Top row: Target config
	// Bottom row: Config + Tasks side by side
	bottomRow := lipgloss.JoinHorizontal(
		lipgloss.Top,
		configPanel,
		" ",
		tasksPanel,
	)

	// Help - different when typing
	var help string
	if m.focus == FocusTargets {
		help = styles.HelpStyle.Render("Tab: next field • Esc: exit input • Ctrl+S: START CAMPAIGN • ↑/↓: select interface")
	} else {
		help = styles.HelpStyle.Render("s: START CAMPAIGN • Enter: edit targets • ←→: panels • o: open file")
	}

	return lipgloss.JoinVertical(lipgloss.Left, header, targetPanel, bottomRow, help)
}

func (m Model) renderTargetPanel() string {
	panelWidth := m.width - 4
	if panelWidth < 60 {
		panelWidth = 60
	}

	title := styles.PanelTitle("TARGET CONFIGURATION", panelWidth)

	// CIDR input
	cidrLabel := "Target CIDRs:"
	if m.inputFocus == 0 && m.focus == FocusTargets {
		cidrLabel = styles.BaseStyle.Foreground(styles.Primary).Render("› ") + cidrLabel
	} else {
		cidrLabel = "  " + cidrLabel
	}
	cidrLine := lipgloss.JoinHorizontal(lipgloss.Left,
		styles.BaseStyle.Width(18).Render(cidrLabel),
		m.cidrInput.View(),
	)

	// Interface selector
	ifaceLabel := "Interface:"
	if m.inputFocus == 1 && m.focus == FocusTargets {
		ifaceLabel = styles.BaseStyle.Foreground(styles.Primary).Render("› ") + ifaceLabel
	} else {
		ifaceLabel = "  " + ifaceLabel
	}
	ifaceLine := lipgloss.JoinHorizontal(lipgloss.Left,
		styles.BaseStyle.Width(18).Render(ifaceLabel),
		m.ifaceInput.View(),
	)
	if len(m.availableIfaces) > 0 {
		ifaceLine += styles.BaseStyle.Foreground(styles.Muted).Render(
			fmt.Sprintf("  (↑/↓ to select: %s)", strings.Join(m.availableIfaces, ", ")),
		)
	}

	// Output directory
	outLabel := "Output Dir:"
	if m.inputFocus == 2 && m.focus == FocusTargets {
		outLabel = styles.BaseStyle.Foreground(styles.Primary).Render("› ") + outLabel
	} else {
		outLabel = "  " + outLabel
	}
	outLine := lipgloss.JoinHorizontal(lipgloss.Left,
		styles.BaseStyle.Width(18).Render(outLabel),
		m.outputInput.View(),
	)

	// Validation status
	var statusLine string
	if len(m.cidrs) > 0 {
		statusLine = styles.BaseStyle.Foreground(styles.Success).Render(
			fmt.Sprintf("  ✓ %d valid target(s) configured", len(m.cidrs)),
		)
	} else if m.cidrInput.Value() != "" {
		statusLine = styles.BaseStyle.Foreground(styles.Error).Render(
			"  ✗ No valid CIDRs parsed",
		)
	} else {
		statusLine = styles.BaseStyle.Foreground(styles.Warning).Render(
			"  ⚠ Enter target CIDRs to scan",
		)
	}

	content := lipgloss.JoinVertical(lipgloss.Left,
		title,
		cidrLine,
		ifaceLine,
		outLine,
		statusLine,
	)

	focusStyle := styles.PanelStyle.Width(panelWidth)
	if m.focus == FocusTargets {
		focusStyle = styles.PanelFocusedStyle.Width(panelWidth)
	}

	return focusStyle.Render(content)
}

func (m Model) renderConfigPanel() string {
	panelWidth := m.width/2 - 3
	if panelWidth < 30 {
		panelWidth = 30
	}

	title := styles.PanelTitle("CAMPAIGN CONFIG", panelWidth)

	var lines []string

	// Basic info
	lines = append(lines, renderField("ID", m.campaign.ID))
	if m.campaign.Name != "" {
		lines = append(lines, renderField("Name", m.campaign.Name))
	}
	lines = append(lines, renderField("Type", string(m.campaign.EffectiveType())))
	if m.campaign.Version != "" {
		lines = append(lines, renderField("Version", m.campaign.Version))
	}

	// Policy
	lines = append(lines, "")
	lines = append(lines, styles.BaseStyle.Foreground(styles.Secondary).Bold(true).Render("Safety Policy:"))
	policy := m.campaign.EffectivePolicy()
	aggressiveIcon := "✗"
	aggressiveColor := styles.Success
	if policy.Safety.AllowAggressive {
		aggressiveIcon = "✓"
		aggressiveColor = styles.Warning
	}
	lines = append(lines, styles.BaseStyle.Foreground(aggressiveColor).Render(
		fmt.Sprintf("  %s Aggressive: %v", aggressiveIcon, policy.Safety.AllowAggressive),
	))
	lines = append(lines, renderField("  Max Parallel", fmt.Sprintf("%d targets", policy.Runner.MaxParallelTargets)))
	
	// Connection defaults
	if policy.Runner.Defaults.ConnectionTimeout > 0 {
		lines = append(lines, renderField("  Conn Timeout", policy.Runner.Defaults.ConnectionTimeout.String()))
	}

	// Scanners
	scanners := m.campaign.EffectiveScanners()
	if len(scanners) > 0 {
		lines = append(lines, "")
		lines = append(lines, styles.BaseStyle.Foreground(styles.Secondary).Bold(true).Render("Scanners:"))
		for _, s := range scanners {
			scannerType := s.Type
			if scannerType == "" {
				scannerType = "nmap"
			}
			scannerInfo := "  • " + scannerType
			if s.Nmap != nil && len(s.Nmap.Ports) > 0 {
				ports := strings.Join(s.Nmap.Ports, ",")
				if len(ports) > 20 {
					ports = ports[:17] + "..."
				}
				scannerInfo += fmt.Sprintf(" (ports: %s)", ports)
			}
			lines = append(lines, styles.BaseStyle.Foreground(styles.TextDim).Render(scannerInfo))
		}
	}

	// Task summary
	lines = append(lines, "")
	lines = append(lines, styles.BaseStyle.Foreground(styles.Secondary).Bold(true).Render("Task Summary:"))
	registryCount := 0
	nativeCount := 0
	abiCount := 0
	for _, t := range m.campaign.Tasks {
		if t.Registry != "" {
			registryCount++
		} else if t.Type == domain.Native {
			nativeCount++
		} else if t.Type == domain.Lib {
			abiCount++
		}
	}
	lines = append(lines, renderField("  Total Tasks", fmt.Sprintf("%d", len(m.campaign.Tasks))))
	if registryCount > 0 {
		lines = append(lines, renderField("  Registry", fmt.Sprintf("%d modules", registryCount)))
	}
	if nativeCount > 0 {
		lines = append(lines, renderField("  Native", fmt.Sprintf("%d modules", nativeCount)))
	}
	if abiCount > 0 {
		lines = append(lines, renderField("  ABI", fmt.Sprintf("%d modules", abiCount)))
	}

	content := lipgloss.JoinVertical(lipgloss.Left, lines...)

	focusStyle := styles.PanelStyle.Width(panelWidth).Height(m.height - 18)
	if m.focus == FocusConfig {
		focusStyle = styles.PanelFocusedStyle.Width(panelWidth).Height(m.height - 18)
	}

	return focusStyle.Render(lipgloss.JoinVertical(lipgloss.Left, title, content))
}

func (m Model) renderTasksPanel() string {
	panelWidth := m.width/2 - 3
	if panelWidth < 30 {
		panelWidth = 30
	}

	title := styles.PanelTitle(
		fmt.Sprintf("TASKS (%d)", len(m.campaign.Tasks)), panelWidth,
	)

	content := m.taskTable.View()

	focusStyle := styles.PanelStyle.Width(panelWidth).Height(m.height - 18)
	if m.focus == FocusTasks {
		focusStyle = styles.PanelFocusedStyle.Width(panelWidth).Height(m.height - 18)
	}

	return focusStyle.Render(lipgloss.JoinVertical(lipgloss.Left, title, content))
}

func renderField(label, value string) string {
	return styles.BaseStyle.Foreground(styles.Muted).Render(label+": ") +
		styles.BaseStyle.Foreground(styles.Text).Render(value)
}
