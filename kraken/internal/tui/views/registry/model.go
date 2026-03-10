package registry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"bytemomo/kraken/internal/registry"
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
	FocusList Focus = iota
	FocusDetails
)

// ModuleItem represents a module in the list
type ModuleItem struct {
	ID        string
	Type      string
	Latest    string
	Cached    bool
	CachedVer string
	HasUpdate bool
	Available bool   // artifact exists for current platform
	Error     string // reason if not available
}

// Model is the registry view model
type Model struct {
	width    int
	height   int
	focus    Focus
	keys     keys.KeyMap
	client   *registry.Client
	modules  []ModuleItem
	table    components.Table
	selected *registry.ResolvedModule
	loading  bool
	err      error
	cacheDir string
}

// IndexRefreshedMsg is sent when the index is refreshed
type IndexRefreshedMsg struct {
	Modules []ModuleItem
	Error   error
}

// ModuleResolvedMsg is sent when a module is resolved
type ModuleResolvedMsg struct {
	Module *registry.ResolvedModule
	Error  error
}

// ModuleDownloadedMsg is sent when a module is downloaded
type ModuleDownloadedMsg struct {
	ModuleID string
	Error    error
}

// New creates a new registry view model
func New(keyMap keys.KeyMap) Model {
	table := components.NewTable([]components.Column{
		{Title: "Module ID", Width: 25},
		{Title: "Type", Width: 12},
		{Title: "Latest", Width: 10},
		{Title: "Status", Width: 20},
	})

	home, _ := os.UserHomeDir()
	cacheDir := filepath.Join(home, ".kraken", "modules")

	return Model{
		keys:     keyMap,
		table:    table,
		focus:    FocusList,
		cacheDir: cacheDir,
	}
}

// Init initializes the model
func (m Model) Init() tea.Cmd {
	return m.refreshIndexCmd()
}

// SetSize sets the view dimensions
func (m *Model) SetSize(width, height int) {
	m.width = width
	m.height = height
	m.table.SetSize(width/2-4, height-6)
}

func (m Model) refreshIndexCmd() tea.Cmd {
	return m.fetchIndexCmd(false)
}

func (m Model) forceRefreshIndexCmd() tea.Cmd {
	return m.fetchIndexCmd(true)
}

func (m Model) fetchIndexCmd(forceRemote bool) tea.Cmd {
	return func() tea.Msg {
		cfg := registry.DefaultConfig()
		cfg.SkipIndexVerify = true // Browse-only; verification happens on download
		client, err := registry.NewClient(cfg)
		if err != nil {
			return IndexRefreshedMsg{Error: err}
		}

		ctx := context.Background()
		var index *registry.Index
		if forceRemote {
			index, err = client.RefreshIndex(ctx)
		} else {
			index, err = client.GetIndex(ctx)
		}
		if err != nil {
			return IndexRefreshedMsg{Error: err}
		}

		home, _ := os.UserHomeDir()
		cacheDir := filepath.Join(home, ".kraken", "modules")

		platform := registry.GetPlatform()

		var modules []ModuleItem
		for id, mod := range index.Modules {
			item := ModuleItem{
				ID:     id,
				Type:   mod.Type,
				Latest: mod.Latest,
			}

			// Check platform availability
			if ver, ok := mod.Versions[mod.Latest]; ok {
				if _, ok := ver.Artifacts[platform]; ok {
					item.Available = true
				} else {
					item.Error = "no " + platform + " artifact"
				}
			} else {
				item.Error = "version not found"
			}

			// Check if cached
			cachedPath := filepath.Join(cacheDir, id)
			if entries, err := os.ReadDir(cachedPath); err == nil && len(entries) > 0 {
				item.Cached = true
				for _, e := range entries {
					if e.IsDir() {
						item.CachedVer = e.Name()
					}
				}
				if item.CachedVer != item.Latest {
					item.HasUpdate = true
				}
			}

			modules = append(modules, item)
		}

		sort.Slice(modules, func(i, j int) bool {
			return modules[i].ID < modules[j].ID
		})

		return IndexRefreshedMsg{Modules: modules}
	}
}

func (m Model) resolveModuleCmd(moduleID string) tea.Cmd {
	return func() tea.Msg {
		cfg := registry.DefaultConfig()
		cfg.SkipIndexVerify = true
		client, err := registry.NewClient(cfg)
		if err != nil {
			return ModuleResolvedMsg{Error: err}
		}

		ctx := context.Background()
		resolved, err := client.ResolveOnly(ctx, moduleID, "latest")
		if err != nil {
			return ModuleResolvedMsg{Error: err}
		}

		return ModuleResolvedMsg{Module: resolved}
	}
}

func (m Model) downloadModuleCmd(moduleID string) tea.Cmd {
	return func() tea.Msg {
		client, err := registry.NewClient(registry.DefaultConfig())
		if err != nil {
			return ModuleDownloadedMsg{Error: err}
		}

		ctx := context.Background()
		resolved, err := client.ResolveAndDownload(
			ctx, moduleID, "latest",
		)
		if err != nil {
			return ModuleDownloadedMsg{ModuleID: moduleID, Error: err}
		}

		return ModuleDownloadedMsg{ModuleID: resolved.ID}
	}
}

// Update handles messages
func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Refresh):
			m.loading = true
			m.err = nil
			return m, m.forceRefreshIndexCmd()
		case key.Matches(msg, m.keys.Download):
			if row := m.table.SelectedRow(); row != nil {
				m.loading = true
				return m, m.downloadModuleCmd(row[0])
			}
		case key.Matches(msg, m.keys.Up):
			if m.focus == FocusList {
				m.table.MoveUp()
				m.selected = nil
				m.tryLoadCachedDetails()
			}
		case key.Matches(msg, m.keys.Down):
			if m.focus == FocusList {
				m.table.MoveDown()
				m.selected = nil
				m.tryLoadCachedDetails()
			}
		case key.Matches(msg, m.keys.Left), key.Matches(msg, m.keys.Right):
			if m.focus == FocusList {
				m.focus = FocusDetails
				m.table.Focused = false
			} else {
				m.focus = FocusList
				m.table.Focused = true
			}
		case key.Matches(msg, m.keys.Enter):
			if row := m.table.SelectedRow(); row != nil {
				return m, m.resolveModuleCmd(row[0])
			}
		}

	case IndexRefreshedMsg:
		m.loading = false
		if msg.Error != nil {
			m.err = msg.Error
			return m, nil
		}
		m.modules = msg.Modules
		m.updateTable()
		m.tryLoadCachedDetails()

	case ModuleResolvedMsg:
		m.loading = false
		if msg.Error != nil {
			m.err = msg.Error
			return m, nil
		}
		m.err = nil
		m.selected = msg.Module
		return m, m.refreshIndexCmd()

	case ModuleDownloadedMsg:
		m.loading = false
		if msg.Error != nil {
			m.err = msg.Error
			return m, nil
		}
		m.err = nil
		return m, m.refreshIndexCmd()
	}

	return m, nil
}

func (m *Model) updateTable() {
	rows := make([]components.Row, len(m.modules))
	for i, mod := range m.modules {
		var status string
		if !mod.Available {
			status = styles.BaseStyle.Foreground(styles.Error).
				Render("✗ " + mod.Error)
		} else if mod.Cached {
			if mod.HasUpdate {
				status = styles.BadgeCached.Render("v"+mod.CachedVer) + " " +
					styles.BadgeUpdate.Render("→ v"+mod.Latest)
			} else {
				status = styles.BadgeCached.Render("✓ cached")
			}
		} else {
			status = styles.BadgeNotCached.Render("↓ download")
		}
		rows[i] = components.Row{
			mod.ID,
			mod.Type,
			mod.Latest,
			status,
		}
	}
	m.table.SetRows(rows)
}

// View renders the view
func (m Model) View() string {
	// Header with actions
	helpHint := styles.HelpStyle.Render("enter: details  d: download  r: refresh")
	header := styles.PanelTitle("MODULE REGISTRY", m.width-lipgloss.Width(helpHint)-4)
	header = lipgloss.JoinHorizontal(lipgloss.Top, header, "  ", helpHint)

	if m.loading {
		header += "  " + styles.BaseStyle.Foreground(styles.Warning).Render("⠸ loading")
	}

	// Error display
	errDisplay := ""
	if m.err != nil {
		errDisplay = styles.BaseStyle.Foreground(styles.Error).Render(
			fmt.Sprintf("─ ERROR: %v", m.err),
		)
	}

	// Left panel: Module list
	listPanel := m.renderListPanel()

	// Right panel: Module details
	detailsPanel := m.renderDetailsPanel()

	// Join panels
	panels := lipgloss.JoinHorizontal(lipgloss.Top, listPanel, " ", detailsPanel)

	parts := []string{header}
	if errDisplay != "" {
		parts = append(parts, errDisplay)
	}
	parts = append(parts, panels)

	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

func (m Model) renderListPanel() string {
	panelWidth := m.width/2 - 2
	if panelWidth < 40 {
		panelWidth = 40
	}

	title := styles.PanelTitle(fmt.Sprintf("AVAILABLE MODULES (%d)", len(m.modules)), panelWidth)
	content := m.table.View()

	focusStyle := styles.PanelStyle.Width(panelWidth)
	if m.focus == FocusList {
		focusStyle = styles.PanelFocusedStyle.Width(panelWidth)
	}

	return focusStyle.Render(lipgloss.JoinVertical(lipgloss.Left, title, content))
}

func (m Model) renderDetailsPanel() string {
	panelWidth := m.width/2 - 2
	if panelWidth < 40 {
		panelWidth = 40
	}

	title := styles.PanelTitle("MODULE DETAILS", panelWidth)

	var content string
	if m.selected == nil {
		hint := "Select a module to view details"
		if row := m.table.SelectedRow(); row != nil {
			hint = "Press Enter to fetch manifest for " + row[0]
		}
		content = styles.BaseStyle.Foreground(styles.Muted).Render(hint)
	} else {
		content = m.renderModuleDetails()
	}

	focusStyle := styles.PanelStyle.Width(panelWidth)
	if m.focus == FocusDetails {
		focusStyle = styles.PanelFocusedStyle.Width(panelWidth)
	}

	return focusStyle.Render(lipgloss.JoinVertical(lipgloss.Left, title, content))
}

func (m Model) renderModuleDetails() string {
	if m.selected == nil || m.selected.Manifest == nil {
		return styles.BaseStyle.Foreground(styles.Muted).
			Render("No manifest available")
	}

	manifest := m.selected.Manifest
	t := styles.BaseStyle.Foreground(styles.BorderDim)
	branch := t.Render("├── ")
	lastBranch := t.Render("└── ")
	pipe := t.Render("│   ")
	blank := "    "
	leaf := t.Render("├─ ")
	leafEnd := t.Render("└─ ")
	leafPipe := t.Render("│  ")

	var lines []string

	// Header: identity + badge
	typeBadge := styles.ModuleTypeBadge(manifest.Type).
		Render(manifest.Type)
	lines = append(lines,
		styles.BaseStyle.Foreground(styles.TextBright).Bold(true).
			Render(manifest.ID)+
			"  "+typeBadge+
			"  "+styles.BaseStyle.Foreground(styles.Muted).
			Render("v"+manifest.Version))

	// Description
	if manifest.Description != "" {
		desc := strings.TrimSpace(manifest.Description)
		if len(desc) > 56 {
			desc = desc[:53] + "..."
		}
		lines = append(lines, t.Render("│"))
		lines = append(lines,
			t.Render("│ ")+
				styles.BaseStyle.Foreground(styles.TextDim).Render(desc))
	}

	lines = append(lines, t.Render("│"))

	// Collect sections to render
	type section struct {
		render func(isLast bool) []string
	}
	var sects []section

	// Build section
	if manifest.Build != nil && manifest.Build.System != "" {
		sects = append(sects, section{
			render: func(isLast bool) []string {
				pfx, cp := branch, pipe
				if isLast {
					pfx, cp = lastBranch, blank
				}
				info := manifest.Build.System
				if len(manifest.Build.Platforms) > 0 {
					info += " → " + strings.Join(
						manifest.Build.Platforms, ", ")
				}
				return []string{
					pfx + sectionTitle("Build"),
					cp + styles.BaseStyle.Foreground(styles.TextDim).
						Render(info),
				}
			},
		})
	}

	// Runtime section
	sects = append(sects, section{
		render: func(isLast bool) []string {
			pfx, cp := branch, pipe
			if isLast {
				pfx, cp = lastBranch, blank
			}
			out := []string{pfx + sectionTitle("Runtime")}

			items := []struct{ k, v string }{
				{"Protocol", manifest.Runtime.Protocol},
				{"Timeout", manifest.Runtime.Timeout},
				{"Memory", manifest.Runtime.Memory},
			}
			var filtered []struct{ k, v string }
			for _, it := range items {
				if it.v != "" {
					filtered = append(filtered, it)
				}
			}
			for i, it := range filtered {
				lf := leaf
				if i == len(filtered)-1 {
					lf = leafEnd
				}
				label := styles.BaseStyle.Foreground(styles.Muted).
					Width(10).Render(it.k)
				out = append(out,
					cp+lf+label+
						styles.BaseStyle.Foreground(styles.Text).
							Render(it.v))
			}
			return out
		},
	})

	// Parameters section
	if manifest.Params != nil && len(manifest.Params.Properties) > 0 {
		sects = append(sects, section{
			render: func(isLast bool) []string {
				pfx, cp := branch, pipe
				if isLast {
					pfx, cp = lastBranch, blank
				}
				count := len(manifest.Params.Properties)
				out := []string{
					pfx + sectionTitle(
						fmt.Sprintf("Parameters (%d)", count)),
				}
				i := 0
				for name, prop := range manifest.Params.Properties {
					i++
					lf, lp := leaf, leafPipe
					if i == count {
						lf, lp = leafEnd, "   "
					}

					required := false
					for _, r := range manifest.Params.Required {
						if r == name {
							required = true
							break
						}
					}

					nm := styles.BaseStyle.Foreground(styles.Text).
						Render(name)
					tp := styles.BaseStyle.Foreground(styles.Muted).
						Render(" " + prop.Type)
					req := ""
					if required {
						req = styles.BaseStyle.
							Foreground(styles.Warning).Render(" ●")
					}
					def := ""
					if prop.Default != nil {
						def = styles.BaseStyle.
							Foreground(styles.Muted).
							Render(fmt.Sprintf(" = %v", prop.Default))
					}
					out = append(out, cp+lf+nm+tp+req+def)

					if prop.Description != "" {
						d := prop.Description
						if len(d) > 38 {
							d = d[:35] + "..."
						}
						out = append(out,
							cp+lp+styles.BaseStyle.
								Foreground(styles.Muted).Render(d))
					}
				}
				return out
			},
		})
	}

	// Findings — severity-grouped cards with colored lane borders
	if len(manifest.Findings) > 0 {
		sects = append(sects, section{
			render: func(isLast bool) []string {
				pfx, cp := branch, pipe
				if isLast {
					pfx, cp = lastBranch, blank
				}
				out := []string{
					pfx + sectionTitle(
						fmt.Sprintf("Findings (%d)",
							len(manifest.Findings))),
				}

				tiers := []string{
					"critical", "high", "medium", "low", "info",
				}
				grouped := map[string][]registry.ManifestFinding{}
				for _, f := range manifest.Findings {
					grouped[f.Severity] = append(
						grouped[f.Severity], f)
				}

				for _, tier := range tiers {
					findings := grouped[tier]
					if len(findings) == 0 {
						continue
					}
					sty := styles.SeverityStyle(tier)
					bar := sty.Render("▌")

					// Severity header
					out = append(out,
						cp+bar+" "+sty.Bold(true).
							Render(strings.ToUpper(tier)))

					for _, f := range findings {
						id := styles.BaseStyle.
							Foreground(styles.TextBright).
							Render(f.ID)
						out = append(out, cp+bar+"  "+id)

						if f.Description != "" {
							d := f.Description
							if len(d) > 38 {
								d = d[:35] + "..."
							}
							out = append(out,
								cp+bar+"  "+styles.BaseStyle.
									Foreground(styles.Muted).
									Render(d))
						}
					}
					out = append(out, cp)
				}
				return out
			},
		})
	}

	// Cache status
	if m.selected.LocalPath != "" {
		sects = append(sects, section{
			render: func(_ bool) []string {
				path := m.selected.LocalPath
				if len(path) > 44 {
					path = "…" + path[len(path)-43:]
				}
				return []string{
					lastBranch + styles.BaseStyle.
						Foreground(styles.Success).
						Render("✓ Cached"),
					blank + styles.BaseStyle.
						Foreground(styles.Muted).Render(path),
				}
			},
		})
	}

	// Render all sections
	for i, s := range sects {
		lines = append(lines, s.render(i == len(sects)-1)...)
	}

	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

// tryLoadCachedDetails loads manifest from disk cache for the selected module.
// If not cached, details panel shows a prompt to press Enter.
func (m *Model) tryLoadCachedDetails() {
	row := m.table.SelectedRow()
	if row == nil {
		return
	}
	moduleID := row[0]

	cfg := registry.DefaultConfig()
	cfg.SkipIndexVerify = true
	client, err := registry.NewClient(cfg)
	if err != nil {
		return
	}

	ctx := context.Background()
	resolved, err := client.Resolve(ctx, moduleID, "latest")
	if err != nil {
		return
	}

	// Only load manifest if already cached on disk — no network
	if err := client.LoadCachedManifest(resolved); err != nil {
		return
	}
	m.selected = resolved
}

func sectionTitle(title string) string {
	return styles.BaseStyle.Foreground(styles.Secondary).Bold(true).
		Render(title)
}

func renderField(label, value string) string {
	return styles.BaseStyle.Foreground(styles.Muted).Render(label+": ") +
		styles.BaseStyle.Foreground(styles.Text).Render(value)
}
