package components

import (
	"fmt"
	"strings"

	"bytemomo/kraken/internal/tui/styles"

	"github.com/charmbracelet/lipgloss"
)

// Tab represents a navigation tab
type Tab int

const (
	TabCampaign Tab = iota
	TabRegistry
	TabExecution
	TabResults
	TabAttackTree
)

var tabNames = []string{"Campaign", "Registry", "Execution", "Results", "Attack Tree"}

// Header renders the tab bar header
type Header struct {
	ActiveTab Tab
	Width     int
}

// NewHeader creates a new header component
func NewHeader() Header {
	return Header{
		ActiveTab: TabCampaign,
	}
}

// SetWidth sets the header width
func (h *Header) SetWidth(width int) {
	h.Width = width
}

// SetActiveTab sets the active tab
func (h *Header) SetActiveTab(tab Tab) {
	h.ActiveTab = tab
}

// NextTab moves to the next tab
func (h *Header) NextTab() {
	h.ActiveTab = (h.ActiveTab + 1) % Tab(len(tabNames))
}

// PrevTab moves to the previous tab
func (h *Header) PrevTab() {
	h.ActiveTab = (h.ActiveTab - 1 + Tab(len(tabNames))) % Tab(len(tabNames))
}

// View renders the header
func (h Header) View() string {
	sep := styles.BaseStyle.Foreground(styles.Muted).Render("│")
	var parts []string

	for i, name := range tabNames {
		if i > 0 {
			parts = append(parts, sep)
		}
		label := fmt.Sprintf("[%d] %s", i+1, name)
		if Tab(i) == h.ActiveTab {
			parts = append(parts, styles.TabActive.Render(label))
		} else {
			parts = append(parts, styles.TabInactive.Render(label))
		}
	}

	tabBar := lipgloss.JoinHorizontal(lipgloss.Top, parts...)

	title := styles.BaseStyle.
		Foreground(styles.Primary).
		Bold(true).
		Render("[ KRAKEN ]")

	tabWidth := lipgloss.Width(tabBar)
	titleWidth := lipgloss.Width(title)
	spacing := h.Width - tabWidth - titleWidth - 2
	if spacing < 0 {
		spacing = 0
	}

	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		tabBar,
		strings.Repeat(" ", spacing),
		title,
	)
}
