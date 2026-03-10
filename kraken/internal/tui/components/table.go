package components

import (
	"strings"

	"bytemomo/kraken/internal/tui/styles"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// Column defines a table column
type Column struct {
	Title string
	Width int
}

// Row represents a table row
type Row []string

// CellStyleFunc returns a style for a specific cell.
// rowIdx is the data index (not screen index).
// If nil, default styles are used.
type CellStyleFunc func(rowIdx, colIdx int, value string) lipgloss.Style

// Table renders a scrollable table
type Table struct {
	Columns       []Column
	Rows          []Row
	Selected      int
	Offset        int
	Height        int
	Width         int
	Focused       bool
	CellStyleFunc CellStyleFunc
}

// NewTable creates a new table
func NewTable(columns []Column) Table {
	return Table{
		Columns:  columns,
		Rows:     []Row{},
		Selected: 0,
		Offset:   0,
		Height:   10,
		Focused:  true,
	}
}

// SetRows sets the table rows
func (t *Table) SetRows(rows []Row) {
	t.Rows = rows
	if t.Selected >= len(rows) {
		t.Selected = len(rows) - 1
	}
	if t.Selected < 0 {
		t.Selected = 0
	}
}

// SetSize sets the table dimensions
func (t *Table) SetSize(width, height int) {
	t.Width = width
	t.Height = height
}

// MoveUp moves selection up
func (t *Table) MoveUp() {
	if t.Selected > 0 {
		t.Selected--
		if t.Selected < t.Offset {
			t.Offset = t.Selected
		}
	}
}

// MoveDown moves selection down
func (t *Table) MoveDown() {
	if t.Selected < len(t.Rows)-1 {
		t.Selected++
		visibleRows := t.Height - 2 // header + border
		if t.Selected >= t.Offset+visibleRows {
			t.Offset = t.Selected - visibleRows + 1
		}
	}
}

// SelectedRow returns the currently selected row
func (t *Table) SelectedRow() Row {
	if t.Selected >= 0 && t.Selected < len(t.Rows) {
		return t.Rows[t.Selected]
	}
	return nil
}

// View renders the table
func (t Table) View() string {
	if len(t.Columns) == 0 {
		return ""
	}

	// Calculate column widths
	totalWidth := 0
	for _, col := range t.Columns {
		totalWidth += col.Width
	}

	// Render header
	var headerCells []string
	for _, col := range t.Columns {
		cell := truncateOrPad(col.Title, col.Width)
		headerCells = append(headerCells, styles.TableHeaderStyle.Width(col.Width).Render(cell))
	}
	header := lipgloss.JoinHorizontal(lipgloss.Top, headerCells...)

	// Header separator
	separator := styles.BaseStyle.Foreground(styles.BorderDim).
		Render(strings.Repeat("─", totalWidth))

	// Render rows
	visibleRows := t.Height - 3 // header + separator + border
	if visibleRows < 1 {
		visibleRows = 1
	}

	var rowStrings []string
	rowStrings = append(rowStrings, header, separator)

	endIdx := t.Offset + visibleRows
	if endIdx > len(t.Rows) {
		endIdx = len(t.Rows)
	}

	for i := t.Offset; i < endIdx; i++ {
		row := t.Rows[i]
		var cells []string
		for j, col := range t.Columns {
			cellContent := ""
			if j < len(row) {
				cellContent = row[j]
			}
			cell := truncateOrPad(cellContent, col.Width)

			style := styles.TableRowStyle
			if (i-t.Offset)%2 != 0 {
				style = styles.TableRowAltStyle
			}
			if t.CellStyleFunc != nil {
				style = t.CellStyleFunc(i, j, cellContent)
			}
			if i == t.Selected && t.Focused {
				style = styles.TableSelectedStyle
			}
			cells = append(cells, style.Width(col.Width).Render(cell))
		}
		rowStrings = append(rowStrings, lipgloss.JoinHorizontal(lipgloss.Top, cells...))
	}

	// Pad with empty rows if needed
	for len(rowStrings) < visibleRows+2 { // +2 for header + separator
		var cells []string
		for _, col := range t.Columns {
			cells = append(cells, styles.TableRowStyle.Width(col.Width).Render(strings.Repeat(" ", col.Width)))
		}
		rowStrings = append(rowStrings, lipgloss.JoinHorizontal(lipgloss.Top, cells...))
	}

	return lipgloss.JoinVertical(lipgloss.Left, rowStrings...)
}

func truncateOrPad(s string, width int) string {
	visible := lipgloss.Width(s)
	if visible > width {
		if width > 3 {
			return ansi.Truncate(s, width-3, "...")
		}
		return ansi.Truncate(s, width, "")
	}
	return s + strings.Repeat(" ", width-visible)
}
