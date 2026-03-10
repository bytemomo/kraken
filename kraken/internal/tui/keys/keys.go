package keys

import "github.com/charmbracelet/bubbles/key"

// KeyMap defines all key bindings for the TUI
type KeyMap struct {
	// Navigation
	Tab       key.Binding
	ShiftTab  key.Binding
	Up        key.Binding
	Down      key.Binding
	Left      key.Binding
	Right     key.Binding
	Enter     key.Binding
	Back      key.Binding
	PageUp    key.Binding
	PageDown  key.Binding
	Home      key.Binding
	End       key.Binding

	// Actions
	Start    key.Binding
	Stop     key.Binding
	Refresh  key.Binding
	Download key.Binding
	Open     key.Binding
	Export   key.Binding

	// Global
	Help key.Binding
	Quit key.Binding
}

// DefaultKeyMap returns the default key bindings
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Tab: key.NewBinding(
			key.WithKeys("tab"),
			key.WithHelp("tab", "next tab"),
		),
		ShiftTab: key.NewBinding(
			key.WithKeys("shift+tab"),
			key.WithHelp("shift+tab", "prev tab"),
		),
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/k", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("↓/j", "down"),
		),
		Left: key.NewBinding(
			key.WithKeys("left", "h"),
			key.WithHelp("←/h", "left"),
		),
		Right: key.NewBinding(
			key.WithKeys("right", "l"),
			key.WithHelp("→/l", "right"),
		),
		Enter: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "select"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc", "backspace"),
			key.WithHelp("esc", "back"),
		),
		PageUp: key.NewBinding(
			key.WithKeys("pgup"),
			key.WithHelp("pgup", "page up"),
		),
		PageDown: key.NewBinding(
			key.WithKeys("pgdown"),
			key.WithHelp("pgdn", "page down"),
		),
		Home: key.NewBinding(
			key.WithKeys("home"),
			key.WithHelp("home", "go to start"),
		),
		End: key.NewBinding(
			key.WithKeys("end"),
			key.WithHelp("end", "go to end"),
		),
		Start: key.NewBinding(
			key.WithKeys("s"),
			key.WithHelp("s", "start"),
		),
		Stop: key.NewBinding(
			key.WithKeys("x"),
			key.WithHelp("x", "stop"),
		),
		Refresh: key.NewBinding(
			key.WithKeys("r"),
			key.WithHelp("r", "refresh"),
		),
		Download: key.NewBinding(
			key.WithKeys("d"),
			key.WithHelp("d", "download"),
		),
		Open: key.NewBinding(
			key.WithKeys("o"),
			key.WithHelp("o", "open"),
		),
		Export: key.NewBinding(
			key.WithKeys("e"),
			key.WithHelp("e", "export"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "help"),
		),
		Quit: key.NewBinding(
			key.WithKeys("ctrl+c", "q"),
			key.WithHelp("q", "quit"),
		),
	}
}

// ShortHelp returns a short help string for the current context
func (k KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Tab, k.Enter, k.Back, k.Help, k.Quit}
}

// FullHelp returns the full help for all key bindings
func (k KeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Left, k.Right},
		{k.Tab, k.ShiftTab, k.Enter, k.Back},
		{k.Start, k.Stop, k.Refresh, k.Download},
		{k.Help, k.Quit},
	}
}
