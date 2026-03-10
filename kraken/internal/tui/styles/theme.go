package styles

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// IsDark tracks the current theme.
var IsDark = true

var (
	// Backgrounds
	BgDark      lipgloss.Color
	BgPanel     lipgloss.Color
	BgHighlight lipgloss.Color
	BgSurface   lipgloss.Color

	// Borders
	Border      lipgloss.Color
	BorderDim   lipgloss.Color
	BorderFocus lipgloss.Color

	// Accents
	Primary   lipgloss.Color
	Secondary lipgloss.Color

	// Semantic
	Success lipgloss.Color
	Warning lipgloss.Color
	Error   lipgloss.Color
	Muted   lipgloss.Color

	// Text
	TextBright lipgloss.Color
	Text       lipgloss.Color
	TextDim    lipgloss.Color

	// Severity colors
	SeverityCritical lipgloss.Color
	SeverityHigh     lipgloss.Color
	SeverityMedium   lipgloss.Color
	SeverityLow      lipgloss.Color
	SeverityInfo     lipgloss.Color

	// Composed styles (rebuilt on theme change)
	BaseStyle          lipgloss.Style
	TabActive          lipgloss.Style
	TabInactive        lipgloss.Style
	PanelStyle         lipgloss.Style
	PanelFocusedStyle  lipgloss.Style
	PanelTitleStyle    lipgloss.Style
	StatusBarStyle     lipgloss.Style
	StatusKeyStyle     lipgloss.Style
	HelpStyle          lipgloss.Style
	HelpKeyStyle       lipgloss.Style
	TableHeaderStyle   lipgloss.Style
	TableSelectedStyle lipgloss.Style
	TableRowStyle      lipgloss.Style
	TableRowAltStyle   lipgloss.Style
	CriticalStyle      lipgloss.Style
	HighStyle          lipgloss.Style
	MediumStyle        lipgloss.Style
	LowStyle           lipgloss.Style
	InfoStyle          lipgloss.Style
	ProgressFilled     lipgloss.Style
	ProgressEmpty      lipgloss.Style
	BadgeNative        lipgloss.Style
	BadgeLib           lipgloss.Style
	BadgeContainer     lipgloss.Style
	BadgeGrpc          lipgloss.Style
	BadgeCached        lipgloss.Style
	BadgeNotCached     lipgloss.Style
	BadgeUpdate        lipgloss.Style
)

func init() {
	applyDark()
}

// ToggleTheme switches between dark and light themes.
func ToggleTheme() {
	if IsDark {
		applyLight()
	} else {
		applyDark()
	}
}

func applyDark() {
	IsDark = true

	BgDark = lipgloss.Color("#0D1117")
	BgPanel = lipgloss.Color("#161B22")
	BgHighlight = lipgloss.Color("#1C2333")
	BgSurface = lipgloss.Color("#21262D")

	Border = lipgloss.Color("#30363D")
	BorderDim = lipgloss.Color("#21262D")
	BorderFocus = lipgloss.Color("#00D4AA")

	Primary = lipgloss.Color("#00D4AA")
	Secondary = lipgloss.Color("#00B4D8")

	Success = lipgloss.Color("#3FB950")
	Warning = lipgloss.Color("#D29922")
	Error = lipgloss.Color("#F85149")
	Muted = lipgloss.Color("#484F58")

	TextBright = lipgloss.Color("#E6EDF3")
	Text = lipgloss.Color("#C9D1D9")
	TextDim = lipgloss.Color("#8B949E")

	SeverityCritical = lipgloss.Color("#FF3860")
	SeverityHigh = lipgloss.Color("#FF6B35")
	SeverityMedium = lipgloss.Color("#FFD166")
	SeverityLow = lipgloss.Color("#06D6A0")
	SeverityInfo = lipgloss.Color("#4A90D9")

	rebuildStyles()
}

func applyLight() {
	IsDark = false

	BgDark = lipgloss.Color("#FFFFFF")
	BgPanel = lipgloss.Color("#F6F8FA")
	BgHighlight = lipgloss.Color("#E8ECF0")
	BgSurface = lipgloss.Color("#DFE3E8")

	Border = lipgloss.Color("#D0D7DE")
	BorderDim = lipgloss.Color("#DFE3E8")
	BorderFocus = lipgloss.Color("#0A8F6C")

	Primary = lipgloss.Color("#0A8F6C")
	Secondary = lipgloss.Color("#0078A8")

	Success = lipgloss.Color("#1A7F37")
	Warning = lipgloss.Color("#9A6700")
	Error = lipgloss.Color("#CF222E")
	Muted = lipgloss.Color("#8C959F")

	TextBright = lipgloss.Color("#1F2328")
	Text = lipgloss.Color("#31363B")
	TextDim = lipgloss.Color("#656D76")

	SeverityCritical = lipgloss.Color("#CF222E")
	SeverityHigh = lipgloss.Color("#BC4C00")
	SeverityMedium = lipgloss.Color("#9A6700")
	SeverityLow = lipgloss.Color("#116329")
	SeverityInfo = lipgloss.Color("#0550AE")

	rebuildStyles()
}

func rebuildStyles() {
	BaseStyle = lipgloss.NewStyle().
		Foreground(Text)

	TabActive = lipgloss.NewStyle().
		Foreground(BgDark).
		Background(Primary).
		Padding(0, 2).
		Bold(true)

	TabInactive = lipgloss.NewStyle().
		Foreground(Muted).
		Padding(0, 2)

	PanelStyle = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(BorderDim).
		Padding(0, 1)

	PanelFocusedStyle = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(BorderFocus).
		Padding(0, 1)

	PanelTitleStyle = lipgloss.NewStyle().
		Foreground(Primary).
		Bold(true)

	StatusBarStyle = lipgloss.NewStyle().
		Foreground(TextDim).
		Background(BgPanel).
		BorderTop(true).
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(Border).
		Padding(0, 1)

	StatusKeyStyle = lipgloss.NewStyle().
		Foreground(Primary).
		Bold(true)

	HelpStyle = lipgloss.NewStyle().
		Foreground(Muted)

	HelpKeyStyle = lipgloss.NewStyle().
		Foreground(Primary)

	TableHeaderStyle = lipgloss.NewStyle().
		Foreground(Secondary).
		Background(BgSurface).
		Bold(true)

	TableSelectedStyle = lipgloss.NewStyle().
		Background(BgHighlight).
		Foreground(TextBright).
		Bold(true)

	TableRowStyle = lipgloss.NewStyle().
		Foreground(Text)

	TableRowAltStyle = lipgloss.NewStyle().
		Foreground(Text).
		Background(BgSurface)

	CriticalStyle = lipgloss.NewStyle().
		Foreground(SeverityCritical).
		Bold(true)

	HighStyle = lipgloss.NewStyle().
		Foreground(SeverityHigh).
		Bold(true)

	MediumStyle = lipgloss.NewStyle().
		Foreground(SeverityMedium)

	LowStyle = lipgloss.NewStyle().
		Foreground(SeverityLow)

	InfoStyle = lipgloss.NewStyle().
		Foreground(SeverityInfo)

	ProgressFilled = lipgloss.NewStyle().
		Foreground(Primary)

	ProgressEmpty = lipgloss.NewStyle().
		Foreground(BorderDim)

	BadgeNative = lipgloss.NewStyle().
		Background(badgeBg("#0D3D2A", "#D3F5E8")).
		Foreground(Primary).
		Padding(0, 1)

	BadgeLib = lipgloss.NewStyle().
		Background(badgeBg("#0D2B45", "#D3E8F5")).
		Foreground(Secondary).
		Padding(0, 1)

	BadgeContainer = lipgloss.NewStyle().
		Background(badgeBg("#3D1A0D", "#F5E0D3")).
		Foreground(Warning).
		Padding(0, 1)

	BadgeGrpc = lipgloss.NewStyle().
		Background(badgeBg("#2A0D3D", "#E8D3F5")).
		Foreground(TextDim).
		Padding(0, 1)

	BadgeCached = lipgloss.NewStyle().
		Background(badgeBg("#1A3D2A", "#D3F5E0")).
		Foreground(Success).
		Padding(0, 1)

	BadgeNotCached = lipgloss.NewStyle().
		Background(BgSurface).
		Foreground(TextDim).
		Padding(0, 1)

	BadgeUpdate = lipgloss.NewStyle().
		Background(badgeBg("#3D2D0D", "#F5ECD3")).
		Foreground(Warning).
		Bold(true).
		Padding(0, 1)
}

func badgeBg(dark, light string) lipgloss.Color {
	if IsDark {
		return lipgloss.Color(dark)
	}
	return lipgloss.Color(light)
}

// PanelTitle renders a styled section title with horizontal rule fill.
func PanelTitle(title string, width int) string {
	prefix := "─ " + title + " "
	remaining := width - lipgloss.Width(prefix)
	if remaining < 0 {
		remaining = 0
	}
	return BaseStyle.Foreground(Primary).Bold(true).
		Render(prefix + strings.Repeat("─", remaining))
}

// SeverityStyle returns the appropriate style for a severity level.
func SeverityStyle(severity string) lipgloss.Style {
	switch severity {
	case "critical":
		return CriticalStyle
	case "high":
		return HighStyle
	case "medium":
		return MediumStyle
	case "low":
		return LowStyle
	default:
		return InfoStyle
	}
}

// ModuleTypeBadge returns the appropriate badge style for a module type.
func ModuleTypeBadge(moduleType string) lipgloss.Style {
	switch moduleType {
	case "native":
		return BadgeNative
	case "lib", "abi":
		return BadgeLib
	case "container":
		return BadgeContainer
	case "grpc":
		return BadgeGrpc
	default:
		return BadgeLib
	}
}
