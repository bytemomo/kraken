package components

import (
	"fmt"
	"strings"
	"time"

	"bytemomo/kraken/internal/tui/styles"

	"github.com/charmbracelet/lipgloss"
)

// LogLevel represents log severity
type LogLevel string

const (
	LogDebug LogLevel = "DEBUG"
	LogInfo  LogLevel = "INFO"
	LogWarn  LogLevel = "WARN"
	LogError LogLevel = "ERROR"
)

// LogMessage represents a single log entry
type LogMessage struct {
	Time    time.Time
	Level   LogLevel
	Message string
}

// LogView renders a scrollable log viewer
type LogView struct {
	Messages   []LogMessage
	Offset     int
	Height     int
	Width      int
	AutoScroll bool
	MaxLines   int
}

// NewLogView creates a new log viewer
func NewLogView(height int) LogView {
	return LogView{
		Messages:   []LogMessage{},
		Height:     height,
		AutoScroll: true,
		MaxLines:   1000,
	}
}

// SetSize sets the log view dimensions
func (l *LogView) SetSize(width, height int) {
	l.Width = width
	l.Height = height
}

// AddMessage adds a new log message
func (l *LogView) AddMessage(level LogLevel, message string) {
	msg := LogMessage{
		Time:    time.Now(),
		Level:   level,
		Message: message,
	}
	l.Messages = append(l.Messages, msg)

	// Trim old messages
	if len(l.Messages) > l.MaxLines {
		l.Messages = l.Messages[len(l.Messages)-l.MaxLines:]
	}

	// Auto-scroll to bottom
	if l.AutoScroll {
		l.ScrollToBottom()
	}
}

// AddInfo adds an info level message
func (l *LogView) AddInfo(message string) {
	l.AddMessage(LogInfo, message)
}

// AddWarn adds a warning level message
func (l *LogView) AddWarn(message string) {
	l.AddMessage(LogWarn, message)
}

// AddError adds an error level message
func (l *LogView) AddError(message string) {
	l.AddMessage(LogError, message)
}

// ScrollUp scrolls up one line
func (l *LogView) ScrollUp() {
	if l.Offset > 0 {
		l.Offset--
		l.AutoScroll = false
	}
}

// ScrollDown scrolls down one line
func (l *LogView) ScrollDown() {
	maxOffset := len(l.Messages) - l.Height
	if maxOffset < 0 {
		maxOffset = 0
	}
	if l.Offset < maxOffset {
		l.Offset++
	}
	if l.Offset >= maxOffset {
		l.AutoScroll = true
	}
}

// ScrollToBottom scrolls to the bottom
func (l *LogView) ScrollToBottom() {
	l.Offset = len(l.Messages) - l.Height
	if l.Offset < 0 {
		l.Offset = 0
	}
	l.AutoScroll = true
}

// ScrollBy scrolls by n lines (positive = down, negative = up)
func (l *LogView) ScrollBy(n int) {
	if n > 0 {
		for i := 0; i < n; i++ {
			l.ScrollDown()
		}
	} else {
		for i := 0; i < -n; i++ {
			l.ScrollUp()
		}
	}
}

// PageUp scrolls up one page
func (l *LogView) PageUp() {
	l.Offset -= l.Height
	if l.Offset < 0 {
		l.Offset = 0
	}
	l.AutoScroll = false
}

// PageDown scrolls down one page
func (l *LogView) PageDown() {
	maxOffset := len(l.Messages) - l.Height
	if maxOffset < 0 {
		maxOffset = 0
	}
	l.Offset += l.Height
	if l.Offset > maxOffset {
		l.Offset = maxOffset
	}
	if l.Offset >= maxOffset {
		l.AutoScroll = true
	}
}

// Clear clears all messages
func (l *LogView) Clear() {
	l.Messages = []LogMessage{}
	l.Offset = 0
}

// View renders the log viewer
func (l LogView) View() string {
	if l.Height <= 0 {
		return ""
	}

	var lines []string

	endIdx := l.Offset + l.Height
	if endIdx > len(l.Messages) {
		endIdx = len(l.Messages)
	}

	for i := l.Offset; i < endIdx; i++ {
		msg := l.Messages[i]
		line := l.formatMessage(msg)
		if l.Width > 0 && len(line) > l.Width {
			line = line[:l.Width-3] + "..."
		}
		lines = append(lines, line)
	}

	// Pad with empty lines if needed
	for len(lines) < l.Height {
		lines = append(lines, "")
	}

	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

func (l LogView) formatMessage(msg LogMessage) string {
	timestamp := msg.Time.Format("15:04:05")
	timestampStyle := styles.BaseStyle.Foreground(styles.Muted)

	levelStyle := styles.BaseStyle
	switch msg.Level {
	case LogDebug:
		levelStyle = levelStyle.Foreground(styles.Muted)
	case LogInfo:
		levelStyle = levelStyle.Foreground(styles.Secondary)
	case LogWarn:
		levelStyle = levelStyle.Foreground(styles.Warning)
	case LogError:
		levelStyle = levelStyle.Foreground(styles.Error)
	}

	msgStyle := styles.BaseStyle.Foreground(styles.Text)
	if msg.Level == LogError {
		msgStyle = styles.BaseStyle.Foreground(styles.TextBright)
	}

	return fmt.Sprintf("%s  %s  %s",
		timestampStyle.Render(timestamp),
		levelStyle.Width(5).Render(string(msg.Level)),
		msgStyle.Render(msg.Message),
	)
}

// Scrollbar returns a visual scrollbar indicator
func (l LogView) Scrollbar() string {
	if len(l.Messages) <= l.Height {
		return ""
	}

	totalLines := len(l.Messages)
	viewportRatio := float64(l.Height) / float64(totalLines)
	scrollbarHeight := int(float64(l.Height) * viewportRatio)
	if scrollbarHeight < 1 {
		scrollbarHeight = 1
	}

	scrollRatio := float64(l.Offset) / float64(totalLines-l.Height)
	scrollbarPos := int(float64(l.Height-scrollbarHeight) * scrollRatio)

	var sb strings.Builder
	for i := 0; i < l.Height; i++ {
		if i >= scrollbarPos && i < scrollbarPos+scrollbarHeight {
			sb.WriteString(styles.BaseStyle.Foreground(styles.Primary).Render("▋"))
		} else {
			sb.WriteString(styles.BaseStyle.Foreground(styles.BorderDim).Render("│"))
		}
		if i < l.Height-1 {
			sb.WriteString("\n")
		}
	}
	return sb.String()
}
