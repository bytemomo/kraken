package attacktree

import (
	"fmt"
	"strings"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/tui/keys"
	"bytemomo/kraken/internal/tui/styles"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Model is the attack tree view model.
type Model struct {
	width  int
	height int
	keys   keys.KeyMap

	trees       []domain.AttackTreeResult
	selectedIdx int
	scrollX     int
	scrollY     int
}

// New creates a new attack tree view.
func New(keyMap keys.KeyMap) Model {
	return Model{keys: keyMap}
}

// Init initializes the model.
func (m Model) Init() tea.Cmd { return nil }

// SetSize sets the view dimensions.
func (m *Model) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// SetTrees sets the attack tree results to display.
func (m *Model) SetTrees(trees []domain.AttackTreeResult) {
	m.trees = trees
	m.selectedIdx = 0
	m.scrollX = 0
	m.scrollY = 0
}

// Update handles messages.
func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Up):
			if m.scrollY > 0 {
				m.scrollY--
			}
		case key.Matches(msg, m.keys.Down):
			m.scrollY++
		case key.Matches(msg, m.keys.Left):
			if m.scrollX > 0 {
				m.scrollX--
			}
		case key.Matches(msg, m.keys.Right):
			m.scrollX++
		case key.Matches(msg, m.keys.PageUp):
			m.scrollY -= 10
			if m.scrollY < 0 {
				m.scrollY = 0
			}
		case key.Matches(msg, m.keys.PageDown):
			m.scrollY += 10
		case msg.String() == "[", msg.String() == "{":
			if m.selectedIdx > 0 {
				m.selectedIdx--
				m.scrollX = 0
				m.scrollY = 0
			}
		case msg.String() == "]", msg.String() == "}":
			if m.selectedIdx < len(m.trees)-1 {
				m.selectedIdx++
				m.scrollX = 0
				m.scrollY = 0
			}
		}
	}
	return m, nil
}

// View renders the view.
func (m Model) View() string {
	header := m.renderHeader()

	if len(m.trees) == 0 {
		hint := styles.BaseStyle.Foreground(styles.Muted).
			Render("No attack trees. Run a campaign with attack_trees_def_path to see results.")
		return lipgloss.JoinVertical(lipgloss.Left, header, "", hint)
	}

	at := m.trees[m.selectedIdx]
	if at.Tree == nil {
		return lipgloss.JoinVertical(lipgloss.Left, header, "",
			styles.BaseStyle.Foreground(styles.Muted).Render("Empty tree"))
	}

	// Render the 2D tree, centered in the available width
	headerH := lipgloss.Height(header) + 1 // +1 for help line
	viewH := m.height - headerH - 1
	canvas := renderTree(at.Tree, m.width, viewH)

	// Apply scroll
	lines := strings.Split(canvas, "\n")
	if m.scrollY >= len(lines) {
		m.scrollY = len(lines) - 1
	}
	if m.scrollY < 0 {
		m.scrollY = 0
	}
	if m.scrollY < len(lines) {
		lines = lines[m.scrollY:]
	}

	if viewH > 0 && len(lines) > viewH {
		lines = lines[:viewH]
	}

	// Horizontal scroll
	if m.scrollX > 0 {
		for i, l := range lines {
			runes := []rune(l)
			if m.scrollX < len(runes) {
				lines[i] = string(runes[m.scrollX:])
			} else {
				lines[i] = ""
			}
		}
	}

	// Pad content to fill viewport so help bar stays at the bottom
	for len(lines) < viewH {
		lines = append(lines, "")
	}

	content := strings.Join(lines, "\n")
	help := styles.HelpStyle.Render(
		"↑↓←→: scroll  PgUp/PgDn: fast scroll  [/]: prev/next tree  F1: theme")

	return lipgloss.JoinVertical(lipgloss.Left, header, content, help)
}

func (m Model) renderHeader() string {
	title := styles.PanelTitle("ATTACK TREE", m.width/2)

	if len(m.trees) == 0 {
		return title
	}

	at := m.trees[m.selectedIdx]

	// Tree selector
	selector := styles.BaseStyle.Foreground(styles.Muted).Render(
		fmt.Sprintf("(%d/%d)", m.selectedIdx+1, len(m.trees)))

	// Tree name
	name := ""
	if at.Tree != nil {
		name = styles.BaseStyle.Foreground(styles.TextBright).Bold(true).
			Render(at.Tree.Name)
	}

	// Target
	target := ""
	if at.Target != nil {
		target = styles.BaseStyle.Foreground(styles.TextDim).
			Render(" @ " + at.Target.String())
	}

	// Overall status
	status := styles.BaseStyle.Foreground(styles.Muted).Render("✗ NOT ACHIEVED")
	if at.Tree != nil && at.Tree.Success {
		status = styles.BaseStyle.Foreground(styles.Error).Bold(true).
			Render("✓ ACHIEVED")
	}

	info := lipgloss.JoinHorizontal(lipgloss.Top,
		selector, "  ", name, target, "  ", status)

	return lipgloss.JoinVertical(lipgloss.Left, title, info)
}

// layout computes the 2D position of every node.
type layout struct {
	nodes map[*domain.AttackNode]*nodeLayout
}

type nodeLayout struct {
	node          *domain.AttackNode
	x, y          int // top-left of box on canvas
	w, h          int // box dimensions
	subtreeWidth  int // total width of subtree rooted here
	centerX       int // center X of this node's box (absolute)
}

const (
	boxPadX   = 1 // horizontal padding inside box
	boxMinW   = 16
	nodeGapX  = 3  // horizontal gap between sibling subtrees
	levelGapY = 3  // vertical gap between levels (for connectors)
)

// RenderTreeTest is exported for testing only.
var RenderTreeTest = func(root *domain.AttackNode) string {
	return renderTree(root, 120, 40)
}

func renderTree(root *domain.AttackNode, viewportW, viewportH int) string {
	lo := &layout{nodes: make(map[*domain.AttackNode]*nodeLayout)}

	// Phase 1: compute box sizes and subtree widths (bottom-up)
	computeSizes(lo, root)

	// Phase 2: assign X,Y positions (top-down)
	assignPositions(lo, root, 0, 0)

	// Phase 3: determine tree extent and center it
	maxX, maxY := 0, 0
	for _, nl := range lo.nodes {
		if nl.x+nl.w > maxX {
			maxX = nl.x + nl.w
		}
		if nl.y+nl.h > maxY {
			maxY = nl.y + nl.h
		}
	}

	// Center horizontally
	treeW := maxX
	offsetX := 0
	if viewportW > treeW {
		offsetX = (viewportW - treeW) / 2
	}

	// Center vertically
	treeH := maxY + levelGapY
	offsetY := 0
	if viewportH > treeH {
		offsetY = (viewportH - treeH) / 2
	}

	if offsetX > 0 || offsetY > 0 {
		for _, nl := range lo.nodes {
			nl.x += offsetX
			nl.centerX += offsetX
			nl.y += offsetY
		}
	}

	canvasW := treeW + offsetX + 2
	if canvasW < viewportW {
		canvasW = viewportW
	}
	canvasH := treeH + offsetY

	// Phase 4: paint onto grid
	grid := newGrid(canvasW, canvasH)

	// Draw connectors first (so boxes paint over them)
	drawConnectors(grid, lo, root)

	// Draw boxes
	for _, nl := range lo.nodes {
		drawNodeBox(grid, nl)
	}

	return grid.String()
}

func computeSizes(lo *layout, node *domain.AttackNode) {
	nl := &nodeLayout{node: node}
	lo.nodes[node] = nl

	// Box content lines
	lines := boxLines(node)
	maxLine := 0
	for _, l := range lines {
		if len(l) > maxLine {
			maxLine = len(l)
		}
	}
	nl.w = maxLine + (boxPadX+1)*2 // +1 for border
	if nl.w < boxMinW {
		nl.w = boxMinW
	}
	nl.h = len(lines) + 2 // +2 for top/bottom border

	if len(node.Children) == 0 {
		nl.subtreeWidth = nl.w
		return
	}

	totalChildWidth := 0
	for i, child := range node.Children {
		computeSizes(lo, child)
		childNL := lo.nodes[child]
		totalChildWidth += childNL.subtreeWidth
		if i > 0 {
			totalChildWidth += nodeGapX
		}
	}

	if totalChildWidth > nl.w {
		nl.subtreeWidth = totalChildWidth
	} else {
		nl.subtreeWidth = nl.w
	}
}

func assignPositions(
	lo *layout, node *domain.AttackNode, x, y int,
) {
	nl := lo.nodes[node]
	// Center this node's box within its subtree width
	nl.x = x + (nl.subtreeWidth-nl.w)/2
	nl.y = y
	nl.centerX = nl.x + nl.w/2

	if len(node.Children) == 0 {
		return
	}

	childY := y + nl.h + levelGapY
	childX := x
	for i, child := range node.Children {
		childNL := lo.nodes[child]
		assignPositions(lo, child, childX, childY)
		childX += childNL.subtreeWidth + nodeGapX
		_ = i
	}
}

func boxLines(node *domain.AttackNode) []string {
	var lines []string

	// Status + gate type
	status := "✗"
	if node.Success {
		status = "✓"
	}

	switch node.Type {
	case domain.AND:
		lines = append(lines, status+" AND")
	case domain.OR:
		lines = append(lines, status+" OR")
	case domain.LEAF:
		lines = append(lines, status+" LEAF")
	}

	// Node name (wrap if long)
	name := node.Name
	if len(name) > 30 {
		// Wrap at ~30 chars
		lines = append(lines, wrapLines(name, 30)...)
	} else {
		lines = append(lines, name)
	}

	// Finding IDs for leaf nodes
	if node.Type == domain.LEAF && len(node.FindingIDs) > 0 {
		ids := strings.Join(node.FindingIDs, ", ")
		if len(ids) > 30 {
			ids = ids[:27] + "..."
		}
		lines = append(lines, "-> "+ids)
	}

	return lines
}

func wrapLines(s string, width int) []string {
	words := strings.Fields(s)
	var lines []string
	cur := ""
	for _, w := range words {
		if cur == "" {
			cur = w
		} else if len(cur)+1+len(w) <= width {
			cur += " " + w
		} else {
			lines = append(lines, cur)
			cur = w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// grid is a 2D character canvas with styling.
type grid struct {
	cells [][]cell
	w, h  int
}

type cell struct {
	ch    rune
	style lipgloss.Style
}

func dimStyle() lipgloss.Style     { return styles.BaseStyle.Foreground(styles.BorderDim) }
func connStyle() lipgloss.Style    { return styles.BaseStyle.Foreground(styles.Muted) }
func successStyle() lipgloss.Style { return styles.BaseStyle.Foreground(styles.Success) }
func failStyle() lipgloss.Style    { return styles.BaseStyle.Foreground(styles.Error) }
func gateORStyle() lipgloss.Style  { return styles.BaseStyle.Foreground(styles.Secondary).Bold(true) }
func gateANDStyle() lipgloss.Style { return styles.BaseStyle.Foreground(styles.Warning).Bold(true) }
func leafStyle() lipgloss.Style    { return styles.BaseStyle.Foreground(styles.Primary).Bold(true) }
func nameStyle() lipgloss.Style    { return styles.BaseStyle.Foreground(styles.Text) }
func idStyle() lipgloss.Style      { return styles.BaseStyle.Foreground(styles.Muted) }
func defaultStyle() lipgloss.Style { return styles.BaseStyle.Foreground(styles.Text) }

func newGrid(w, h int) *grid {
	cells := make([][]cell, h)
	for y := range cells {
		cells[y] = make([]cell, w)
		for x := range cells[y] {
			cells[y][x] = cell{ch: ' ', style: defaultStyle()}
		}
	}
	return &grid{cells: cells, w: w, h: h}
}

func (g *grid) set(x, y int, ch rune, sty lipgloss.Style) {
	if x >= 0 && x < g.w && y >= 0 && y < g.h {
		g.cells[y][x] = cell{ch: ch, style: sty}
	}
}

func (g *grid) putStr(x, y int, s string, sty lipgloss.Style) {
	for i, ch := range s {
		g.set(x+i, y, ch, sty)
	}
}

func (g *grid) String() string {
	var sb strings.Builder
	for y, row := range g.cells {
		if y > 0 {
			sb.WriteRune('\n')
		}
		// Find last non-space to avoid trailing whitespace
		last := len(row) - 1
		for last >= 0 && row[last].ch == ' ' {
			last--
		}
		for x := 0; x <= last; x++ {
			c := row[x]
			sb.WriteString(c.style.Render(string(c.ch)))
		}
	}
	return sb.String()
}

func drawNodeBox(g *grid, nl *nodeLayout) {
	node := nl.node
	x, y, w, h := nl.x, nl.y, nl.w, nl.h

	// Pick border color based on state
	borderSty := dimStyle()
	if node.Success {
		borderSty = successStyle()
	} else if node.Type == domain.LEAF {
		borderSty = failStyle()
	}

	// Top border
	g.set(x, y, '╭', borderSty)
	for i := 1; i < w-1; i++ {
		g.set(x+i, y, '─', borderSty)
	}
	g.set(x+w-1, y, '╮', borderSty)

	// Bottom border
	g.set(x, y+h-1, '╰', borderSty)
	for i := 1; i < w-1; i++ {
		g.set(x+i, y+h-1, '─', borderSty)
	}
	g.set(x+w-1, y+h-1, '╯', borderSty)

	// Side borders
	for row := 1; row < h-1; row++ {
		g.set(x, y+row, '│', borderSty)
		g.set(x+w-1, y+row, '│', borderSty)
	}

	// Content
	lines := boxLines(node)
	for i, line := range lines {
		row := y + 1 + i
		if row >= y+h-1 {
			break
		}

		// Center content in box
		padLeft := (w - 2 - len(line)) / 2
		if padLeft < 1 {
			padLeft = 1
		}

		// Pick style based on line type
		var sty lipgloss.Style
		if i == 0 {
			// Status + gate line
			if node.Success {
				sty = successStyle()
			} else {
				sty = failStyle()
			}
			// Render status char separately, then gate type
			statusCh := "✗"
			if node.Success {
				statusCh = "✓"
			}
			g.putStr(x+padLeft, row, statusCh, sty)

			var gateSty lipgloss.Style
			switch node.Type {
			case domain.OR:
				gateSty = gateORStyle()
			case domain.AND:
				gateSty = gateANDStyle()
			case domain.LEAF:
				gateSty = leafStyle()
			}
			rest := line[len(statusCh):]
			g.putStr(x+padLeft+len(statusCh), row, rest, gateSty)
			continue
		}

		if strings.HasPrefix(line, "-> ") {
			sty = idStyle()
		} else {
			sty = nameStyle()
		}
		g.putStr(x+padLeft, row, line, sty)
	}
}

func drawConnectors(
	g *grid, lo *layout, node *domain.AttackNode,
) {
	if len(node.Children) == 0 {
		return
	}

	nl := lo.nodes[node]
	parentCX := nl.centerX
	parentBottom := nl.y + nl.h

	// Collect child center Xs
	childCXs := make([]int, len(node.Children))
	for i, child := range node.Children {
		childNL := lo.nodes[child]
		childCXs[i] = childNL.centerX
	}

	cs := connStyle()
	if len(node.Children) == 1 {
		// Straight vertical line
		childTop := lo.nodes[node.Children[0]].y
		cx := parentCX
		for y := parentBottom; y < childTop; y++ {
			g.set(cx, y, '│', cs)
		}
	} else {
		// Fan-out
		// Vertical from parent down to fan-out line
		fanY := parentBottom + 1
		g.set(parentCX, parentBottom, '│', cs)

		// Horizontal fan-out line
		leftX := childCXs[0]
		rightX := childCXs[len(childCXs)-1]

		// Build the horizontal line
		childSet := make(map[int]bool)
		for _, cx := range childCXs {
			childSet[cx] = true
		}

		for x := leftX; x <= rightX; x++ {
			up := x == parentCX
			down := childSet[x]
			isLeft := x == leftX
			isRight := x == rightX

			ch := boxChar(up, down, !isLeft, !isRight)
			g.set(x, fanY, ch, cs)
		}

		// Vertical drops to each child
		for i, child := range node.Children {
			childNL := lo.nodes[child]
			cx := childCXs[i]
			for y := fanY + 1; y < childNL.y; y++ {
				g.set(cx, y, '│', cs)
			}
		}
	}

	// Recurse
	for _, child := range node.Children {
		drawConnectors(g, lo, child)
	}
}

func boxChar(up, down, left, right bool) rune {
	switch {
	case up && down && left && right:
		return '┼'
	case up && down && right && !left:
		return '├'
	case up && down && left && !right:
		return '┤'
	case up && left && right && !down:
		return '┴'
	case down && left && right && !up:
		return '┬'
	case up && down:
		return '│'
	case left && right:
		return '─'
	case down && right:
		return '┌'
	case down && left:
		return '┐'
	case up && right:
		return '└'
	case up && left:
		return '┘'
	case up:
		return '│'
	case down:
		return '│'
	default:
		return '─'
	}
}
