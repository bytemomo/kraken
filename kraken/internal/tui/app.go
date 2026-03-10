package tui

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"bytemomo/kraken/internal/adapter/jsonreport"
	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/modules"
	"bytemomo/kraken/internal/native"
	regclient "bytemomo/kraken/internal/registry"
	"bytemomo/kraken/internal/adapter/yamlconfig"
	"bytemomo/kraken/internal/runner"
	"bytemomo/kraken/internal/runner/adapter"
	"bytemomo/kraken/internal/scanner"
	"bytemomo/kraken/internal/tui/components"
	"bytemomo/kraken/internal/tui/events"
	"bytemomo/kraken/internal/tui/keys"
	"bytemomo/kraken/internal/tui/styles"
	"bytemomo/kraken/internal/tui/views/attacktree"
	"bytemomo/kraken/internal/tui/views/campaign"
	"bytemomo/kraken/internal/tui/views/execution"
	"bytemomo/kraken/internal/tui/views/registry"
	"bytemomo/kraken/internal/tui/views/results"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/sirupsen/logrus"
)

// App is the root TUI model
type App struct {
	width  int
	height int
	keys   keys.KeyMap

	// Navigation
	header    components.Header
	statusBar components.StatusBar

	// Views
	campaign   campaign.Model
	registry   registry.Model
	execution  execution.Model
	results    results.Model
	attackTree attacktree.Model

	// State
	loadedCampaign *domain.Campaign
	campaignPath   string
	cancelFunc     context.CancelFunc
	isRunning      bool

	// Confirmation dialog
	showConfirm   bool
	confirmAction func()

	// Event channel for live updates
	eventChan chan events.Event

	// Execution config (from campaign view)
	cidrs     []string
	iface     string
	outputDir string
}

// New creates a new TUI application
func New() App {
	keyMap := keys.DefaultKeyMap()

	// Initialize modules
	modules.Init()

	eventChan := make(chan events.Event, 100)

	// Redirect logrus to file instead of stdout/stderr (prevents TUI corruption)
	logFile, err := os.OpenFile("kraken-tui.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		logrus.SetOutput(logFile)
	} else {
		logrus.SetOutput(io.Discard)
	}
	logrus.SetFormatter(&logrus.JSONFormatter{})

	return App{
		keys:       keyMap,
		header:     components.NewHeader(),
		statusBar:  components.NewStatusBar(),
		campaign:   campaign.New(keyMap),
		registry:   registry.New(keyMap),
		execution:  execution.New(keyMap),
		results:    results.New(keyMap),
		attackTree: attacktree.New(keyMap),
		eventChan:  eventChan,
		outputDir:  "./kraken-results",
	}
}

// EventChannel returns the event channel for sending live updates
func (a *App) EventChannel() chan<- events.Event {
	return a.eventChan
}

const tickInterval = time.Second

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(tickInterval, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// Init initializes the application
func (a App) Init() tea.Cmd {
	return tea.Batch(
		a.campaign.Init(),
		a.registry.Init(),
		a.listenForEvents(),
		tickCmd(),
	)
}

func (a App) listenForEvents() tea.Cmd {
	return func() tea.Msg {
		event := <-a.eventChan
		return event
	}
}

// Update handles messages
func (a App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
		a.header.SetWidth(msg.Width)
		a.statusBar.SetWidth(msg.Width)

		contentHeight := msg.Height - 3 // header + status bar (with top border)
		a.campaign.SetSize(msg.Width, contentHeight)
		a.registry.SetSize(msg.Width, contentHeight)
		a.execution.SetSize(msg.Width, contentHeight)
		a.results.SetSize(msg.Width, contentHeight)
		a.attackTree.SetSize(msg.Width, contentHeight)

	case tea.KeyMsg:
		// Handle confirmation dialog
		if a.showConfirm {
			switch msg.String() {
			case "y", "Y":
				a.showConfirm = false
				if a.confirmAction != nil {
					a.confirmAction()
					a.confirmAction = nil
				}
			case "n", "N", "esc":
				a.showConfirm = false
				a.confirmAction = nil
			}
			return a, nil
		}

		// Skip global key handling when typing in campaign view
		textInputActive := a.header.ActiveTab == components.TabCampaign && a.campaign.IsTextInputActive()

		switch {
		case key.Matches(msg, a.keys.Quit):
			// Always allow quit with ctrl+c
			if msg.String() == "ctrl+c" {
				if a.cancelFunc != nil {
					a.cancelFunc()
				}
				return a, tea.Quit
			}
			// 'q' only quits when not typing
			if !textInputActive {
				if a.isRunning {
					a.showConfirm = true
					a.confirmAction = func() {
						if a.cancelFunc != nil {
							a.cancelFunc()
						}
					}
					return a, tea.Quit
				}
				if a.cancelFunc != nil {
					a.cancelFunc()
				}
				return a, tea.Quit
			}
		case key.Matches(msg, a.keys.Tab):
			// Don't switch tabs if typing in an input
			if !textInputActive && a.header.ActiveTab != components.TabCampaign {
				nextTab := (a.header.ActiveTab + 1) % 5
				a.switchToTab(nextTab)
			}
		case key.Matches(msg, a.keys.ShiftTab):
			if !textInputActive && a.header.ActiveTab != components.TabCampaign {
				prevTab := (a.header.ActiveTab + 4) % 5
				a.switchToTab(prevTab)
			}
		case key.Matches(msg, a.keys.Stop):
			if !textInputActive && a.cancelFunc != nil {
				a.cancelFunc()
				a.cancelFunc = nil
				a.isRunning = false
				a.statusBar.State = components.StateFailed
			}
		case msg.String() == "1":
			if !textInputActive {
				a.switchToTab(components.TabCampaign)
			}
		case msg.String() == "2":
			if !textInputActive {
				a.switchToTab(components.TabRegistry)
			}
		case msg.String() == "3":
			if !textInputActive {
				a.switchToTab(components.TabExecution)
			}
		case msg.String() == "4":
			if !textInputActive {
				a.switchToTab(components.TabResults)
			}
		case msg.String() == "5":
			if !textInputActive {
				a.switchToTab(components.TabAttackTree)
			}
		case msg.String() == "f1":
			styles.ToggleTheme()
		}

	case tickMsg:
		if a.isRunning {
			a.execution.Tick()
		}
		cmds = append(cmds, tickCmd())

	case campaign.StartRequestedMsg:
		// User pressed start in campaign view with all config
		a.loadedCampaign = msg.Campaign
		a.campaignPath = msg.Path
		a.cidrs = msg.CIDRs
		a.iface = msg.Interface
		a.outputDir = msg.OutputDir
		a.statusBar.CampaignID = msg.Campaign.ID
		a.statusBar.TargetCount = 0
		a.statusBar.FindingCount = 0
		a.statusBar.OutputDir = msg.OutputDir
		a.isRunning = true

		// Switch to execution view and start
		a.header.SetActiveTab(components.TabExecution)
		// Reset execution view for fresh run
		a.execution = execution.New(a.keys)
		a.execution.SetSize(a.width, a.height-3)
		a.execution.SetCampaign(msg.Campaign)
		// Clear previous results when starting a new campaign
		a.results.Clear()
		cmds = append(cmds, a.startCampaignCmd())

	case campaign.CampaignLoadedMsg:
		a.loadedCampaign = msg.Campaign
		a.campaignPath = msg.Path
		a.statusBar.CampaignID = msg.Campaign.ID

	case registry.IndexRefreshedMsg,
		registry.ModuleResolvedMsg,
		registry.ModuleDownloadedMsg:
		newRegistry, cmd := a.registry.Update(msg)
		a.registry = newRegistry
		cmds = append(cmds, cmd)
		return a, tea.Batch(cmds...)

	case runCompletedMsg:
		a.isRunning = false
		a.statusBar.State = components.StateCompleted
		if msg.err != nil {
			a.statusBar.State = components.StateFailed
			a.eventChan <- events.LogEntry{Time: time.Now(), Level: "error", Message: msg.err.Error()}
		}
		a.results.SetResults(msg.results)
		a.attackTree.SetTrees(msg.attackTrees)

	case events.Event:
		// Forward events to execution view
		a.execution.HandleEvent(msg)

		// Update results view with findings
		if fe, ok := msg.(events.FindingDiscovered); ok {
			a.results.AddFinding(fe.Finding)
			a.statusBar.FindingCount++
		}

		// Update status bar
		if _, ok := msg.(events.TargetDiscovered); ok {
			a.statusBar.TargetCount++
		}

		// Update output dir
		if od, ok := msg.(events.OutputDirResolved); ok {
			a.statusBar.OutputDir = od.Path
		}

		// Update state
		switch msg.(type) {
		case events.ScannerStarted:
			a.statusBar.State = components.StateScanning
		case events.ModuleStarted:
			a.statusBar.State = components.StateRunning
		case events.RunCompleted:
			rc := msg.(events.RunCompleted)
			if rc.Error != nil {
				a.statusBar.State = components.StateFailed
			} else {
				a.statusBar.State = components.StateCompleted
			}
		}

		// Continue listening and return early (events are already
		// handled by HandleEvent, no need to forward to view Update)
		cmds = append(cmds, a.listenForEvents())
		return a, tea.Batch(cmds...)
	}

	// Update active view
	switch a.header.ActiveTab {
	case components.TabCampaign:
		newCampaign, cmd := a.campaign.Update(msg)
		a.campaign = newCampaign
		cmds = append(cmds, cmd)

	case components.TabRegistry:
		newRegistry, cmd := a.registry.Update(msg)
		a.registry = newRegistry
		cmds = append(cmds, cmd)

	case components.TabExecution:
		newExecution, cmd := a.execution.Update(msg)
		a.execution = newExecution
		cmds = append(cmds, cmd)

	case components.TabResults:
		newResults, cmd := a.results.Update(msg)
		a.results = newResults
		cmds = append(cmds, cmd)

	case components.TabAttackTree:
		newTree, cmd := a.attackTree.Update(msg)
		a.attackTree = newTree
		cmds = append(cmds, cmd)
	}

	return a, tea.Batch(cmds...)
}

type runCompletedMsg struct {
	results     []domain.RunResult
	attackTrees []domain.AttackTreeResult
	err         error
}

func (a *App) switchToTab(tab components.Tab) {
	// If running and switching away from execution/results, ask for confirmation
	if a.isRunning && tab != components.TabExecution && tab != components.TabResults && tab != components.TabAttackTree {
		a.showConfirm = true
		a.confirmAction = func() {
			// Stop the running campaign
			if a.cancelFunc != nil {
				a.cancelFunc()
				a.cancelFunc = nil
			}
			a.isRunning = false
			a.statusBar.State = components.StateIdle
			// Reset execution view
			a.execution = execution.New(a.keys)
			a.execution.SetSize(a.width, a.height-3)
			a.header.SetActiveTab(tab)
		}
		return
	}
	a.header.SetActiveTab(tab)
}

func (a *App) startCampaignCmd() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithCancel(context.Background())
		a.cancelFunc = cancel
		a.execution.Start(cancel)

		camp := a.loadedCampaign

		log := logrus.NewEntry(logrus.StandardLogger())

		// Send start event
		a.eventChan <- events.ScannerStarted{
			ScannerType: "nmap",
			Config:      fmt.Sprintf("CIDRs: %v, Interface: %s", a.cidrs, a.iface),
		}

		var classifiedTargets []domain.ClassifiedTarget
		var scanErr error

		if camp.EffectiveType() == domain.CampaignNetwork {
			if len(a.cidrs) == 0 {
				a.eventChan <- events.LogEntry{Time: time.Now(), Level: "error", Message: "No target CIDRs configured"}
				a.eventChan <- events.RunCompleted{Error: fmt.Errorf("no target CIDRs configured")}
				return runCompletedMsg{err: fmt.Errorf("no target CIDRs configured")}
			}

			configs := camp.EffectiveScanners()
			var scanners []scanner.Scanner

			for i, cfg := range configs {
				if cfg.Type == "ethercat" && cfg.EtherCAT != nil && a.iface != "" {
					cfg.EtherCAT.Interface = a.iface
				}
				s, err := scanner.NewScanner(log.WithField("scanner_idx", i), cfg, a.cidrs)
				if err != nil {
					a.eventChan <- events.LogEntry{Time: time.Now(), Level: "error", Message: fmt.Sprintf("Create scanner: %v", err)}
					continue
				}
				scanners = append(scanners, s)
			}

			if len(scanners) > 0 {
				classifiedTargets, scanErr = scanner.ExecuteAll(ctx, scanners)
				if scanErr != nil {
					a.eventChan <- events.LogEntry{Time: time.Now(), Level: "error", Message: fmt.Sprintf("Scanner error: %v", scanErr)}
				}
			}

			// Emit target discovered events
			for _, ct := range classifiedTargets {
				a.eventChan <- events.TargetDiscovered{Target: ct}
			}

			a.eventChan <- events.ScannerCompleted{Targets: classifiedTargets, Error: scanErr}
		} else {
			// Fuzz campaign - no scanning
			classifiedTargets = []domain.ClassifiedTarget{{
				Target: domain.HostPort{Host: camp.ID},
			}}
			a.eventChan <- events.ScannerCompleted{Targets: classifiedTargets}
		}

		if ctx.Err() != nil {
			return runCompletedMsg{err: ctx.Err()}
		}

		// Setup result directory
		resultDir := fmt.Sprintf("%s/%s/%d", a.outputDir, camp.ID, time.Now().Unix())
		if err := os.MkdirAll(resultDir, 0o755); err != nil {
			a.eventChan <- events.LogEntry{Time: time.Now(), Level: "error", Message: fmt.Sprintf("Create output dir: %v", err)}
		}
		jsonReporter := jsonreport.New(resultDir)

		a.eventChan <- events.OutputDirResolved{Path: resultDir}
		a.eventChan <- events.LogEntry{Time: time.Now(), Level: "info", Message: fmt.Sprintf("Results will be saved to: %s", resultDir)}

		// Setup registry resolver for lazy loading of registry modules
		var registryResolver runner.RegistryResolver
		regClient, err := regclient.NewClient(regclient.DefaultConfig())
		if err == nil {
			registryResolver = regclient.NewResolver(regClient)
		}

		// Create runner with callbacks
		r := runner.Runner{
			Log:              log,
			Executors:        newModuleExecutors(),
			Store:            jsonReporter,
			ResultDirectory:  resultDir,
			RegistryResolver: registryResolver,
			Callbacks: runner.Callbacks{
				OnTargetStart: func(target domain.Target, moduleCount int) {
					a.eventChan <- events.LogEntry{
						Time:    time.Now(),
						Level:   "info",
						Message: fmt.Sprintf("Starting target %s (%d modules)", target.String(), moduleCount),
					}
				},
				OnTargetComplete: func(target domain.Target, result domain.RunResult) {
					a.eventChan <- events.TargetCompleted{Target: target, Result: result}
				},
				OnModuleStart: func(target domain.Target, module string, timeout time.Duration) {
					a.eventChan <- events.ModuleStarted{Target: target, Module: module, Timeout: timeout}
				},
				OnModuleComplete: func(target domain.Target, module string, findings []domain.Finding, err error) {
					a.eventChan <- events.ModuleCompleted{
						Target:   target,
						Module:   module,
						Findings: findings,
						Error:    err,
					}
				},
				OnFinding: func(finding domain.Finding) {
					a.eventChan <- events.FindingDiscovered{Finding: finding}
				},
				OnLog: func(level, message string) {
					a.eventChan <- events.LogEntry{Time: time.Now(), Level: level, Message: message}
				},
			},
		}

		// Execute
		results, runErr := r.Execute(ctx, *camp, classifiedTargets)

		// Evaluate attack trees against findings
		var attackTreeResults []domain.AttackTreeResult
		if camp.AttackTreesDefPath != "" {
			trees, err := yamlconfig.LoadAttackTrees(camp.AttackTreesDefPath)
			if err != nil {
				a.eventChan <- events.LogEntry{
					Time: time.Now(), Level: "warn",
					Message: fmt.Sprintf("Load attack trees: %v", err),
				}
			} else {
				for _, result := range results {
					for _, tree := range trees {
						treeClone := tree.Clone()
						treeClone.Evaluate(result.Findings)
						attackTreeResults = append(attackTreeResults,
							domain.AttackTreeResult{
								Target: result.Target,
								Tree:   treeClone,
							})
					}
				}
			}
		}

		a.eventChan <- events.RunCompleted{Results: results, Error: runErr}

		return runCompletedMsg{
			results:     results,
			attackTrees: attackTreeResults,
			err:         runErr,
		}
	}
}

func newModuleExecutors() []runner.ModuleExecutor {
	return []runner.ModuleExecutor{
		adapter.NewNativeBuiltinAdapter(),
		adapter.NewABIModuleAdapter(),
		adapter.NewContainerModuleAdapter(),
		adapter.NewGRPCModuleAdapter(),
	}
}

// View renders the application
func (a App) View() string {
	if a.width == 0 || a.height == 0 {
		return "Initializing..."
	}

	// Header
	header := a.header.View()

	// Content based on active tab
	var content string
	switch a.header.ActiveTab {
	case components.TabCampaign:
		content = a.campaign.View()
	case components.TabRegistry:
		content = a.registry.View()
	case components.TabExecution:
		content = a.execution.View()
	case components.TabResults:
		content = a.results.View()
	case components.TabAttackTree:
		content = a.attackTree.View()
	}

	// Status bar
	statusBar := a.statusBar.View()

	// Show confirmation dialog if active
	if a.showConfirm {
		dialogStyle := lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(styles.Primary).
			Padding(1, 2).
			Align(lipgloss.Center)

		dialog := dialogStyle.Render(
			"Campaign is running!\n\n" +
				"Stop campaign and switch view?\n\n" +
				"[Y] Yes  [N] No",
		)

		// Overlay dialog centered on content
		content = lipgloss.Place(a.width, a.height-3, lipgloss.Center, lipgloss.Center, dialog)
	}

	// Combine
	return lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		content,
		statusBar,
	)
}

// ListNativeModules returns the list of native modules
func ListNativeModules() []string {
	modules.Init()
	var names []string
	for _, m := range native.List() {
		names = append(names, m.ID)
	}
	return names
}
