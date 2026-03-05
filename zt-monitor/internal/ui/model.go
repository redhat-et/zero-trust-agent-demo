package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/redhat-et/zero-trust-agent-demo/zt-monitor/internal/k8s"
	"github.com/redhat-et/zero-trust-agent-demo/zt-monitor/internal/parser"
)

// EventMsg wraps a parsed event as a Bubbletea message.
type EventMsg parser.Event

// TickMsg triggers periodic UI refresh.
type TickMsg time.Time

// Model is the main Bubbletea model for zt-monitor.
type Model struct {
	namespace  string
	kubeconfig string

	width  int
	height int

	events     *EventList
	tokens     *TokenPanel
	paused     bool
	filtering  bool
	filterBuf  string

	// Flow state
	activeServices map[string]bool
	activeEdge     [2]string
	edgeLabel      string
	edgeExpiry     time.Time

	// Log streaming
	cancel context.CancelFunc
	eventCh chan parser.Event

	// Event count for status
	totalEvents int
}

// NewModel creates a new TUI model.
func NewModel(namespace, kubeconfig string) Model {
	return Model{
		namespace:      namespace,
		kubeconfig:     kubeconfig,
		events:         NewEventList(),
		tokens:         NewTokenPanel(),
		activeServices: make(map[string]bool),
	}
}

// Init starts log streaming and the refresh ticker.
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.startStreaming(),
		tickCmd(),
	)
}

func (m *Model) startStreaming() tea.Cmd {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.eventCh = make(chan parser.Event, 100)

	go k8s.StreamLogs(ctx, m.namespace, m.kubeconfig, m.eventCh)

	return m.waitForEvent()
}

func (m *Model) waitForEvent() tea.Cmd {
	ch := m.eventCh
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return nil
		}
		return EventMsg(ev)
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

// Update handles messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.events.SetHeight(m.eventPanelHeight())
		return m, nil

	case tea.KeyPressMsg:
		return m.handleKey(msg)

	case EventMsg:
		if !m.paused {
			ev := parser.Event(msg)
			m.events.Add(ev)
			m.tokens.UpdateFromEvent(ev)
			m.updateFlowState(ev)
			m.totalEvents++
		}
		return m, m.waitForEvent()

	case TickMsg:
		// Expire active edge highlight
		if !m.edgeExpiry.IsZero() && time.Now().After(m.edgeExpiry) {
			m.activeEdge = [2]string{}
			m.edgeLabel = ""
			m.edgeExpiry = time.Time{}
			// Clear active services after timeout
			m.activeServices = make(map[string]bool)
		}
		return m, tickCmd()
	}

	return m, nil
}

func (m Model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	// If filtering, handle filter input
	if m.filtering {
		switch msg.String() {
		case "enter":
			m.filtering = false
			m.events.SetFilter(m.filterBuf)
			return m, nil
		case "escape":
			m.filtering = false
			m.filterBuf = ""
			m.events.SetFilter("")
			return m, nil
		case "backspace":
			if len(m.filterBuf) > 0 {
				m.filterBuf = m.filterBuf[:len(m.filterBuf)-1]
			}
			return m, nil
		default:
			if len(msg.String()) == 1 {
				m.filterBuf += msg.String()
			}
			return m, nil
		}
	}

	switch msg.String() {
	case "q", "ctrl+c":
		if m.cancel != nil {
			m.cancel()
		}
		return m, tea.Quit
	case "p":
		m.paused = !m.paused
		return m, nil
	case "c":
		m.events.Clear()
		m.tokens.Clear()
		m.activeServices = make(map[string]bool)
		m.activeEdge = [2]string{}
		m.totalEvents = 0
		return m, nil
	case "f":
		m.filtering = true
		m.filterBuf = ""
		return m, nil
	case "up", "k":
		m.events.ScrollUp(1)
		return m, nil
	case "down", "j":
		m.events.ScrollDown(1)
		return m, nil
	case "pgup":
		m.events.ScrollUp(10)
		return m, nil
	case "pgdown":
		m.events.ScrollDown(10)
		return m, nil
	}

	return m, nil
}

func (m *Model) updateFlowState(ev parser.Event) {
	m.activeServices[ev.Source] = true

	switch ev.Type {
	case parser.EventTokenExchange:
		if aud, ok := ev.Fields["audience"]; ok {
			m.activeEdge = [2]string{ev.Source, audienceToService(aud)}
			m.edgeLabel = "Token Exchange"
		} else {
			m.activeEdge = [2]string{ev.Source, ""}
			m.edgeLabel = "Token Exchange"
		}
	case parser.EventDelegation:
		m.activeEdge = [2]string{"user-svc", "agent-svc"}
		m.edgeLabel = "Delegation"
	case parser.EventAccessDecision:
		m.activeEdge = [2]string{"doc-svc", "opa"}
		if ev.Allowed != nil && *ev.Allowed {
			m.edgeLabel = "ALLOW"
		} else {
			m.edgeLabel = "DENY"
		}
	case parser.EventA2AInvoke:
		m.activeEdge = [2]string{"agent-svc", ev.Source}
		m.edgeLabel = "A2A Invoke"
	}

	m.edgeExpiry = time.Now().Add(5 * time.Second)
}

func audienceToService(aud string) string {
	switch {
	case strings.Contains(aud, "document"):
		return "doc-svc"
	case strings.Contains(aud, "summarizer"):
		return "summarizer"
	case strings.Contains(aud, "reviewer"):
		return "reviewer"
	case strings.Contains(aud, "agent"):
		return "agent-svc"
	case strings.Contains(aud, "user"):
		return "user-svc"
	default:
		return aud
	}
}

// View renders the full TUI.
func (m Model) View() tea.View {
	if m.width == 0 {
		return tea.NewView("Initializing...")
	}

	var sections []string

	// Header
	sections = append(sections, m.renderHeader())

	// Flow panel (~30%)
	flowHeight := max(m.height*30/100, 8)
	flowContent := RenderFlow(m.width-4, m.activeServices, m.activeEdge, m.edgeLabel)
	flowPanel := panelBorder.
		Width(m.width - 2).
		Height(flowHeight).
		Render(flowContent)
	sections = append(sections, flowPanel)

	// Events panel (~40%)
	eventContent := m.events.Render(m.width - 4)
	eventHeight := max(m.height*40/100, 6)
	m.events.SetHeight(eventHeight)
	eventPanel := panelBorder.
		Width(m.width - 2).
		Height(eventHeight).
		Render(eventContent)
	sections = append(sections, eventPanel)

	// Token panel (~20%)
	tokenContent := m.tokens.Render(m.width - 4)
	tokenHeight := max(m.height*20/100, 5)
	tokenPanel := panelBorder.
		Width(m.width - 2).
		Height(tokenHeight).
		Render(tokenContent)
	sections = append(sections, tokenPanel)

	// Status bar
	sections = append(sections, m.renderStatusBar())

	return tea.NewView(strings.Join(sections, "\n"))
}

func (m Model) renderHeader() string {
	title := titleStyle.Render("Zero-Trust Flow Monitor")

	ns := badgeNamespace.Render("[" + m.namespace + "]")

	status := badgeLive.Render("Live")
	if m.paused {
		status = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#000000")).
			Background(colorToken).
			Padding(0, 1).
			Render("Paused")
	}

	right := ns + " " + status
	gap := m.width - len(stripANSI(title)) - len(stripANSI(right)) - 2
	if gap < 1 {
		gap = 1
	}

	return title + strings.Repeat(" ", gap) + right
}

func (m Model) renderStatusBar() string {
	help := "q:quit  p:pause  c:clear  f:filter  ↑↓/jk:scroll"
	if m.filtering {
		help = fmt.Sprintf("Filter: %s█  (enter to apply, esc to cancel)", m.filterBuf)
	}

	right := fmt.Sprintf("Events: %d", m.totalEvents)
	gap := m.width - len(help) - len(right) - 4
	if gap < 1 {
		gap = 1
	}

	return helpStyle.Render(help) + strings.Repeat(" ", gap) + statusBarStyle.Render(right)
}

func (m Model) eventPanelHeight() int {
	h := m.height * 40 / 100
	if h < 6 {
		return 6
	}
	return h
}
