package ui

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/redhat-et/zero-trust-agent-demo/zt-monitor/internal/parser"
)

const maxEvents = 200

// EventList manages a scrollable list of events.
type EventList struct {
	events   []parser.Event
	offset   int // scroll offset (0 = latest at bottom)
	height   int
	filter   string
}

// NewEventList creates a new event list.
func NewEventList() *EventList {
	return &EventList{
		events: make([]parser.Event, 0, maxEvents),
	}
}

// Add appends an event, dropping old ones if at capacity.
func (el *EventList) Add(ev parser.Event) {
	el.events = append(el.events, ev)
	if len(el.events) > maxEvents {
		el.events = el.events[len(el.events)-maxEvents:]
	}
	// offset == 0 means "follow tail" — no adjustment needed
}

// Clear removes all events.
func (el *EventList) Clear() {
	el.events = el.events[:0]
	el.offset = 0
}

// ScrollUp moves the view up.
func (el *EventList) ScrollUp(n int) {
	el.offset += n
	visibleRows := el.height - 3 // match Render's header + padding
	if visibleRows < 1 {
		visibleRows = 1
	}
	maxOffset := len(el.filtered()) - visibleRows
	if maxOffset < 0 {
		maxOffset = 0
	}
	if el.offset > maxOffset {
		el.offset = maxOffset
	}
}

// ScrollDown moves the view down.
func (el *EventList) ScrollDown(n int) {
	el.offset -= n
	if el.offset < 0 {
		el.offset = 0
	}
}

// SetHeight sets the visible height.
func (el *EventList) SetHeight(h int) {
	el.height = h
}

// SetFilter sets a filter string. Empty means no filter.
func (el *EventList) SetFilter(f string) {
	el.filter = f
	el.offset = 0
}

// filtered returns events matching the current filter.
func (el *EventList) filtered() []parser.Event {
	if el.filter == "" {
		return el.events
	}
	f := strings.ToLower(el.filter)
	var result []parser.Event
	for _, ev := range el.events {
		if strings.Contains(strings.ToLower(ev.Message), f) ||
			strings.Contains(strings.ToLower(ev.Source), f) ||
			strings.Contains(strings.ToLower(ev.Type.String()), f) {
			result = append(result, ev)
		}
	}
	return result
}

// Render returns the formatted event list for display.
func (el *EventList) Render(width int) string {
	events := el.filtered()
	if len(events) == 0 {
		return panelTitle.Render("EVENTS") + "\n\n" +
			lipgloss.NewStyle().
				Foreground(colorMuted).
				PaddingLeft(2).
				Render("Waiting for events...")
	}

	var b strings.Builder
	header := panelTitle.Render("EVENTS")
	if el.filter != "" {
		header += lipgloss.NewStyle().
			Foreground(colorMuted).
			Render(fmt.Sprintf("  [filter: %s]", el.filter))
	}
	count := lipgloss.NewStyle().
		Foreground(colorMuted).
		Render(fmt.Sprintf("  (%d)", len(events)))
	b.WriteString(header + count + "\n\n")

	// Calculate visible window (from bottom)
	visibleHeight := el.height - 3 // header + padding
	if visibleHeight < 1 {
		visibleHeight = 1
	}

	start := len(events) - visibleHeight - el.offset
	if start < 0 {
		start = 0
	}
	end := start + visibleHeight
	if end > len(events) {
		end = len(events)
	}

	for _, ev := range events[start:end] {
		b.WriteString(formatEvent(ev, width))
		b.WriteString("\n")
	}

	// Scroll indicator
	if el.offset > 0 {
		b.WriteString(lipgloss.NewStyle().
			Foreground(colorMuted).
			PaddingLeft(2).
			Render(fmt.Sprintf("↓ %d more below", el.offset)))
	}

	return b.String()
}

func formatEvent(ev parser.Event, width int) string {
	ts := ev.Time.Format("15:04:05")

	sourceStyle := lipgloss.NewStyle().
		Foreground(ServiceColor(ev.Source)).
		Bold(true)

	label := ev.Source
	if ev.Container == "envoy-proxy" || ev.Container == "envoy" {
		label = "ENVOY"
	} else {
		label = strings.ToUpper(label)
	}

	src := sourceStyle.Render(fmt.Sprintf("[%-12s]", label))

	var msgStyle lipgloss.Style
	switch ev.Type {
	case parser.EventAccessDecision:
		if ev.Allowed != nil && *ev.Allowed {
			msgStyle = allowStyle
		} else {
			msgStyle = denyStyle
		}
	case parser.EventTokenExchange:
		msgStyle = tokenExchangeStyle
	case parser.EventDelegation:
		msgStyle = delegationStyle
	default:
		msgStyle = eventLineStyle
	}

	// Truncate message to fit available width (accounting for prefix)
	prefixWidth := 2 + len(ts) + 1 + 14 + 1 // "  HH:MM:SS [LABEL       ] "
	msg := ev.Message
	if width > 0 {
		maxMsg := width - prefixWidth
		if maxMsg > 0 && len(msg) > maxMsg {
			msg = msg[:maxMsg-1] + "…"
		}
	}

	return fmt.Sprintf("  %s %s %s", ts, src, msgStyle.Render(msg))
}
