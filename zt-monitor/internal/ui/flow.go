package ui

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
)

// flowNode represents a service in the flow diagram.
type flowNode struct {
	Name  string
	Short string
}

var flowNodes = []flowNode{
	{Name: "dashboard", Short: "dashboard"},
	{Name: "user-svc", Short: "user-svc"},
	{Name: "agent-svc", Short: "agent-svc"},
	{Name: "doc-svc", Short: "doc-svc"},
	{Name: "opa", Short: "opa"},
}

var a2aNodes = []flowNode{
	{Name: "summarizer", Short: "summarizer"},
	{Name: "reviewer", Short: "reviewer"},
}

// RenderFlow renders the ASCII flow diagram with active service highlighting.
func RenderFlow(width int, activeServices map[string]bool, activeEdge [2]string, edgeLabel string) string {
	var b strings.Builder

	b.WriteString(panelTitle.Render("FLOW"))
	b.WriteString("\n\n")

	// Main flow line
	b.WriteString("  ")
	for i, node := range flowNodes {
		style := flowNodeStyle
		if activeServices[node.Name] {
			style = flowActiveStyle
		}
		b.WriteString(style.Render(node.Short))
		if i < len(flowNodes)-1 {
			var arrow string
			if isActiveEdge(activeEdge, flowNodes[i].Name, flowNodes[i+1].Name) {
				arrow = flowActiveStyle.Render(" ──→ ")
			} else {
				arrow = flowArrowStyle.Render(" ──→ ")
			}
			b.WriteString(arrow)
		}
	}
	b.WriteString("\n")

	// A2A branch line (from agent-svc)
	b.WriteString("                           ")
	for i, node := range a2aNodes {
		prefix := "└──→ "
		if i > 0 {
			prefix = "     └──→ "
		}
		style := flowNodeStyle
		if activeServices[node.Name] {
			style = flowActiveStyle
		}

		if isActiveEdge(activeEdge, "agent-svc", node.Name) {
			b.WriteString(flowActiveStyle.Render(prefix))
		} else {
			b.WriteString(flowArrowStyle.Render(prefix))
		}
		b.WriteString(style.Render(node.Short))

		// Show arrow to doc-svc from A2A agents
		if activeServices[node.Name] {
			b.WriteString(flowArrowStyle.Render(" ──→ "))
			b.WriteString(flowNodeStyle.Render("doc-svc"))
		}
		b.WriteString("\n")
		if i == 0 {
			b.WriteString("                           ")
		}
	}

	// Active edge label
	if activeEdge[0] != "" && activeEdge[1] != "" {
		label := fmt.Sprintf("Active: %s → %s", activeEdge[0], activeEdge[1])
		if edgeLabel != "" {
			label += " [" + edgeLabel + "]"
		}
		style := lipgloss.NewStyle().
			Foreground(colorActive).
			Bold(true).
			PaddingLeft(2)
		b.WriteString("\n")
		b.WriteString(style.Render(label))
	}

	return b.String()
}

func isActiveEdge(active [2]string, from, to string) bool {
	return active[0] == from && active[1] == to
}
