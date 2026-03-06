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

const arrow = " -> "

// RenderFlow renders the ASCII flow diagram with active service highlighting.
func RenderFlow(activeServices map[string]bool, activeEdge [2]string, edgeLabel string) string {
	var b strings.Builder

	b.WriteString(panelTitle.Render("FLOW"))
	b.WriteString("\n\n")

	// Main flow line:
	//   dashboard -> user-svc -> agent-svc -> doc-svc -> opa
	b.WriteString("  ")
	for i, node := range flowNodes {
		style := flowNodeStyle
		if activeServices[node.Name] {
			style = flowActiveStyle
		}
		b.WriteString(style.Render(node.Short))
		if i < len(flowNodes)-1 {
			if isActiveEdge(activeEdge, flowNodes[i].Name, flowNodes[i+1].Name) {
				b.WriteString(flowActiveStyle.Render(arrow))
			} else {
				b.WriteString(flowArrowStyle.Render(arrow))
			}
		}
	}
	b.WriteString("\n")

	// Calculate indent to align branches under agent-svc
	indent := 2 + len("dashboard") + len(arrow) + len("user-svc") + len(arrow)
	pad := strings.Repeat(" ", indent)

	// A2A branch lines (both are peers called by agent-svc):
	//                             |- summarizer  -> doc-svc -> opa
	//                             '- reviewer    -> doc-svc -> opa
	for i, node := range a2aNodes {
		connector := "|- "
		if i == len(a2aNodes)-1 {
			connector = "'- "
		}

		b.WriteString(pad)

		if isActiveEdge(activeEdge, "agent-svc", node.Name) {
			b.WriteString(flowActiveStyle.Render(connector))
		} else {
			b.WriteString(flowArrowStyle.Render(connector))
		}

		style := flowNodeStyle
		if activeServices[node.Name] {
			style = flowActiveStyle
		}
		name := fmt.Sprintf("%-12s", node.Short)
		b.WriteString(style.Render(name))

		// -> doc-svc -> opa
		if isActiveEdge(activeEdge, node.Name, "doc-svc") {
			b.WriteString(flowActiveStyle.Render(arrow))
			b.WriteString(flowActiveStyle.Render("doc-svc"))
		} else {
			b.WriteString(flowArrowStyle.Render(arrow))
			b.WriteString(flowNodeStyle.Render("doc-svc"))
		}

		if isActiveEdge(activeEdge, "doc-svc", "opa") {
			b.WriteString(flowActiveStyle.Render(arrow))
			b.WriteString(flowActiveStyle.Render("opa"))
		} else {
			b.WriteString(flowArrowStyle.Render(arrow))
			b.WriteString(flowNodeStyle.Render("opa"))
		}

		b.WriteString("\n")
	}

	// Active edge label
	if activeEdge[0] != "" && activeEdge[1] != "" {
		label := fmt.Sprintf("Active: %s -> %s", activeEdge[0], activeEdge[1])
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
