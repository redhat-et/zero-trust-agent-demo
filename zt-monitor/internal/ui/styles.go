package ui

import (
	"image/color"

	"charm.land/lipgloss/v2"
)

// Colors used throughout the TUI.
var (
	colorTitle    = lipgloss.Color("#7D56F4")
	colorBorder   = lipgloss.Color("#444444")
	colorActive   = lipgloss.Color("#04B575")
	colorDenied   = lipgloss.Color("#FF4444")
	colorAllowed  = lipgloss.Color("#04B575")
	colorToken    = lipgloss.Color("#FFD700")
	colorMuted    = lipgloss.Color("#666666")
	colorLabel    = lipgloss.Color("#AAAAAA")
	colorHighlight = lipgloss.Color("#FF79C6")

	// Service colors (matching logger component colors)
	colorUserSvc    = lipgloss.Color("#5555FF") // blue
	colorAgentSvc   = lipgloss.Color("#FF55FF") // magenta
	colorDocSvc     = lipgloss.Color("#FFFF55") // yellow
	colorOPA        = lipgloss.Color("#55FFFF") // cyan
	colorDashboard  = lipgloss.Color("#FFFFFF") // white
	colorSummarizer = lipgloss.Color("#55FFFF") // cyan
	colorReviewer   = lipgloss.Color("#FF55FF") // magenta
	colorEnvoy      = lipgloss.Color("#FF8800") // orange
)

// Styles used by the TUI components.
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorTitle).
			PaddingLeft(1)

	badgeLive = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#000000")).
			Background(colorActive).
			Padding(0, 1)

	badgeNamespace = lipgloss.NewStyle().
			Foreground(colorLabel).
			Padding(0, 1)

	panelBorder = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder)

	panelTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorLabel).
			PaddingLeft(1)

	eventLineStyle = lipgloss.NewStyle().
			PaddingLeft(1)

	allowStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAllowed)

	denyStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorDenied)

	tokenExchangeStyle = lipgloss.NewStyle().
				Foreground(colorToken)

	delegationStyle = lipgloss.NewStyle().
			Foreground(colorHighlight)

	flowNodeStyle = lipgloss.NewStyle().
			Foreground(colorLabel)

	flowActiveStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorActive)

	flowArrowStyle = lipgloss.NewStyle().
			Foreground(colorMuted)

	tokenLabelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorLabel)

	tokenValueStyle = lipgloss.NewStyle().
			Foreground(colorToken)

	helpStyle = lipgloss.NewStyle().
			Foreground(colorMuted).
			PaddingLeft(1)

	statusBarStyle = lipgloss.NewStyle().
			Foreground(colorMuted).
			PaddingLeft(1)
)

// ServiceColor returns the display color for a service name.
func ServiceColor(service string) color.Color {
	switch service {
	case "user-svc", "user-service":
		return colorUserSvc
	case "agent-svc", "agent-service":
		return colorAgentSvc
	case "doc-svc", "document-service":
		return colorDocSvc
	case "opa", "opa-service":
		return colorOPA
	case "dashboard", "web-dashboard":
		return colorDashboard
	case "summarizer", "summarizer-service":
		return colorSummarizer
	case "reviewer", "reviewer-service":
		return colorReviewer
	case "envoy", "envoy-proxy":
		return colorEnvoy
	default:
		return colorLabel
	}
}
