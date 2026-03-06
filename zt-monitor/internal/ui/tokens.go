package ui

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/redhat-et/zero-trust-agent-demo/zt-monitor/internal/parser"
)

// TokenPanel shows before/after token claims side by side.
type TokenPanel struct {
	Before map[string]string
	After  map[string]string
}

// NewTokenPanel creates an empty token panel.
func NewTokenPanel() *TokenPanel {
	return &TokenPanel{
		Before: make(map[string]string),
		After:  make(map[string]string),
	}
}

// UpdateFromEvent extracts token claims from a token exchange event.
func (tp *TokenPanel) UpdateFromEvent(ev parser.Event) {
	if ev.Type != parser.EventTokenExchange {
		return
	}

	phase := ev.Fields["phase"]
	switch phase {
	case "before":
		for k, v := range ev.Fields {
			if strings.HasPrefix(k, "before_") {
				tp.Before[strings.TrimPrefix(k, "before_")] = v
			}
		}
	case "after":
		for k, v := range ev.Fields {
			if strings.HasPrefix(k, "after_") {
				tp.After[strings.TrimPrefix(k, "after_")] = v
			}
		}
	}

	// Also extract from specific fields
	if aud, ok := ev.Fields["audience"]; ok {
		tp.After["aud"] = aud
	}
	if cid, ok := ev.Fields["client_id"]; ok {
		tp.Before["azp"] = cid
	}
}

// Clear resets the token panel.
func (tp *TokenPanel) Clear() {
	tp.Before = make(map[string]string)
	tp.After = make(map[string]string)
}

// Render returns the formatted token panel.
func (tp *TokenPanel) Render(width int) string {
	var b strings.Builder

	b.WriteString(panelTitle.Render("TOKENS"))
	b.WriteString("\n\n")

	if len(tp.Before) == 0 && len(tp.After) == 0 {
		b.WriteString(lipgloss.NewStyle().
			Foreground(colorMuted).
			PaddingLeft(2).
			Render("No token exchange captured yet"))
		return b.String()
	}

	halfWidth := (width - 6) / 2
	if halfWidth < 20 {
		halfWidth = 20
	}

	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorToken).
		Width(halfWidth).
		PaddingLeft(1).
		PaddingRight(1)

	titleStyle := lipgloss.NewStyle().
		Foreground(colorToken).
		Bold(true)

	beforeContent := renderClaims(titleStyle.Render("Before"), tp.Before, halfWidth-4)
	afterContent := renderClaims(titleStyle.Render("After"), tp.After, halfWidth-4)

	beforeBox := boxStyle.Render(beforeContent)
	afterBox := boxStyle.Render(afterContent)

	// Place side by side
	beforeLines := strings.Split(beforeBox, "\n")
	afterLines := strings.Split(afterBox, "\n")

	maxLines := max(len(beforeLines), len(afterLines))

	for i := range maxLines {
		left := ""
		if i < len(beforeLines) {
			left = beforeLines[i]
		}
		right := ""
		if i < len(afterLines) {
			right = afterLines[i]
		}

		left = padRight(left, halfWidth+2)

		b.WriteString("  ")
		b.WriteString(left)
		b.WriteString("  ")
		b.WriteString(right)
		b.WriteString("\n")
	}

	return b.String()
}

func renderClaims(title string, claims map[string]string, maxValWidth int) string {
	var b strings.Builder

	b.WriteString(title)
	b.WriteString("\n")

	displayKeys := []string{"aud", "azp", "sub", "iss", "exp", "scope"}
	for _, key := range displayKeys {
		if val, ok := claims[key]; ok {
			b.WriteString(fmt.Sprintf("%s: %s\n",
				tokenLabelStyle.Render(key),
				tokenValueStyle.Render(truncate(val, maxValWidth-len(key)-2))))
		}
	}

	for key, val := range claims {
		if !contains(displayKeys, key) {
			b.WriteString(fmt.Sprintf("%s: %s\n",
				tokenLabelStyle.Render(key),
				tokenValueStyle.Render(truncate(val, maxValWidth-len(key)-2))))
		}
	}

	return strings.TrimRight(b.String(), "\n")
}

func padRight(s string, n int) string {
	w := lipgloss.Width(s)
	if w >= n {
		return s
	}
	return s + strings.Repeat(" ", n-w)
}

func truncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return s
	}
	if len(s) > maxLen {
		return s[:maxLen-1] + "…"
	}
	return s
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
