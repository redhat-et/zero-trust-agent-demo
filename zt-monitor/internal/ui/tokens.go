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

	beforeBox := renderClaimBox("Before", tp.Before, halfWidth)
	afterBox := renderClaimBox("After", tp.After, halfWidth)

	// Side by side
	beforeLines := strings.Split(beforeBox, "\n")
	afterLines := strings.Split(afterBox, "\n")

	maxLines := len(beforeLines)
	if len(afterLines) > maxLines {
		maxLines = len(afterLines)
	}

	for i := range maxLines {
		left := ""
		if i < len(beforeLines) {
			left = beforeLines[i]
		}
		right := ""
		if i < len(afterLines) {
			right = afterLines[i]
		}

		// Pad left to fixed width
		left = padRight(left, halfWidth)

		b.WriteString("  ")
		b.WriteString(left)
		b.WriteString("  ")
		b.WriteString(right)
		b.WriteString("\n")
	}

	return b.String()
}

func renderClaimBox(title string, claims map[string]string, width int) string {
	var b strings.Builder

	header := tokenLabelStyle.Render(fmt.Sprintf("┌─ %s ", title))
	remaining := width - len(fmt.Sprintf("┌─ %s ", title))
	if remaining > 0 {
		header += tokenLabelStyle.Render(strings.Repeat("─", remaining) + "┐")
	}
	b.WriteString(header)
	b.WriteString("\n")

	displayKeys := []string{"aud", "azp", "sub", "iss", "exp", "scope"}
	for _, key := range displayKeys {
		if val, ok := claims[key]; ok {
			line := fmt.Sprintf("│ %s: %s", key,
				tokenValueStyle.Render(truncate(val, width-len(key)-6)))
			b.WriteString(tokenLabelStyle.Render("│ "))
			b.WriteString(fmt.Sprintf("%s: %s",
				tokenLabelStyle.Render(key),
				tokenValueStyle.Render(truncate(val, width-len(key)-6))))
			_ = line
			b.WriteString("\n")
		}
	}

	// Any remaining keys not in displayKeys
	for key, val := range claims {
		if !contains(displayKeys, key) {
			b.WriteString(tokenLabelStyle.Render("│ "))
			b.WriteString(fmt.Sprintf("%s: %s",
				tokenLabelStyle.Render(key),
				tokenValueStyle.Render(truncate(val, width-len(key)-6))))
			b.WriteString("\n")
		}
	}

	footer := tokenLabelStyle.Render("└" + strings.Repeat("─", width-1) + "┘")
	b.WriteString(footer)

	return b.String()
}

func padRight(s string, n int) string {
	// Count visible length (strip ANSI)
	visible := stripANSI(s)
	if len(visible) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(visible))
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

// stripANSI removes ANSI escape sequences for length calculation.
func stripANSI(s string) string {
	var b strings.Builder
	inEsc := false
	for _, r := range s {
		if r == '\033' {
			inEsc = true
			continue
		}
		if inEsc {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEsc = false
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
