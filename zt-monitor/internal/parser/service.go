package parser

import (
	"regexp"
	"strings"
	"time"
)

// serviceLogRe matches the colored logger format:
//
//	{emoji} [{COMPONENT}] {message} key=value ...
var serviceLogRe = regexp.MustCompile(`^.{1,4}\s*\[([A-Z][-A-Z]*)\]\s*(.*)$`)

// kvRe matches key=value pairs at the end of log lines.
var kvRe = regexp.MustCompile(`(\w+)=(\S+)`)

// ParseServiceLog parses a service log line into an Event.
// Returns nil if the line doesn't match the expected format.
func ParseServiceLog(line, source string) *Event {
	m := serviceLogRe.FindStringSubmatch(line)
	if m == nil {
		return nil
	}

	component := m[1]
	body := m[2]

	ev := &Event{
		Time:   time.Now(),
		Source: source,
		Fields: parseKV(body),
	}

	switch {
	// Access decisions
	case strings.Contains(body, "ALLOW:"):
		ev.Type = EventAccessDecision
		ev.Message = body
		allowed := true
		ev.Allowed = &allowed

	case strings.Contains(body, "DENY:") || strings.HasPrefix(body, "\u274C"):
		ev.Type = EventAccessDecision
		ev.Message = body
		denied := false
		ev.Allowed = &denied

	// Delegation
	case strings.Contains(strings.ToLower(body), "delegation") ||
		strings.Contains(strings.ToLower(body), "delegated"):
		ev.Type = EventDelegation
		ev.Message = body

	// A2A invocation
	case strings.Contains(strings.ToLower(body), "a2a") ||
		strings.Contains(strings.ToLower(body), "invoke"):
		ev.Type = EventA2AInvoke
		ev.Message = body

	// Document fetch
	case strings.Contains(body, "[DOC-") ||
		strings.Contains(strings.ToLower(body), "document"):
		ev.Type = EventDocumentFetch
		ev.Message = body

	// Flow messages (directional arrows)
	case strings.HasPrefix(body, "-> ") || strings.HasPrefix(body, "<- "):
		ev.Type = EventFlow
		ev.Message = body

	// Section headers (skip)
	case strings.Contains(body, "══"):
		return nil

	// Empty lines (skip)
	case strings.TrimSpace(body) == "":
		return nil

	default:
		ev.Type = EventUnknown
		ev.Message = body
	}

	// Use component as source label if no better one
	if component != "" {
		ev.Source = componentToService(component)
	}

	return ev
}

func parseKV(s string) map[string]string {
	result := make(map[string]string)
	matches := kvRe.FindAllStringSubmatch(s, -1)
	for _, m := range matches {
		result[m[1]] = m[2]
	}
	return result
}

func componentToService(component string) string {
	switch component {
	case "USER-SERVICE":
		return "user-svc"
	case "AGENT-SERVICE":
		return "agent-svc"
	case "DOC-SERVICE":
		return "doc-svc"
	case "OPA-SERVICE":
		return "opa"
	case "DASHBOARD":
		return "dashboard"
	case "SUMMARIZER":
		return "summarizer"
	case "REVIEWER":
		return "reviewer"
	case "OPA-QUERY", "OPA-EVAL", "OPA-DECISION":
		return "opa"
	default:
		return strings.ToLower(component)
	}
}
