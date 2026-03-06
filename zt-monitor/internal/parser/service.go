package parser

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// jsonLog represents a structured JSON log line from our services.
type jsonLog struct {
	Time      string `json:"time"`
	Level     string `json:"level"`
	Msg       string `json:"msg"`
	Component string `json:"component"`
}

// serviceLogRe matches the colored logger format (local dev):
//
//	{ANSI}{emoji} [{COMPONENT}]{ANSI} {message} key=value ...
var serviceLogRe = regexp.MustCompile(`\[([A-Z][-A-Z]*)\]\s*(.*)`)

// kvRe matches key=value pairs at the end of log lines.
var kvRe = regexp.MustCompile(`(\w+)=(\S+)`)

// ParseServiceLog parses a service log line into an Event.
// Supports both JSON format (k8s) and colored text format (local dev).
// Returns nil if the line doesn't match the expected format.
func ParseServiceLog(line, source string) *Event {
	// Try JSON first (k8s structured logs)
	if strings.HasPrefix(strings.TrimSpace(line), "{") {
		return parseJSONLog(line, source)
	}

	// Fall back to colored text format (local dev)
	return parseTextLog(line, source)
}

func parseJSONLog(line, source string) *Event {
	var jl jsonLog
	if err := json.Unmarshal([]byte(line), &jl); err != nil {
		return nil
	}

	if jl.Msg == "" {
		return nil
	}

	ts := time.Now()
	if jl.Time != "" {
		if parsed, err := time.Parse(time.RFC3339, jl.Time); err == nil {
			ts = parsed
		}
	}

	ev := &Event{
		Time:   ts,
		Source: source,
		Fields: make(map[string]string),
	}

	// Parse extra fields from the raw JSON
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err == nil {
		for k, v := range raw {
			switch k {
			case "time", "level", "msg", "component":
				continue
			default:
				if s, ok := v.(string); ok {
					ev.Fields[k] = s
				}
			}
		}
	}

	// Use component for source label
	if jl.Component != "" {
		ev.Source = componentToService(jl.Component)
	}

	classifyMessage(ev, jl.Msg)
	return ev
}

func parseTextLog(line, source string) *Event {
	m := serviceLogRe.FindStringSubmatch(line)
	if m == nil {
		return nil
	}

	component := m[1]
	body := m[2]

	// Strip any trailing ANSI reset codes from body
	body = stripANSICodes(body)

	ev := &Event{
		Time:   time.Now(),
		Source: source,
		Fields: parseKV(body),
	}

	if component != "" {
		ev.Source = componentToService(component)
	}

	classifyMessage(ev, body)
	return ev
}

// stripANSICodes removes ANSI escape sequences from a string.
var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSICodes(s string) string {
	return ansiRe.ReplaceAllString(s, "")
}

func classifyMessage(ev *Event, body string) {
	lower := strings.ToLower(body)

	switch {
	// Access decisions
	case strings.Contains(body, "ALLOW:"):
		ev.Type = EventAccessDecision
		ev.Message = body
		allowed := true
		ev.Allowed = &allowed

	case strings.Contains(body, "DENY:") || strings.Contains(body, "\u274C"):
		ev.Type = EventAccessDecision
		ev.Message = body
		denied := false
		ev.Allowed = &denied

	// Delegation
	case strings.Contains(lower, "delegation") ||
		strings.Contains(lower, "delegated"):
		ev.Type = EventDelegation
		ev.Message = body

	// A2A invocation
	case strings.Contains(lower, "a2a") ||
		strings.Contains(lower, "invoke"):
		ev.Type = EventA2AInvoke
		ev.Message = body

	// Document fetch
	case strings.Contains(body, "[DOC-") ||
		strings.Contains(lower, "document"):
		ev.Type = EventDocumentFetch
		ev.Message = body

	// Flow messages (directional arrows)
	case strings.HasPrefix(body, "-> ") || strings.HasPrefix(body, "<- "):
		ev.Type = EventFlow
		ev.Message = body

	// Section headers (skip)
	case strings.Contains(body, "══"):
		ev.Type = EventUnknown

	// Empty lines (skip)
	case strings.TrimSpace(body) == "":
		ev.Type = EventUnknown

	default:
		ev.Type = EventUnknown
		ev.Message = body
	}
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
