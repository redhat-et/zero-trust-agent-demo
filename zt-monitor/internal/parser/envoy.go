package parser

import (
	"regexp"
	"strings"
	"time"
)

// Envoy ext-proc (kagenti go-processor) log patterns.
var (
	tokenExchangeStartRe = regexp.MustCompile(`\[Token Exchange\]\s*Starting token exchange for audience:\s*(.+)`)
	tokenExchangeClientRe = regexp.MustCompile(`\[Token Exchange\]\s*Client ID:\s*(.+)`)
	tokenExchangeSuccessRe = regexp.MustCompile(`\[Token Exchange\]\s*Successfully exchanged token`)
	delegationUserRe      = regexp.MustCompile(`\[Delegation\]\s*X-Delegation-User:\s*(.+)`)
	delegationAgentRe     = regexp.MustCompile(`\[Delegation\]\s*X-Delegation-Agent:\s*(.+)`)
	tokenClaimRe          = regexp.MustCompile(`\[Token Exchange\]\s*(Before|After)\s+exchange\s*[-:]?\s*(.+)`)
)

// ParseEnvoyLog parses an envoy ext-proc log line into an Event.
// Returns nil if the line doesn't match any known pattern.
func ParseEnvoyLog(line, source string) *Event {
	ev := &Event{
		Time:      time.Now(),
		Source:    source,
		Container: "envoy",
		Fields:    make(map[string]string),
	}

	switch {
	case tokenExchangeStartRe.MatchString(line):
		m := tokenExchangeStartRe.FindStringSubmatch(line)
		ev.Type = EventTokenExchange
		ev.Message = "Token exchange → " + strings.TrimSpace(m[1])
		ev.Fields["audience"] = strings.TrimSpace(m[1])

	case tokenExchangeClientRe.MatchString(line):
		m := tokenExchangeClientRe.FindStringSubmatch(line)
		ev.Type = EventTokenExchange
		ev.Message = "Client: " + strings.TrimSpace(m[1])
		ev.Fields["client_id"] = strings.TrimSpace(m[1])

	case tokenExchangeSuccessRe.MatchString(line):
		ev.Type = EventTokenExchange
		ev.Message = "Token exchange successful"

	case delegationUserRe.MatchString(line):
		m := delegationUserRe.FindStringSubmatch(line)
		ev.Type = EventDelegation
		ev.Message = "Delegation user: " + strings.TrimSpace(m[1])
		ev.Fields["delegation_user"] = strings.TrimSpace(m[1])

	case delegationAgentRe.MatchString(line):
		m := delegationAgentRe.FindStringSubmatch(line)
		ev.Type = EventDelegation
		ev.Message = "Delegation agent: " + strings.TrimSpace(m[1])
		ev.Fields["delegation_agent"] = strings.TrimSpace(m[1])

	case tokenClaimRe.MatchString(line):
		m := tokenClaimRe.FindStringSubmatch(line)
		ev.Type = EventTokenExchange
		phase := strings.ToLower(strings.TrimSpace(m[1]))
		claims := strings.TrimSpace(m[2])
		ev.Message = phase + ": " + claims
		ev.Fields["phase"] = phase
		ev.Fields["claims"] = claims
		// Try to extract individual claims
		for _, kv := range kvRe.FindAllStringSubmatch(claims, -1) {
			ev.Fields[phase+"_"+kv[1]] = kv[2]
		}

	default:
		// Check for generic token/delegation keywords
		lower := strings.ToLower(line)
		if strings.Contains(lower, "token exchange") || strings.Contains(lower, "[token") {
			ev.Type = EventTokenExchange
			ev.Message = strings.TrimSpace(line)
		} else if strings.Contains(lower, "delegation") {
			ev.Type = EventDelegation
			ev.Message = strings.TrimSpace(line)
		} else {
			return nil
		}
	}

	return ev
}
