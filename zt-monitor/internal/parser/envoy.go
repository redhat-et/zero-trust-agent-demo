package parser

import (
	"regexp"
	"strings"
	"time"
)

// Envoy ext-proc (kagenti go-processor) log patterns.
// Lines from the ext-proc start with a Go log timestamp: "2026/03/05 18:14:43 ..."
// Envoy's own C++ debug lines start with "[2026-03-05 ...][thread][level]" and are skipped.
var (
	// Go log prefix: "2026/03/05 18:14:43 " — capture and strip before matching.
	goLogPrefixRe = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+`)

	// Token exchange patterns (matched against the message after stripping timestamp)
	tokenExchangeStartRe   = regexp.MustCompile(`\[Token Exchange\]\s*Starting token exchange`)
	tokenExchangeSuccessRe = regexp.MustCompile(`\[Token Exchange\]\s*Successfully exchanged token`)
	tokenExchangeClientRe  = regexp.MustCompile(`\[Token Exchange\]\s*Client ID:\s*(.+)`)
	tokenExchangeAudRe     = regexp.MustCompile(`\[Token Exchange\]\s*(?:Target )?Audience:\s*(.+)`)
	tokenExchangeScopesRe  = regexp.MustCompile(`\[Token Exchange\]\s*(?:Target )?Scopes:\s*(.+)`)
	tokenExchangeURLRe     = regexp.MustCompile(`\[Token Exchange\]\s*Token URL:\s*(.+)`)
	tokenExchangeConfigRe  = regexp.MustCompile(`\[Token Exchange\]\s*Configuration loaded`)
	tokenExchangeNoAuthRe  = regexp.MustCompile(`\[Token Exchange\]\s*No Authorization header`)

	// Delegation patterns
	delegationUserRe  = regexp.MustCompile(`\[Delegation\]\s*X-Delegation-User:\s*(.+)`)
	delegationAgentRe = regexp.MustCompile(`\[Delegation\]\s*X-Delegation-Agent:\s*(.+)`)

	// Outbound request context
	outboundHeadersRe = regexp.MustCompile(`=== Outbound Request Headers ===`)
	authorityRe       = regexp.MustCompile(`:authority:\s*(.+)`)
	pathRe            = regexp.MustCompile(`:path:\s*(.+)`)
)

// ParseEnvoyLog parses an envoy ext-proc log line into an Event.
// Returns nil if the line doesn't match any known pattern.
func ParseEnvoyLog(line, source string) *Event {
	// Skip Envoy C++ debug lines (they start with "[timestamp][thread][level]")
	if strings.HasPrefix(line, "[") {
		return nil
	}

	// Extract and strip Go log timestamp prefix
	ts := time.Now()
	msg := line
	if m := goLogPrefixRe.FindStringSubmatch(line); m != nil {
		if parsed, err := time.Parse("2006/01/02 15:04:05", m[1]); err == nil {
			ts = parsed
		}
		msg = line[len(m[0]):]
	} else if !strings.Contains(line, "[Token") && !strings.Contains(line, "[Delegation") {
		// No timestamp prefix and no known markers — not an ext-proc line
		return nil
	}

	if msg == "" {
		return nil
	}

	ev := &Event{
		Time:      ts,
		Source:    source,
		Container: "envoy",
		Fields:    make(map[string]string),
	}

	switch {
	case tokenExchangeStartRe.MatchString(msg):
		ev.Type = EventTokenExchange
		ev.Message = "Token exchange starting"

	case tokenExchangeSuccessRe.MatchString(msg):
		ev.Type = EventTokenExchange
		if strings.Contains(msg, "replacing") {
			ev.Message = "Token exchanged, Authorization header replaced"
		} else {
			ev.Message = "Token exchange successful"
		}

	case tokenExchangeClientRe.MatchString(msg):
		m := tokenExchangeClientRe.FindStringSubmatch(msg)
		ev.Type = EventTokenExchange
		clientID := strings.TrimSpace(m[1])
		ev.Message = "Client: " + clientID
		ev.Fields["client_id"] = clientID

	case tokenExchangeAudRe.MatchString(msg):
		m := tokenExchangeAudRe.FindStringSubmatch(msg)
		ev.Type = EventTokenExchange
		aud := strings.TrimSpace(m[1])
		ev.Message = "Token exchange -> " + aud
		ev.Fields["audience"] = aud

	case tokenExchangeScopesRe.MatchString(msg):
		m := tokenExchangeScopesRe.FindStringSubmatch(msg)
		ev.Type = EventTokenExchange
		ev.Message = "Scopes: " + strings.TrimSpace(m[1])
		ev.Fields["scopes"] = strings.TrimSpace(m[1])

	case tokenExchangeURLRe.MatchString(msg):
		m := tokenExchangeURLRe.FindStringSubmatch(msg)
		ev.Type = EventTokenExchange
		ev.Message = "Token URL: " + strings.TrimSpace(m[1])
		ev.Fields["token_url"] = strings.TrimSpace(m[1])

	case tokenExchangeConfigRe.MatchString(msg):
		ev.Type = EventTokenExchange
		ev.Message = "Token exchange config loaded"

	case tokenExchangeNoAuthRe.MatchString(msg):
		ev.Type = EventTokenExchange
		ev.Message = "No Authorization header (skipped)"

	case delegationUserRe.MatchString(msg):
		m := delegationUserRe.FindStringSubmatch(msg)
		ev.Type = EventDelegation
		user := strings.TrimSpace(m[1])
		ev.Message = "Delegation user: " + user
		ev.Fields["delegation_user"] = user

	case delegationAgentRe.MatchString(msg):
		m := delegationAgentRe.FindStringSubmatch(msg)
		ev.Type = EventDelegation
		agent := strings.TrimSpace(m[1])
		ev.Message = "Delegation agent: " + agent
		ev.Fields["delegation_agent"] = agent

	case outboundHeadersRe.MatchString(msg):
		ev.Type = EventFlow
		ev.Message = "Outbound request"

	case authorityRe.MatchString(msg):
		m := authorityRe.FindStringSubmatch(msg)
		ev.Type = EventFlow
		target := strings.TrimSpace(m[1])
		ev.Message = "-> " + target
		ev.Fields["target"] = target

	case pathRe.MatchString(msg):
		m := pathRe.FindStringSubmatch(msg)
		ev.Type = EventFlow
		path := strings.TrimSpace(m[1])
		ev.Message = "Path: " + path
		ev.Fields["path"] = path

	default:
		// Catch-all for any other [Token Exchange] or [Delegation] lines
		lower := strings.ToLower(msg)
		if strings.Contains(lower, "[token exchange]") || strings.Contains(lower, "[token") {
			ev.Type = EventTokenExchange
			ev.Message = strings.TrimSpace(msg)
		} else if strings.Contains(lower, "[delegation]") {
			ev.Type = EventDelegation
			ev.Message = strings.TrimSpace(msg)
		} else {
			return nil
		}
	}

	return ev
}
