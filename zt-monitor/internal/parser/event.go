package parser

import (
	"fmt"
	"time"
)

// EventType classifies the kind of zero-trust flow event.
type EventType int

const (
	EventDelegation     EventType = iota // user delegates to agent
	EventTokenExchange                   // envoy exchanges token
	EventAccessDecision                  // ALLOW or DENY
	EventA2AInvoke                       // agent calls A2A agent
	EventDocumentFetch                   // document retrieved
	EventFlow                            // generic flow message
	EventUnknown                         // unrecognized log line
)

func (t EventType) String() string {
	switch t {
	case EventDelegation:
		return "DELEGATION"
	case EventTokenExchange:
		return "TOKEN-EXCHANGE"
	case EventAccessDecision:
		return "ACCESS"
	case EventA2AInvoke:
		return "A2A-INVOKE"
	case EventDocumentFetch:
		return "DOCUMENT"
	case EventFlow:
		return "FLOW"
	default:
		return "UNKNOWN"
	}
}

// Event represents a parsed log event from a Kubernetes pod.
type Event struct {
	Time      time.Time
	Source    string            // service name (e.g., "agent-service")
	Container string           // container name (e.g., "envoy-proxy")
	Type      EventType
	Message   string
	Fields    map[string]string // parsed key=value pairs
	Allowed   *bool             // for access decisions: true=allow, false=deny
}

// Summary returns a short display string for the event.
func (e Event) Summary() string {
	ts := e.Time.Format("15:04:05")
	label := e.Source
	if e.Container != "" && e.Container != e.Source {
		label = e.Container
	}
	return fmt.Sprintf("%s [%-12s] %s", ts, label, e.Message)
}
