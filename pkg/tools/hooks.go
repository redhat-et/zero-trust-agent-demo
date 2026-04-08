package tools

import "context"

// Hook allows external systems to intercept tool calls.
type Hook interface {
	BeforeToolCall(ctx context.Context, name string,
		args map[string]any) (allow bool, reason string)
}
