package tools

import (
	"context"
	"fmt"
)

// Tool defines the interface for an executable tool.
type Tool interface {
	Name() string
	Description() string
	Parameters() map[string]any
	Execute(ctx context.Context, args map[string]any) *ToolResult
}

// ToolResult holds the output of a tool execution.
type ToolResult struct {
	Output string
	Error  bool
}

// OK creates a successful tool result.
func OK(output string) *ToolResult {
	return &ToolResult{Output: output}
}

// Errorf creates an error tool result.
func Errorf(format string, args ...any) *ToolResult {
	return &ToolResult{
		Output: fmt.Sprintf(format, args...),
		Error:  true,
	}
}
