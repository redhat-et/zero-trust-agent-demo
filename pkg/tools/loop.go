package tools

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/redhat-et/zero-trust-agent-demo/pkg/llm"
)

// LoopConfig controls the agentic loop behavior.
type LoopConfig struct {
	MaxIterations int
}

// DefaultLoopConfig returns sensible defaults.
func DefaultLoopConfig() LoopConfig {
	return LoopConfig{
		MaxIterations: 10,
	}
}

// RunToolLoop executes the agentic tool-use loop.
func RunToolLoop(ctx context.Context, provider llm.Provider,
	messages []llm.Message, registry *Registry,
	config LoopConfig) (string, error) {

	toolDefs := registry.Definitions()

	for i := 0; i < config.MaxIterations; i++ {
		resp, err := provider.CompleteWithTools(ctx, messages, toolDefs)
		if err != nil {
			return "", fmt.Errorf("LLM call failed: %w", err)
		}

		if !resp.HasToolCalls() {
			return resp.Content, nil
		}

		messages = append(messages, llm.Message{
			Role:      "assistant",
			Content:   resp.Content,
			ToolCalls: resp.ToolCalls,
		})

		var results []llm.ToolResultContent
		for _, tc := range resp.ToolCalls {
			result := executeTool(ctx, registry, tc, nil)
			results = append(results, llm.ToolResultContent{
				ToolUseID: tc.ID,
				Output:    result.Output,
				IsError:   result.Error,
			})
		}

		messages = append(messages, llm.Message{
			Role:        "tool",
			ToolResults: results,
		})
	}

	return "", fmt.Errorf("max iterations (%d) reached without final response", config.MaxIterations)
}

func executeTool(ctx context.Context, registry *Registry,
	tc llm.ToolCall, hook Hook) *ToolResult {

	if hook != nil {
		allow, reason := hook.BeforeToolCall(ctx, tc.Name, tc.Args)
		if !allow {
			slog.Warn("tool call denied by hook",
				"tool", tc.Name, "reason", reason)
			return Errorf("Tool call denied: %s", reason)
		}
	}

	tool, ok := registry.Get(tc.Name)
	if !ok {
		slog.Warn("unknown tool requested", "tool", tc.Name)
		return Errorf("Unknown tool: %s", tc.Name)
	}

	slog.Info("executing tool", "tool", tc.Name)
	result := tool.Execute(ctx, tc.Args)
	if result.Error {
		slog.Warn("tool returned error",
			"tool", tc.Name, "output", truncateLog(result.Output))
	}

	return result
}

func truncateLog(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
