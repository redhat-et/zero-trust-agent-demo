package tools

import (
	"context"
	"testing"

	"github.com/redhat-et/zero-trust-agent-demo/pkg/llm"
)

// mockProvider implements llm.Provider for testing the loop.
type mockProvider struct {
	responses []*llm.Response
	callIdx   int
}

func (m *mockProvider) Complete(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

func (m *mockProvider) CompleteWithTools(_ context.Context, _ []llm.Message, _ []llm.ToolDefinition) (*llm.Response, error) {
	if m.callIdx >= len(m.responses) {
		return &llm.Response{StopReason: llm.StopReasonEndTurn, Content: "done"}, nil
	}
	resp := m.responses[m.callIdx]
	m.callIdx++
	return resp, nil
}

func (m *mockProvider) Model() string        { return "mock" }
func (m *mockProvider) ProviderName() string { return "mock" }

func TestRunToolLoopNoTools(t *testing.T) {
	provider := &mockProvider{
		responses: []*llm.Response{
			{StopReason: llm.StopReasonEndTurn, Content: "Hello!"},
		},
	}
	registry := NewRegistry(nil)
	messages := []llm.Message{
		{Role: "user", Content: "Say hello"},
	}

	result, err := RunToolLoop(context.Background(), provider, messages,
		registry, DefaultLoopConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Hello!" {
		t.Fatalf("expected 'Hello!', got %q", result)
	}
}

func TestRunToolLoopWithToolCall(t *testing.T) {
	provider := &mockProvider{
		responses: []*llm.Response{
			{
				StopReason: llm.StopReasonToolUse,
				Content:    "I'll check that.",
				ToolCalls: []llm.ToolCall{
					{ID: "tc1", Name: "test_tool", Args: map[string]any{}},
				},
			},
			{
				StopReason: llm.StopReasonEndTurn,
				Content:    "The result is: ok",
			},
		},
	}

	registry := NewRegistry(nil)
	registry.Register(&mockTool{name: "test_tool", output: "ok"})

	messages := []llm.Message{
		{Role: "user", Content: "Use the tool"},
	}

	result, err := RunToolLoop(context.Background(), provider, messages,
		registry, DefaultLoopConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "The result is: ok" {
		t.Fatalf("expected 'The result is: ok', got %q", result)
	}
}

func TestRunToolLoopMaxIterations(t *testing.T) {
	provider := &mockProvider{
		responses: make([]*llm.Response, 20),
	}
	for i := range provider.responses {
		provider.responses[i] = &llm.Response{
			StopReason: llm.StopReasonToolUse,
			ToolCalls: []llm.ToolCall{
				{ID: "tc", Name: "test_tool", Args: map[string]any{}},
			},
		}
	}

	registry := NewRegistry(nil)
	registry.Register(&mockTool{name: "test_tool", output: "ok"})

	cfg := DefaultLoopConfig()
	cfg.MaxIterations = 3

	messages := []llm.Message{
		{Role: "user", Content: "Loop forever"},
	}

	_, err := RunToolLoop(context.Background(), provider, messages,
		registry, cfg)
	if err == nil {
		t.Fatal("expected error for max iterations")
	}
}

func TestRunToolLoopUnknownTool(t *testing.T) {
	provider := &mockProvider{
		responses: []*llm.Response{
			{
				StopReason: llm.StopReasonToolUse,
				ToolCalls: []llm.ToolCall{
					{ID: "tc1", Name: "nonexistent", Args: map[string]any{}},
				},
			},
			{
				StopReason: llm.StopReasonEndTurn,
				Content:    "Tool not found, sorry.",
			},
		},
	}

	registry := NewRegistry(nil)
	messages := []llm.Message{
		{Role: "user", Content: "Use unknown tool"},
	}

	result, err := RunToolLoop(context.Background(), provider, messages,
		registry, DefaultLoopConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Tool not found, sorry." {
		t.Fatalf("expected error recovery response, got %q", result)
	}
}
