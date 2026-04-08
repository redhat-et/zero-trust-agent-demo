package llm

import "context"

// Provider defines the interface for LLM providers
type Provider interface {
	// Complete sends a message to the LLM and returns the response
	Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error)

	// CompleteWithTools sends a multi-turn conversation with tool
	// definitions and returns a response that may contain tool calls.
	CompleteWithTools(ctx context.Context, messages []Message,
		tools []ToolDefinition) (*Response, error)

	// Model returns the configured model name
	Model() string

	// ProviderName returns the name of the LLM provider (e.g., "anthropic", "openai")
	ProviderName() string
}
