package llm

import "context"

// Provider defines the interface for LLM providers
type Provider interface {
	// Complete sends a message to the LLM and returns the response
	Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error)

	// Model returns the configured model name
	Model() string

	// ProviderName returns the name of the LLM provider (e.g., "anthropic", "openai")
	ProviderName() string
}
