package llm

import "fmt"

// NewProvider creates a new LLM provider based on the configuration.
// It dispatches to the appropriate provider implementation based on cfg.Provider:
//   - "anthropic" or "": Creates an AnthropicProvider (default)
//   - "openai": Creates an OpenAICompatProvider with OpenAI defaults
//   - "litellm": Creates an OpenAICompatProvider for LiteLLM (requires BaseURL)
func NewProvider(cfg Config) (Provider, error) {
	switch cfg.Provider {
	case ProviderAnthropic, "":
		return NewAnthropicProvider(cfg)
	case ProviderOpenAI, ProviderLiteLLM:
		return NewOpenAICompatProvider(cfg)
	default:
		return nil, fmt.Errorf("unknown LLM provider: %s", cfg.Provider)
	}
}
