package llm

// Config holds LLM client configuration
type Config struct {
	Provider  string `mapstructure:"provider"`        // "anthropic", "openai", "litellm"
	APIKey    string `mapstructure:"api_key"`         // API key for the provider
	BaseURL   string `mapstructure:"base_url"`        // Base URL for OpenAI-compatible APIs
	Model     string `mapstructure:"model"`           // Model name to use
	MaxTokens int    `mapstructure:"max_tokens"`      // Maximum tokens in response
	Timeout   int    `mapstructure:"timeout_seconds"` // Request timeout in seconds
}

// Provider defaults
const (
	ProviderAnthropic = "anthropic"
	ProviderOpenAI    = "openai"
	ProviderLiteLLM   = "litellm"

	DefaultAnthropicModel = "claude-sonnet-4-20250514"
	DefaultOpenAIModel    = "gpt-4o"
	DefaultLiteLLMModel   = "qwen3-14b"
	DefaultOpenAIBaseURL  = "https://api.openai.com/v1"

	DefaultMaxTokens = 4096
	DefaultTimeout   = 45
)

// DefaultConfig returns sensible defaults for the LLM client
func DefaultConfig() Config {
	return Config{
		Provider:  ProviderAnthropic,
		Model:     DefaultAnthropicModel,
		MaxTokens: DefaultMaxTokens,
		Timeout:   DefaultTimeout,
	}
}

// DefaultConfigForProvider returns defaults for a specific provider
func DefaultConfigForProvider(provider string) Config {
	cfg := DefaultConfig()
	cfg.Provider = provider

	switch provider {
	case ProviderAnthropic, "":
		cfg.Model = DefaultAnthropicModel
	case ProviderOpenAI:
		cfg.Model = DefaultOpenAIModel
		cfg.BaseURL = DefaultOpenAIBaseURL
	case ProviderLiteLLM:
		cfg.Model = DefaultLiteLLMModel
		// BaseURL must be set by user for LiteLLM
	}

	return cfg
}
