package llm

import (
	"context"
	"fmt"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// Config holds LLM client configuration
type Config struct {
	APIKey    string `mapstructure:"api_key"`
	Model     string `mapstructure:"model"`
	MaxTokens int    `mapstructure:"max_tokens"`
	Timeout   int    `mapstructure:"timeout_seconds"`
}

// DefaultConfig returns sensible defaults for the LLM client
func DefaultConfig() Config {
	return Config{
		Model:     "claude-sonnet-4-20250514",
		MaxTokens: 4096,
		Timeout:   45,
	}
}

// Client wraps the Anthropic API client
type Client struct {
	client    anthropic.Client
	model     string
	maxTokens int
	timeout   time.Duration
}

// NewClient creates a new LLM client with the given configuration
func NewClient(cfg Config) (*Client, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("API key is required")
	}

	if cfg.Model == "" {
		cfg.Model = DefaultConfig().Model
	}
	if cfg.MaxTokens == 0 {
		cfg.MaxTokens = DefaultConfig().MaxTokens
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultConfig().Timeout
	}

	client := anthropic.NewClient(
		option.WithAPIKey(cfg.APIKey),
	)

	return &Client{
		client:    client,
		model:     cfg.Model,
		maxTokens: cfg.MaxTokens,
		timeout:   time.Duration(cfg.Timeout) * time.Second,
	}, nil
}

// Complete sends a message to the Claude API and returns the response
func (c *Client) Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	message, err := c.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(c.model),
		MaxTokens: int64(c.maxTokens),
		System: []anthropic.TextBlockParam{
			{Text: systemPrompt},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt)),
		},
	})
	if err != nil {
		return "", fmt.Errorf("API request failed: %w", err)
	}

	// Extract text content from response
	if len(message.Content) == 0 {
		return "", fmt.Errorf("empty response from API")
	}

	var result string
	for _, block := range message.Content {
		if block.Type == "text" {
			result += block.Text
		}
	}

	return result, nil
}

// Model returns the configured model name
func (c *Client) Model() string {
	return c.model
}
