package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenAICompatProvider implements the Provider interface for OpenAI-compatible APIs
// including OpenAI, Azure OpenAI, LiteLLM, vLLM, and other compatible services.
type OpenAICompatProvider struct {
	baseURL      string
	apiKey       string
	model        string
	maxTokens    int
	timeout      time.Duration
	client       *http.Client
	providerName string
}

// openAIChatRequest represents the request body for OpenAI chat completions API
type openAIChatRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
	Temperature float64         `json:"temperature,omitempty"`
}

// openAIMessage represents a message in the OpenAI chat format
type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// openAIChatResponse represents the response from OpenAI chat completions API
type openAIChatResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int           `json:"index"`
		Message      openAIMessage `json:"message"`
		FinishReason string        `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
	Error *openAIError `json:"error,omitempty"`
}

// openAIError represents an error response from the OpenAI API
type openAIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code"`
}

// NewOpenAICompatProvider creates a new OpenAI-compatible LLM provider
func NewOpenAICompatProvider(cfg Config) (*OpenAICompatProvider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("API key is required")
	}

	if cfg.BaseURL == "" {
		if cfg.Provider == ProviderLiteLLM {
			return nil, fmt.Errorf("base_url is required for LiteLLM provider")
		}
		cfg.BaseURL = DefaultOpenAIBaseURL
	}

	// Ensure base URL doesn't have trailing slash
	cfg.BaseURL = strings.TrimSuffix(cfg.BaseURL, "/")

	if cfg.Model == "" {
		switch cfg.Provider {
		case ProviderLiteLLM:
			cfg.Model = DefaultLiteLLMModel
		default:
			cfg.Model = DefaultOpenAIModel
		}
	}
	if cfg.MaxTokens == 0 {
		cfg.MaxTokens = DefaultMaxTokens
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}

	providerName := cfg.Provider
	if providerName == "" {
		providerName = ProviderOpenAI
	}

	return &OpenAICompatProvider{
		baseURL:      cfg.BaseURL,
		apiKey:       cfg.APIKey,
		model:        cfg.Model,
		maxTokens:    cfg.MaxTokens,
		timeout:      time.Duration(cfg.Timeout) * time.Second,
		client:       &http.Client{},
		providerName: providerName,
	}, nil
}

// Complete sends a message to the OpenAI-compatible API and returns the response
func (p *OpenAICompatProvider) Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	reqBody := openAIChatRequest{
		Model: p.model,
		Messages: []openAIMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		MaxTokens: p.maxTokens,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.baseURL+"/chat/completions", bytes.NewReader(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp openAIChatResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != nil {
			return "", fmt.Errorf("API error (%d): %s", resp.StatusCode, errResp.Error.Message)
		}
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var chatResp openAIChatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("empty response from API")
	}

	return chatResp.Choices[0].Message.Content, nil
}

// Model returns the configured model name
func (p *OpenAICompatProvider) Model() string {
	return p.model
}

// ProviderName returns the name of this provider
func (p *OpenAICompatProvider) ProviderName() string {
	return p.providerName
}

// Ensure OpenAICompatProvider implements Provider interface
var _ Provider = (*OpenAICompatProvider)(nil)
