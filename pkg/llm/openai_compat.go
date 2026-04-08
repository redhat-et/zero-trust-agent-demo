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

// openAIToolCall represents a tool call in the OpenAI response.
type openAIToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"` // JSON string
	} `json:"function"`
}

// openAIToolDef represents a tool definition for the OpenAI API.
type openAIToolDef struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

// openAIChatRequestWithTools extends the request with tools support.
type openAIChatRequestWithTools struct {
	Model     string            `json:"model"`
	Messages  []json.RawMessage `json:"messages"`
	Tools     []openAIToolDef   `json:"tools,omitempty"`
	MaxTokens int               `json:"max_tokens,omitempty"`
}

// openAIChatResponseWithTools extends the response with tool calls.
type openAIChatResponseWithTools struct {
	Choices []struct {
		Message struct {
			Role      string           `json:"role"`
			Content   *string          `json:"content"`
			ToolCalls []openAIToolCall `json:"tool_calls,omitempty"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Error *openAIError `json:"error,omitempty"`
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

// CompleteWithTools sends a multi-turn conversation with tool
// definitions to the OpenAI-compatible API.
func (p *OpenAICompatProvider) CompleteWithTools(ctx context.Context,
	messages []Message, tools []ToolDefinition) (*Response, error) {

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	// Convert messages to OpenAI format
	var openaiMsgs []json.RawMessage
	for _, msg := range messages {
		var raw []byte
		var err error

		switch msg.Role {
		case "system", "user":
			raw, err = json.Marshal(map[string]string{
				"role":    msg.Role,
				"content": msg.Content,
			})
		case "assistant":
			assistantMsg := map[string]any{
				"role": "assistant",
			}
			if msg.Content != "" {
				assistantMsg["content"] = msg.Content
			}
			if len(msg.ToolCalls) > 0 {
				var tcs []openAIToolCall
				for _, tc := range msg.ToolCalls {
					argsJSON, _ := json.Marshal(tc.Args)
					tcs = append(tcs, openAIToolCall{
						ID:   tc.ID,
						Type: "function",
						Function: struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						}{
							Name:      tc.Name,
							Arguments: string(argsJSON),
						},
					})
				}
				assistantMsg["tool_calls"] = tcs
			}
			raw, err = json.Marshal(assistantMsg)
		case "tool":
			for _, tr := range msg.ToolResults {
				toolMsg, _ := json.Marshal(map[string]string{
					"role":         "tool",
					"tool_call_id": tr.ToolUseID,
					"content":      tr.Output,
				})
				openaiMsgs = append(openaiMsgs, toolMsg)
			}
			continue
		}

		if err != nil {
			return nil, fmt.Errorf("failed to marshal message: %w", err)
		}
		openaiMsgs = append(openaiMsgs, raw)
	}

	// Convert tool definitions
	var openaiTools []openAIToolDef
	for _, td := range tools {
		def := openAIToolDef{Type: "function"}
		def.Function.Name = td.Name
		def.Function.Description = td.Description
		def.Function.Parameters = td.Parameters
		openaiTools = append(openaiTools, def)
	}

	reqBody := openAIChatRequestWithTools{
		Model:     p.model,
		Messages:  openaiMsgs,
		Tools:     openaiTools,
		MaxTokens: p.maxTokens,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.baseURL+"/chat/completions", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	httpResp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d: %s",
			httpResp.StatusCode, string(body))
	}

	var chatResp openAIChatResponseWithTools
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("empty response from API")
	}

	choice := chatResp.Choices[0]
	resp := &Response{}

	if choice.FinishReason == "tool_calls" {
		resp.StopReason = StopReasonToolUse
	} else {
		resp.StopReason = StopReasonEndTurn
	}

	if choice.Message.Content != nil {
		resp.Content = *choice.Message.Content
	}

	for _, tc := range choice.Message.ToolCalls {
		var args map[string]any
		if err := json.Unmarshal([]byte(tc.Function.Arguments), &args); err != nil {
			args = map[string]any{"_raw": tc.Function.Arguments}
		}
		resp.ToolCalls = append(resp.ToolCalls, ToolCall{
			ID:   tc.ID,
			Name: tc.Function.Name,
			Args: args,
		})
	}

	return resp, nil
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
