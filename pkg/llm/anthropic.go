package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// AnthropicProvider wraps the Anthropic API client
type AnthropicProvider struct {
	client    anthropic.Client
	model     string
	maxTokens int
	timeout   time.Duration
}

// NewAnthropicProvider creates a new Anthropic LLM provider with the given configuration
func NewAnthropicProvider(cfg Config) (*AnthropicProvider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("API key is required")
	}

	if cfg.Model == "" {
		cfg.Model = DefaultAnthropicModel
	}
	if cfg.MaxTokens == 0 {
		cfg.MaxTokens = DefaultMaxTokens
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}

	client := anthropic.NewClient(
		option.WithAPIKey(cfg.APIKey),
	)

	return &AnthropicProvider{
		client:    client,
		model:     cfg.Model,
		maxTokens: cfg.MaxTokens,
		timeout:   time.Duration(cfg.Timeout) * time.Second,
	}, nil
}

// Complete sends a message to the Claude API and returns the response
func (p *AnthropicProvider) Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	message, err := p.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(p.model),
		MaxTokens: int64(p.maxTokens),
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

// CompleteWithTools sends a multi-turn conversation with tool
// definitions to the Anthropic API.
func (p *AnthropicProvider) CompleteWithTools(ctx context.Context,
	messages []Message, tools []ToolDefinition) (*Response, error) {

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	// Convert messages to Anthropic format
	var anthropicMsgs []anthropic.MessageParam
	var systemPrompt string

	for _, msg := range messages {
		switch msg.Role {
		case "system":
			systemPrompt = msg.Content
		case "user":
			anthropicMsgs = append(anthropicMsgs,
				anthropic.NewUserMessage(anthropic.NewTextBlock(msg.Content)))
		case "assistant":
			var blocks []anthropic.ContentBlockParamUnion
			if msg.Content != "" {
				blocks = append(blocks, anthropic.NewTextBlock(msg.Content))
			}
			for _, tc := range msg.ToolCalls {
				blocks = append(blocks, anthropic.NewToolUseBlock(tc.ID, tc.Args, tc.Name))
			}
			anthropicMsgs = append(anthropicMsgs,
				anthropic.MessageParam{Role: "assistant", Content: blocks})
		case "tool":
			var blocks []anthropic.ContentBlockParamUnion
			for _, tr := range msg.ToolResults {
				blocks = append(blocks, anthropic.NewToolResultBlock(
					tr.ToolUseID, tr.Output, tr.IsError))
			}
			anthropicMsgs = append(anthropicMsgs,
				anthropic.MessageParam{Role: "user", Content: blocks})
		}
	}

	// Convert tool definitions
	var anthropicTools []anthropic.ToolUnionParam
	for _, td := range tools {
		// Extract properties and required from the parameters map
		properties := td.Parameters["properties"]
		required, _ := td.Parameters["required"].([]string)

		schema := anthropic.ToolInputSchemaParam{
			Properties: properties,
			Required:   required,
		}

		tool := anthropic.ToolUnionParam{
			OfTool: &anthropic.ToolParam{
				Name:        td.Name,
				Description: anthropic.String(td.Description),
				InputSchema: schema,
			},
		}
		anthropicTools = append(anthropicTools, tool)
	}

	// Build params
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(p.model),
		MaxTokens: int64(p.maxTokens),
		Messages:  anthropicMsgs,
		Tools:     anthropicTools,
	}
	if systemPrompt != "" {
		params.System = []anthropic.TextBlockParam{{Text: systemPrompt}}
	}

	message, err := p.client.Messages.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	// Parse response
	resp := &Response{}
	switch message.StopReason {
	case "tool_use":
		resp.StopReason = StopReasonToolUse
	default:
		resp.StopReason = StopReasonEndTurn
	}

	for _, block := range message.Content {
		switch block.Type {
		case "text":
			resp.Content += block.Text
		case "tool_use":
			// Parse the JSON RawMessage input into a map
			var args map[string]any
			if len(block.Input) > 0 {
				if err := json.Unmarshal(block.Input, &args); err != nil {
					return nil, fmt.Errorf("failed to parse tool input: %w", err)
				}
			}
			resp.ToolCalls = append(resp.ToolCalls, ToolCall{
				ID:   block.ID,
				Name: block.Name,
				Args: args,
			})
		}
	}

	return resp, nil
}

// Model returns the configured model name
func (p *AnthropicProvider) Model() string {
	return p.model
}

// ProviderName returns the name of this provider
func (p *AnthropicProvider) ProviderName() string {
	return ProviderAnthropic
}

// Ensure AnthropicProvider implements Provider interface
var _ Provider = (*AnthropicProvider)(nil)
