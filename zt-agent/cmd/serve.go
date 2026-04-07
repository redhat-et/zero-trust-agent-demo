package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/a2aproject/a2a-go/a2a"
)

// loadSystemPrompt reads the system prompt from config-dir/system-prompt.txt.
// Returns an error if the file does not exist.
func loadSystemPrompt(configDir string) (string, error) {
	path := filepath.Join(configDir, "system-prompt.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read system prompt: %w", err)
	}
	prompt := strings.TrimSpace(string(data))
	if prompt == "" {
		return "", fmt.Errorf("system prompt is empty: %s", path)
	}
	return prompt, nil
}

// loadAgentCard reads the agent card from config-dir/agent-card.json.
// If the file does not exist, returns a minimal fallback card.
func loadAgentCard(configDir string) (*a2a.AgentCard, error) {
	path := filepath.Join(configDir, "agent-card.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &a2a.AgentCard{
				Name:               "zt-agent",
				Description:        "Zero Trust Agent",
				Version:            "1.0.0",
				ProtocolVersion:    "0.3.0",
				Capabilities:       a2a.AgentCapabilities{},
				DefaultInputModes:  []string{"application/json"},
				DefaultOutputModes: []string{"text/plain"},
			}, nil
		}
		return nil, fmt.Errorf("failed to read agent card: %w", err)
	}

	var card a2a.AgentCard
	if err := json.Unmarshal(data, &card); err != nil {
		return nil, fmt.Errorf("failed to parse agent card: %w", err)
	}
	return &card, nil
}

// loadPromptVariants reads optional prompt variants from
// config-dir/prompts.json. Returns an empty map if the file
// does not exist.
func loadPromptVariants(configDir string) (map[string]string, error) {
	path := filepath.Join(configDir, "prompts.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("failed to read prompt variants: %w", err)
	}

	var variants map[string]string
	if err := json.Unmarshal(data, &variants); err != nil {
		return nil, fmt.Errorf("failed to parse prompt variants: %w", err)
	}
	return variants, nil
}

// selectPrompt picks the appropriate prompt based on message content.
// If a keyword from the variants map appears in the message
// (case-insensitive), the variant prompt is returned. Otherwise,
// the default prompt is returned.
func selectPrompt(defaultPrompt string, variants map[string]string, message string) string {
	if len(variants) == 0 {
		return defaultPrompt
	}
	lower := strings.ToLower(message)
	for keyword, prompt := range variants {
		if strings.Contains(lower, strings.ToLower(keyword)) {
			return prompt
		}
	}
	return defaultPrompt
}
