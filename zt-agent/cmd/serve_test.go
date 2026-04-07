package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSystemPrompt(t *testing.T) {
	dir := filepath.Join("..", "testdata", "summarizer-hr")
	prompt, err := loadSystemPrompt(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prompt == "" {
		t.Fatal("expected non-empty prompt")
	}
	if len(prompt) < 50 {
		t.Fatalf("prompt too short: %q", prompt)
	}
}

func TestLoadSystemPromptMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := loadSystemPrompt(dir)
	if err == nil {
		t.Fatal("expected error for missing prompt file")
	}
}

func TestLoadAgentCard(t *testing.T) {
	dir := filepath.Join("..", "testdata", "summarizer-hr")
	card, err := loadAgentCard(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if card.Name != "summarizer-hr" {
		t.Fatalf("expected name summarizer-hr, got %q", card.Name)
	}
	if len(card.Skills) == 0 {
		t.Fatal("expected at least one skill")
	}
}

func TestLoadAgentCardMissing(t *testing.T) {
	dir := t.TempDir()
	card, err := loadAgentCard(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return a minimal fallback card
	if card.Name != "zt-agent" {
		t.Fatalf("expected fallback name zt-agent, got %q", card.Name)
	}
}

func TestLoadPromptVariants(t *testing.T) {
	dir := filepath.Join("..", "testdata", "reviewer-ops")
	variants, err := loadPromptVariants(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(variants) != 2 {
		t.Fatalf("expected 2 variants, got %d", len(variants))
	}
	if _, ok := variants["compliance"]; !ok {
		t.Fatal("expected compliance variant")
	}
	if _, ok := variants["security"]; !ok {
		t.Fatal("expected security variant")
	}
}

func TestLoadPromptVariantsMissing(t *testing.T) {
	dir := filepath.Join("..", "testdata", "summarizer-hr")
	variants, err := loadPromptVariants(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(variants) != 0 {
		t.Fatalf("expected 0 variants, got %d", len(variants))
	}
}

func TestSelectPrompt(t *testing.T) {
	defaultPrompt := "You are a general reviewer."
	variants := map[string]string{
		"compliance": "You are a compliance reviewer.",
		"security":   "You are a security reviewer.",
	}

	tests := []struct {
		name     string
		message  string
		expected string
	}{
		{"no keyword", "Review DOC-001", defaultPrompt},
		{"compliance keyword", "Compliance review of DOC-006", "You are a compliance reviewer."},
		{"security keyword", "Security check on DOC-003", "You are a security reviewer."},
		{"case insensitive", "COMPLIANCE review", "You are a compliance reviewer."},
		{"no variants", "Review DOC-001", defaultPrompt},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := selectPrompt(defaultPrompt, variants, tt.message)
			if result != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestSelectPromptNoVariants(t *testing.T) {
	defaultPrompt := "You are a summarizer."
	result := selectPrompt(defaultPrompt, nil, "Summarize DOC-001")
	if result != defaultPrompt {
		t.Fatalf("expected default prompt, got %q", result)
	}
}

func TestRunServeRequiresPrompt(t *testing.T) {
	dir := t.TempDir()
	// Write an agent card but no prompt
	cardData := `{"name":"test","version":"1.0.0","protocolVersion":"0.3.0","capabilities":{},"defaultInputModes":["application/json"],"defaultOutputModes":["text/plain"]}`
	if err := os.WriteFile(filepath.Join(dir, "agent-card.json"), []byte(cardData), 0644); err != nil {
		t.Fatalf("failed to write agent card: %v", err)
	}

	err := startAgent(dir, nil)
	if err == nil {
		t.Fatal("expected error when system-prompt.txt is missing")
	}
	if !strings.Contains(err.Error(), "system prompt") {
		t.Fatalf("expected system prompt error, got: %v", err)
	}
}
