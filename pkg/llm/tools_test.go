package llm

import (
	"encoding/json"
	"testing"
)

func TestToolDefinitionJSON(t *testing.T) {
	td := ToolDefinition{
		Name:        "read_file",
		Description: "Read a file and return its contents",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{"type": "string"},
			},
			"required": []string{"path"},
		},
	}

	data, err := json.Marshal(td)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var roundtrip ToolDefinition
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if roundtrip.Name != "read_file" {
		t.Fatalf("expected read_file, got %q", roundtrip.Name)
	}
}

func TestResponseWithToolCalls(t *testing.T) {
	resp := &Response{
		StopReason: StopReasonToolUse,
		Content:    "I'll read the file.",
		ToolCalls: []ToolCall{
			{
				ID:   "tc_001",
				Name: "read_file",
				Args: map[string]any{"path": "main.go"},
			},
		},
	}

	if !resp.HasToolCalls() {
		t.Fatal("expected HasToolCalls to be true")
	}
}

func TestResponseWithoutToolCalls(t *testing.T) {
	resp := &Response{
		StopReason: StopReasonEndTurn,
		Content:    "Here is the summary.",
	}

	if resp.HasToolCalls() {
		t.Fatal("expected HasToolCalls to be false")
	}
}
