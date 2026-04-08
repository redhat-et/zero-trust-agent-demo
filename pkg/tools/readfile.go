package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type readFileTool struct {
	workspace string
}

func NewReadFileTool(workspace string) Tool {
	return &readFileTool{workspace: workspace}
}

func (t *readFileTool) Name() string        { return "read_file" }
func (t *readFileTool) Description() string {
	return "Read a file and return its contents with numbered lines. " +
		"Use when you need to examine file contents."
}
func (t *readFileTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{
				"type":        "string",
				"description": "Path to the file to read",
			},
		},
		"required": []string{"path"},
	}
}

func (t *readFileTool) Execute(_ context.Context, args map[string]any) *ToolResult {
	path, ok := args["path"].(string)
	if !ok || path == "" {
		return Errorf("path is required")
	}

	if t.workspace != "" {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return Errorf("invalid path: %s", err)
		}
		absWorkspace, _ := filepath.Abs(t.workspace)
		if !strings.HasPrefix(absPath, absWorkspace) {
			return Errorf("Access denied: path outside workspace")
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Errorf("Error reading file: %s", err)
	}

	lines := strings.Split(string(data), "\n")
	var numbered strings.Builder
	for i, line := range lines {
		fmt.Fprintf(&numbered, "%4d\t%s\n", i+1, line)
	}

	output := numbered.String()
	if len(output) > 50000 {
		output = output[:50000] + "\n...(truncated)"
	}

	return OK(output)
}
