package tools

import (
	"context"
	"os"
	"path/filepath"
)

type writeFileTool struct {
	workspace string
}

func NewWriteFileTool(workspace string) Tool {
	return &writeFileTool{workspace: workspace}
}

func (t *writeFileTool) Name() string        { return "write_file" }
func (t *writeFileTool) Description() string {
	return "Write content to a file. Creates the file if it doesn't exist, " +
		"overwrites if it does."
}
func (t *writeFileTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{
				"type":        "string",
				"description": "Path to the file to write",
			},
			"content": map[string]any{
				"type":        "string",
				"description": "Content to write to the file",
			},
		},
		"required": []string{"path", "content"},
	}
}

func (t *writeFileTool) Execute(_ context.Context, args map[string]any) *ToolResult {
	path, _ := args["path"].(string)
	content, _ := args["content"].(string)
	if path == "" {
		return Errorf("path is required")
	}

	if t.workspace != "" {
		if !isInsideWorkspace(path, t.workspace) {
			return Errorf("Access denied: path outside workspace")
		}
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return Errorf("failed to create directory: %s", err)
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return Errorf("failed to write file: %s", err)
	}

	return OK("File written successfully: " + path)
}
