package tools

import (
	"context"
	"testing"
)

func TestExecToolDenyPatterns(t *testing.T) {
	tool := NewExecTool(ExecConfig{Timeout: 5, MaxOutput: 1000})

	denied := []string{
		"rm -rf /",
		"sudo apt-get install",
		"docker run malicious",
		"git push --force",
		"dd if=/dev/zero of=/dev/sda",
	}

	for _, cmd := range denied {
		t.Run(cmd, func(t *testing.T) {
			result := tool.Execute(context.Background(),
				map[string]any{"command": cmd})
			if !result.Error {
				t.Fatalf("expected deny for %q", cmd)
			}
		})
	}
}

func TestExecToolAllowed(t *testing.T) {
	tool := NewExecTool(ExecConfig{Timeout: 5, MaxOutput: 1000})

	result := tool.Execute(context.Background(),
		map[string]any{"command": "echo hello"})
	if result.Error {
		t.Fatalf("unexpected error: %s", result.Output)
	}
	if result.Output != "hello\n" {
		t.Fatalf("expected 'hello\\n', got %q", result.Output)
	}
}

func TestExecToolTimeout(t *testing.T) {
	tool := NewExecTool(ExecConfig{Timeout: 1, MaxOutput: 1000})

	result := tool.Execute(context.Background(),
		map[string]any{"command": "sleep 10"})
	if !result.Error {
		t.Fatal("expected timeout error")
	}
}
