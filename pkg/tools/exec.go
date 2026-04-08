package tools

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"time"
)

type ExecConfig struct {
	Timeout   int // seconds
	MaxOutput int // max output length in characters
}

func DefaultExecConfig() ExecConfig {
	return ExecConfig{Timeout: 30, MaxOutput: 50000}
}

var denyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\brm\s+(-\w*\s+)*-r`),
	regexp.MustCompile(`\brm\s+(-\w*\s+)*-f`),
	regexp.MustCompile(`\bsudo\b`),
	regexp.MustCompile(`\bdd\b.*\bof=/dev/`),
	regexp.MustCompile(`\bmkfs\b`),
	regexp.MustCompile(`\bgit\s+push\b`),
	regexp.MustCompile(`\bgit\s+reset\s+--hard\b`),
	regexp.MustCompile(`\bdocker\s+run\b`),
	regexp.MustCompile(`\bdocker\s+exec\b`),
	regexp.MustCompile(`\bpodman\s+run\b`),
	regexp.MustCompile(`\bkubectl\s+delete\b`),
	regexp.MustCompile(`\boc\s+delete\b`),
	regexp.MustCompile(`\bcurl\b.*\|\s*(ba)?sh`),
	regexp.MustCompile(`\bwget\b.*\|\s*(ba)?sh`),
	regexp.MustCompile(`\bchmod\s+[0-7]*777\b`),
	regexp.MustCompile(`\bchown\b`),
	regexp.MustCompile(`\beval\b`),
	regexp.MustCompile(`:\(\)\{.*\}:`),
	regexp.MustCompile(`\b/dev/sd[a-z]\b`),
	regexp.MustCompile(`\bshutdown\b`),
	regexp.MustCompile(`\breboot\b`),
	regexp.MustCompile(`\bhalt\b`),
	regexp.MustCompile(`\bpoweroff\b`),
	regexp.MustCompile(`>\s*/etc/`),
	regexp.MustCompile(`\bssh\b`),
	regexp.MustCompile(`\bnc\s+-l`),
}

type execTool struct {
	config ExecConfig
}

func NewExecTool(cfg ExecConfig) Tool {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30
	}
	if cfg.MaxOutput == 0 {
		cfg.MaxOutput = 50000
	}
	return &execTool{config: cfg}
}

func (t *execTool) Name() string        { return "exec" }
func (t *execTool) Description() string {
	return "Run a shell command and return stdout/stderr. " +
		"Use for file conversion, data processing, and system commands. " +
		"Dangerous commands (rm -rf, sudo, docker, etc.) are blocked."
}
func (t *execTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"command": map[string]any{
				"type":        "string",
				"description": "The shell command to execute",
			},
		},
		"required": []string{"command"},
	}
}

func (t *execTool) Execute(ctx context.Context, args map[string]any) *ToolResult {
	command, ok := args["command"].(string)
	if !ok || command == "" {
		return Errorf("command is required")
	}

	for _, pattern := range denyPatterns {
		if pattern.MatchString(command) {
			return Errorf("Command blocked by security policy: %s", command)
		}
	}

	timeout := time.Duration(t.config.Timeout) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	output, err := cmd.CombinedOutput()

	result := string(output)
	if len(result) > t.config.MaxOutput {
		result = result[:t.config.MaxOutput] + "\n...(truncated)"
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return Errorf("Command timed out after %ds: %s", t.config.Timeout, command)
		}
		return &ToolResult{
			Output: fmt.Sprintf("%s\nExit error: %s", result, err),
			Error:  true,
		}
	}

	return OK(result)
}
