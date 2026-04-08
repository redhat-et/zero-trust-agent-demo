package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/redhat-et/zero-trust-agent-demo/pkg/tools"
)

// AgentConfig holds the agent-config.yaml configuration.
type AgentConfig struct {
	Tools ToolsConfig `yaml:"tools"`
	Loop  LoopCfg     `yaml:"loop"`
}

// ToolsConfig configures tool availability and behavior.
type ToolsConfig struct {
	Allowed   []string       `yaml:"allowed"`
	Exec      ExecToolConfig `yaml:"exec"`
	WebFetch  WebFetchCfg    `yaml:"web_fetch"`
	Workspace string         `yaml:"workspace"`
}

// ExecToolConfig configures the exec tool.
type ExecToolConfig struct {
	Timeout   int `yaml:"timeout"`
	MaxOutput int `yaml:"max_output"`
}

// WebFetchCfg configures the web_fetch tool.
type WebFetchCfg struct {
	AllowedHosts []string `yaml:"allowed_hosts"`
}

// LoopCfg configures the agentic loop.
type LoopCfg struct {
	MaxIterations int `yaml:"max_iterations"`
}

// loadAgentConfig reads agent-config.yaml from the config directory.
// Returns nil if the file does not exist (phase 1 mode).
func loadAgentConfig(configDir string) (*AgentConfig, error) {
	path := filepath.Join(configDir, "agent-config.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Phase 1 mode
		}
		return nil, fmt.Errorf("failed to read agent config: %w", err)
	}

	var cfg AgentConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse agent config: %w", err)
	}

	return &cfg, nil
}

// toLoopConfig converts AgentConfig to the tools.LoopConfig.
func (c *AgentConfig) toLoopConfig() tools.LoopConfig {
	cfg := tools.DefaultLoopConfig()
	if c.Loop.MaxIterations > 0 {
		cfg.MaxIterations = c.Loop.MaxIterations
	}
	return cfg
}
