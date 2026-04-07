package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/a2aproject/a2a-go/a2a"
	"github.com/a2aproject/a2a-go/a2asrv"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/redhat-et/zero-trust-agent-demo/pkg/a2abridge"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/config"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/llm"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/logger"
	_ "github.com/redhat-et/zero-trust-agent-demo/pkg/metrics"
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

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the zt-agent service",
	Long:  "Start the zt-agent service with ConfigMap-driven personality.",
	RunE:  runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().String("config-dir", "/config/agent",
		"Directory containing system-prompt.txt, agent-card.json, and optional prompts.json")
	serveCmd.Flags().String("document-service-url", "http://localhost:8080",
		"Document service URL")
	serveCmd.Flags().String("llm-provider", "", "LLM provider (anthropic, openai, litellm)")
	serveCmd.Flags().String("llm-api-key", "", "LLM API key")
	serveCmd.Flags().String("llm-base-url", "", "Base URL for OpenAI-compatible APIs")
	serveCmd.Flags().String("llm-model", "", "LLM model to use")
	serveCmd.Flags().Int("llm-max-tokens", 4096, "Max tokens for LLM response")
	serveCmd.Flags().Int("llm-timeout", 45, "LLM request timeout in seconds")

	v.BindPFlag("config_dir", serveCmd.Flags().Lookup("config-dir"))
	v.BindPFlag("document_service_url", serveCmd.Flags().Lookup("document-service-url"))
	v.BindPFlag("llm.provider", serveCmd.Flags().Lookup("llm-provider"))
	v.BindPFlag("llm.api_key", serveCmd.Flags().Lookup("llm-api-key"))
	v.BindPFlag("llm.base_url", serveCmd.Flags().Lookup("llm-base-url"))
	v.BindPFlag("llm.model", serveCmd.Flags().Lookup("llm-model"))
	v.BindPFlag("llm.max_tokens", serveCmd.Flags().Lookup("llm-max-tokens"))
	v.BindPFlag("llm.timeout_seconds", serveCmd.Flags().Lookup("llm-timeout"))
}

// Config holds zt-agent configuration.
type Config struct {
	config.CommonConfig `mapstructure:",squash"`
	ConfigDir           string     `mapstructure:"config_dir"`
	DocumentServiceURL  string     `mapstructure:"document_service_url"`
	LLM                 llm.Config `mapstructure:"llm"`
}

// startAgent loads config from configDir and validates it.
// This function is separated from runServe for testability.
func startAgent(configDir string, llmProvider llm.Provider) error {
	_, err := loadSystemPrompt(configDir)
	if err != nil {
		return err
	}
	return nil
}

func runServe(cmd *cobra.Command, args []string) error {
	var cfg Config
	if err := config.Load(v, &cfg); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.ConfigDir == "" {
		cfg.ConfigDir = "/config/agent"
	}
	if cfg.DocumentServiceURL == "" {
		cfg.DocumentServiceURL = "http://localhost:8080"
	}

	// Load LLM env var fallbacks (same pattern as existing agents)
	if cfg.LLM.Provider == "" {
		cfg.LLM.Provider = os.Getenv("LLM_PROVIDER")
	}
	if cfg.LLM.APIKey == "" {
		cfg.LLM.APIKey = os.Getenv("LLM_API_KEY")
		if cfg.LLM.APIKey == "" {
			cfg.LLM.APIKey = os.Getenv("ANTHROPIC_API_KEY")
		}
	}
	if cfg.LLM.BaseURL == "" {
		cfg.LLM.BaseURL = os.Getenv("LLM_BASE_URL")
	}
	if cfg.LLM.Model == "" {
		cfg.LLM.Model = os.Getenv("LLM_MODEL")
	}

	// Load agent personality from config dir
	systemPrompt, err := loadSystemPrompt(cfg.ConfigDir)
	if err != nil {
		return err
	}

	agentCard, err := loadAgentCard(cfg.ConfigDir)
	if err != nil {
		return err
	}

	promptVariants, err := loadPromptVariants(cfg.ConfigDir)
	if err != nil {
		return err
	}

	log := logger.New(logger.ComponentAgent)

	// HTTP client with delegation transport
	httpClient := &http.Client{
		Transport: &a2abridge.DelegationTransport{Base: http.DefaultTransport},
		Timeout:   30 * time.Second,
	}

	// Initialize LLM provider
	var llmProvider llm.Provider
	if cfg.LLM.APIKey != "" {
		llmProvider, err = llm.NewProvider(cfg.LLM)
		if err != nil {
			return fmt.Errorf("failed to create LLM provider: %w", err)
		}
		log.Info("LLM provider initialized",
			"provider", llmProvider.ProviderName(),
			"model", llmProvider.Model())
	} else {
		log.Warn("LLM API key not configured - will use mock responses")
	}

	// Document fetcher (same as existing agents)
	fetchDocument := func(ctx context.Context, documentID, bearerToken string) (map[string]any, error) {
		url := fmt.Sprintf("%s/documents/%s", cfg.DocumentServiceURL, documentID)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		if bearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+bearerToken)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("document service request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf("access denied")
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("document service returned status %d", resp.StatusCode)
		}

		var result map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		if doc, ok := result["document"].(map[string]any); ok {
			return doc, nil
		}
		return result, nil
	}

	// LLM processor with prompt selection
	processLLM := func(ctx context.Context, title, content string) (string, error) {
		userPrompt := "Please process the following document:\n\n" +
			"**Title:** " + title + "\n\n" +
			"**Content:**\n" + content

		selectedPrompt := selectPrompt(systemPrompt, promptVariants, title+" "+content)

		if llmProvider != nil {
			log.Info("Processing document with LLM", "document", title)
			result, err := llmProvider.Complete(ctx, selectedPrompt, userPrompt)
			if err != nil {
				return "", fmt.Errorf("LLM request failed: %w", err)
			}
			log.Success("LLM processing completed")
			return result, nil
		}

		return fmt.Sprintf("## Result\n\n**Document:** %s\n\nMock response. "+
			"Configure LLM_API_KEY to enable AI processing.\n\n"+
			"### Document Preview\n\n%s",
			title, truncate(content, 500)), nil
	}

	// Build HTTP mux
	mux := http.NewServeMux()

	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	}
	mux.HandleFunc("/health", healthHandler)

	// A2A setup — only set URL if not already configured in agent-card.json
	if agentCard.URL == "" {
		agentCard.URL = fmt.Sprintf("http://localhost:%d", cfg.Service.Port)
	}
	executor := &a2abridge.AgentExecutor{
		Log:           log,
		FetchDocument: fetchDocument,
		ProcessLLM:    processLLM,
	}
	a2aHandler := a2asrv.NewHandler(executor)
	jsonrpcHandler := a2asrv.NewJSONRPCHandler(a2aHandler)
	unsignedHandler := a2asrv.NewStaticAgentCardHandler(agentCard)
	cardHandler := a2abridge.SignedCardHandler(
		os.Getenv("AGENT_CARD_SIGNED_PATH"),
		unsignedHandler,
		log.Logger,
	)
	mux.Handle("GET /.well-known/agent-card.json", cardHandler)
	mux.Handle("POST /a2a", jsonrpcHandler)
	mux.Handle("POST /{$}", jsonrpcHandler)

	// Main server
	server := &http.Server{
		Addr:         cfg.Service.Addr(),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 120 * time.Second,
	}

	// Graceful shutdown
	done := make(chan bool)
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh
		log.Info("Shutting down zt-agent...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Error("Shutdown error", "error", err)
		}
		close(done)
	}()

	// Startup logging
	log.Section("STARTING ZT-AGENT")
	log.Info("Agent", "name", agentCard.Name)
	log.Info("Listening", "addr", cfg.Service.Addr())
	log.Info("Health server", "addr", cfg.Service.HealthAddr())
	log.Info("Document service", "url", cfg.DocumentServiceURL)
	log.Info("Config dir", "path", cfg.ConfigDir)
	if len(promptVariants) > 0 {
		keys := make([]string, 0, len(promptVariants))
		for k := range promptVariants {
			keys = append(keys, k)
		}
		log.Info("Prompt variants loaded", "variants", strings.Join(keys, ", "))
	}
	if llmProvider != nil {
		log.Info("LLM enabled",
			"provider", llmProvider.ProviderName(),
			"model", llmProvider.Model())
	}

	// Health server (plain HTTP for K8s probes)
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", healthHandler)
	healthMux.HandleFunc("/ready", healthHandler)
	healthMux.Handle("/metrics", promhttp.Handler())
	healthServer := &http.Server{
		Addr:         cfg.Service.HealthAddr(),
		Handler:      healthMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	go func() {
		if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("Health server error", "error", err)
		}
	}()

	serverErr := server.ListenAndServe()
	if serverErr != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", serverErr)
	}

	<-done
	log.Info("zt-agent stopped")
	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
