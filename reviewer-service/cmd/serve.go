package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
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
	"github.com/redhat-et/zero-trust-agent-demo/pkg/metrics"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the reviewer agent service",
	Long:  `Start the reviewer agent service on the configured port.`,
	RunE:  runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().String("document-service-url", "http://localhost:8080", "Document service URL")
	serveCmd.Flags().String("llm-provider", "", "LLM provider (anthropic, openai, litellm)")
	serveCmd.Flags().String("llm-api-key", "", "LLM API key (or set LLM_API_KEY/ANTHROPIC_API_KEY env var)")
	serveCmd.Flags().String("llm-base-url", "", "Base URL for OpenAI-compatible APIs")
	serveCmd.Flags().String("llm-model", "", "LLM model to use (provider-specific default if empty)")
	serveCmd.Flags().Int("llm-max-tokens", 4096, "Max tokens for LLM response")
	serveCmd.Flags().Int("llm-timeout", 45, "LLM request timeout in seconds")
	v.BindPFlag("document_service_url", serveCmd.Flags().Lookup("document-service-url"))
	v.BindPFlag("llm.provider", serveCmd.Flags().Lookup("llm-provider"))
	v.BindPFlag("llm.api_key", serveCmd.Flags().Lookup("llm-api-key"))
	v.BindPFlag("llm.base_url", serveCmd.Flags().Lookup("llm-base-url"))
	v.BindPFlag("llm.model", serveCmd.Flags().Lookup("llm-model"))
	v.BindPFlag("llm.max_tokens", serveCmd.Flags().Lookup("llm-max-tokens"))
	v.BindPFlag("llm.timeout_seconds", serveCmd.Flags().Lookup("llm-timeout"))
}

type Config struct {
	config.CommonConfig `mapstructure:",squash"`
	DocumentServiceURL  string     `mapstructure:"document_service_url"`
	LLM                 llm.Config `mapstructure:"llm"`
}

// ReviewRequest represents a request to review a document
type ReviewRequest struct {
	DocumentID string `json:"document_id"`
	ReviewType string `json:"review_type,omitempty"` // compliance, security, general
}

// ReviewResponse represents the response from a review
type ReviewResponse struct {
	Allowed          bool   `json:"allowed"`
	DocumentID       string `json:"document_id"`
	Review           string `json:"review,omitempty"`
	IssuesFound      int    `json:"issues_found,omitempty"`
	Severity         string `json:"severity,omitempty"`
	Reason           string `json:"reason,omitempty"`
	ProcessingTimeMs int64  `json:"processing_time_ms"`
}

// ReviewerService handles review operations
type ReviewerService struct {
	httpClient         *http.Client
	documentServiceURL string
	log                *logger.Logger
	llmProvider        llm.Provider
}

func runServe(cmd *cobra.Command, args []string) error {
	var cfg Config
	if err := config.Load(v, &cfg); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Set defaults
	if cfg.DocumentServiceURL == "" {
		cfg.DocumentServiceURL = "http://localhost:8080"
	}

	// Get LLM provider from environment if not set in config
	if cfg.LLM.Provider == "" {
		cfg.LLM.Provider = os.Getenv("LLM_PROVIDER")
	}

	// Get API key from environment if not set in config
	if cfg.LLM.APIKey == "" {
		cfg.LLM.APIKey = os.Getenv("LLM_API_KEY")
		if cfg.LLM.APIKey == "" {
			cfg.LLM.APIKey = os.Getenv("ANTHROPIC_API_KEY")
		}
	}

	// Get base URL from environment if not set in config
	if cfg.LLM.BaseURL == "" {
		cfg.LLM.BaseURL = os.Getenv("LLM_BASE_URL")
	}

	// Get model from environment if not set in config
	if cfg.LLM.Model == "" {
		cfg.LLM.Model = os.Getenv("LLM_MODEL")
	}

	log := logger.New(logger.ComponentReviewer)

	// Wrap the HTTP client with DelegationTransport so that outbound
	// requests to document-service automatically include X-Delegation-*
	// headers from the request context — no auth logic in agent code.
	httpClient := &http.Client{
		Transport: &a2abridge.DelegationTransport{Base: http.DefaultTransport},
		Timeout:   30 * time.Second,
	}

	// Initialize LLM provider if API key is available
	var llmProvider llm.Provider
	if cfg.LLM.APIKey != "" {
		var err error
		llmProvider, err = llm.NewProvider(cfg.LLM)
		if err != nil {
			return fmt.Errorf("failed to create LLM provider: %w", err)
		}
		log.Info("LLM provider initialized", "provider", llmProvider.ProviderName(), "model", llmProvider.Model())
	} else {
		log.Warn("LLM API key not configured - reviews will use mock responses")
	}

	svc := &ReviewerService{
		httpClient:         httpClient,
		documentServiceURL: cfg.DocumentServiceURL,
		log:                log,
		llmProvider:        llmProvider,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", svc.handleHealth)
	mux.HandleFunc("/review", svc.handleReview)

	// A2A agent card and JSON-RPC endpoint
	agentURL := fmt.Sprintf("http://localhost:%d", cfg.Service.Port)
	card := a2abridge.BuildAgentCard(a2abridge.AgentCardParams{
		Name:        "Reviewer Agent",
		Description: "Specialized agent for reviewing documents for compliance, security, and quality",
		Version:     "1.0.0",
		URL:         agentURL,
		Skills: []a2a.AgentSkill{
			{
				ID:          "document-review",
				Name:        "Document Review",
				Description: "Reviews documents for compliance, security, and general quality",
				Tags:        []string{"engineering", "finance", "admin", "hr"},
				Examples:    []string{"Review DOC-001", "Compliance review of DOC-006"},
			},
		},
	})

	// The reviewer executor needs to extract review_type from the A2A message,
	// so we wrap the generic AgentExecutor with a review-type-aware LLM processor.
	executor := &a2abridge.AgentExecutor{
		Log:           log,
		FetchDocument: svc.fetchDocument,
		ProcessLLM:    svc.reviewDocument,
	}
	a2aHandler := a2asrv.NewHandler(executor)
	jsonrpcHandler := a2asrv.NewJSONRPCHandler(a2aHandler)
	mux.Handle("GET /.well-known/agent-card.json", a2asrv.NewStaticAgentCardHandler(card))
	mux.Handle("POST /a2a", jsonrpcHandler)
	mux.Handle("POST /{$}", jsonrpcHandler) // Kagenti sends JSON-RPC to root path

	server := &http.Server{
		Addr:         cfg.Service.Addr(),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 120 * time.Second, // Longer for LLM responses
	}

	// Graceful shutdown
	done := make(chan bool)
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh

		log.Info("Shutting down reviewer service...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Error("Shutdown error", "error", err)
		}
		close(done)
	}()

	log.Section("STARTING REVIEWER SERVICE")
	log.Info("Reviewer Service starting", "addr", cfg.Service.Addr())
	log.Info("Health server starting", "addr", cfg.Service.HealthAddr())
	log.Info("Document service", "url", cfg.DocumentServiceURL)
	log.Info("A2A endpoint", "url", agentURL+"/a2a")
	log.Info("A2A agent card", "url", agentURL+"/.well-known/agent-card.json")
	if llmProvider != nil {
		log.Info("LLM enabled", "provider", llmProvider.ProviderName(), "model", llmProvider.Model())
	}

	// Start separate plain HTTP health server for Kubernetes probes
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", svc.handleHealth)
	healthMux.HandleFunc("/ready", svc.handleHealth)
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
	log.Info("Reviewer service stopped")
	return nil
}

func (s *ReviewerService) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func (s *ReviewerService) handleReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	startTime := time.Now()

	var req ReviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.log.Error("Invalid request body", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Default review type
	if req.ReviewType == "" {
		req.ReviewType = "general"
	}

	s.log.Section("REVIEW REQUEST")
	s.log.Info("Received review request",
		"document_id", req.DocumentID,
		"review_type", req.ReviewType)

	// Validate required fields
	if req.DocumentID == "" {
		s.log.Error("Missing required fields")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ReviewResponse{
			Allowed:          false,
			DocumentID:       req.DocumentID,
			Reason:           "document_id is required",
			ProcessingTimeMs: time.Since(startTime).Milliseconds(),
		})
		return
	}

	// Fetch document from document-service
	bearerToken := extractBearerToken(r)
	doc, err := s.fetchDocument(r.Context(), req.DocumentID, bearerToken)
	if err != nil {
		s.log.Error("Failed to fetch document", "error", err)
		metrics.AuthorizationDecisions.WithLabelValues("reviewer-service", "error", "direct").Inc()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ReviewResponse{
			Allowed:          false,
			DocumentID:       req.DocumentID,
			Reason:           err.Error(),
			ProcessingTimeMs: time.Since(startTime).Milliseconds(),
		})
		return
	}

	if doc == nil || doc["content"] == nil {
		s.log.Deny("Access denied by document service")
		metrics.AuthorizationDecisions.WithLabelValues("reviewer-service", "deny", "direct").Inc()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ReviewResponse{
			Allowed:          false,
			DocumentID:       req.DocumentID,
			Reason:           "Access denied",
			ProcessingTimeMs: time.Since(startTime).Milliseconds(),
		})
		return
	}

	s.log.Allow("Document access granted")
	metrics.AuthorizationDecisions.WithLabelValues("reviewer-service", "allow", "direct").Inc()

	// Extract document details
	title, _ := doc["title"].(string)
	content, _ := doc["content"].(string)

	// Generate review using LLM
	var review string
	var issuesFound int
	var severity string

	if s.llmProvider != nil {
		s.log.Info("Generating review with LLM", "document", title, "review_type", req.ReviewType)
		systemPrompt := llm.GetReviewerPrompt(req.ReviewType)
		userPrompt := llm.FormatReviewRequest(title, content, req.ReviewType)
		review, err = s.llmProvider.Complete(r.Context(), systemPrompt, userPrompt)
		if err != nil {
			s.log.Error("LLM request failed", "error", err)
			review = fmt.Sprintf("## Review Failed\n\nFailed to generate AI review: %v\n\n### Document Preview\n\n%s", err, truncate(content, 500))
		} else {
			s.log.Success("Review generated successfully")
			issuesFound = countIssues(review)
			severity = determineSeverity(review)
		}
	} else {
		// Mock response when LLM is not configured
		reviewTypeLabel := req.ReviewType
		if len(reviewTypeLabel) > 0 {
			reviewTypeLabel = strings.ToUpper(reviewTypeLabel[:1]) + reviewTypeLabel[1:]
		}
		review = fmt.Sprintf("## %s Review\n\n**Document:** %s\n\nThis is a mock review. Configure LLM_API_KEY to enable real AI reviews.\n\n### Document Preview\n\n%s", reviewTypeLabel, title, truncate(content, 500))
		issuesFound = 0
		severity = "low"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ReviewResponse{
		Allowed:          true,
		DocumentID:       req.DocumentID,
		Review:           review,
		IssuesFound:      issuesFound,
		Severity:         severity,
		ProcessingTimeMs: time.Since(startTime).Milliseconds(),
	})
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

// fetchDocument fetches a document from document-service using a simple GET.
// Delegation context (X-Delegation-User/Agent headers) is injected automatically
// by the DelegationTransport wrapping the HTTP client.
func (s *ReviewerService) fetchDocument(ctx context.Context, documentID, bearerToken string) (map[string]any, error) {
	url := fmt.Sprintf("%s/documents/%s", s.documentServiceURL, documentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	resp, err := s.httpClient.Do(req)
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

// reviewDocument generates a review for the given document using the LLM.
// It uses "general" as the default review type.
func (s *ReviewerService) reviewDocument(ctx context.Context, title, content string) (string, error) {
	reviewType := "general"

	if s.llmProvider != nil {
		s.log.Info("Generating review with LLM (A2A)", "document", title, "review_type", reviewType)
		systemPrompt := llm.GetReviewerPrompt(reviewType)
		userPrompt := llm.FormatReviewRequest(title, content, reviewType)
		result, err := s.llmProvider.Complete(ctx, systemPrompt, userPrompt)
		if err != nil {
			return "", fmt.Errorf("LLM request failed: %w", err)
		}
		s.log.Success("Review generated successfully (A2A)")
		return result, nil
	}

	reviewTypeLabel := strings.ToUpper(reviewType[:1]) + reviewType[1:]
	return fmt.Sprintf("## %s Review\n\n**Document:** %s\n\nThis is a mock review. Configure LLM_API_KEY to enable real AI reviews.\n\n### Document Preview\n\n%s", reviewTypeLabel, title, truncate(content, 500)), nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// countIssues attempts to count issues mentioned in the review
func countIssues(review string) int {
	lower := strings.ToLower(review)
	count := 0
	count += strings.Count(lower, "critical:")
	count += strings.Count(lower, "high:")
	count += strings.Count(lower, "medium:")
	count += strings.Count(lower, "low:")
	count += strings.Count(lower, "- issue")
	count += strings.Count(lower, "finding")
	if count == 0 {
		count = 1
	}
	return count
}

// determineSeverity determines overall severity from review content
func determineSeverity(review string) string {
	lower := strings.ToLower(review)
	if strings.Contains(lower, "critical") {
		return "critical"
	}
	if strings.Contains(lower, "high") {
		return "high"
	}
	if strings.Contains(lower, "medium") {
		return "medium"
	}
	return "low"
}
