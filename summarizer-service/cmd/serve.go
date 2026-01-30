package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/redhat-et/zero-trust-agent-demo/pkg/config"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/llm"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/logger"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/metrics"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/spiffe"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the summarizer agent service",
	Long:  `Start the summarizer agent service on the configured port.`,
	RunE:  runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().String("document-service-url", "http://localhost:8084", "Document service URL")
	serveCmd.Flags().String("anthropic-api-key", "", "Anthropic API key (or set ANTHROPIC_API_KEY env var)")
	serveCmd.Flags().String("llm-model", "claude-sonnet-4-20250514", "LLM model to use")
	serveCmd.Flags().Int("llm-max-tokens", 4096, "Max tokens for LLM response")
	serveCmd.Flags().Int("llm-timeout", 45, "LLM request timeout in seconds")
	v.BindPFlag("document_service_url", serveCmd.Flags().Lookup("document-service-url"))
	v.BindPFlag("llm.api_key", serveCmd.Flags().Lookup("anthropic-api-key"))
	v.BindPFlag("llm.model", serveCmd.Flags().Lookup("llm-model"))
	v.BindPFlag("llm.max_tokens", serveCmd.Flags().Lookup("llm-max-tokens"))
	v.BindPFlag("llm.timeout_seconds", serveCmd.Flags().Lookup("llm-timeout"))
}

type Config struct {
	config.CommonConfig `mapstructure:",squash"`
	DocumentServiceURL  string     `mapstructure:"document_service_url"`
	LLM                 llm.Config `mapstructure:"llm"`
}

// SummarizeRequest represents a request to summarize a document
type SummarizeRequest struct {
	DocumentID      string   `json:"document_id"`
	UserSPIFFEID    string   `json:"user_spiffe_id"`
	UserDepartments []string `json:"user_departments,omitempty"`
}

// SummarizeResponse represents the response from summarization
type SummarizeResponse struct {
	Allowed          bool   `json:"allowed"`
	DocumentID       string `json:"document_id"`
	Summary          string `json:"summary,omitempty"`
	Reason           string `json:"reason,omitempty"`
	ProcessingTimeMs int64  `json:"processing_time_ms"`
}

// SummarizerService handles summarization operations
type SummarizerService struct {
	httpClient         *http.Client
	documentServiceURL string
	log                *logger.Logger
	trustDomain        string
	workloadClient     *spiffe.WorkloadClient
	llmClient          *llm.Client
	agentSPIFFEID      string
}

func runServe(cmd *cobra.Command, args []string) error {
	var cfg Config
	if err := config.Load(v, &cfg); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Set defaults
	if cfg.DocumentServiceURL == "" {
		cfg.DocumentServiceURL = "http://localhost:8084"
	}

	// Set port defaults for summarizer-service
	if cfg.Service.Port == 0 {
		cfg.Service.Port = 8086
	}
	if cfg.Service.HealthPort == 0 {
		cfg.Service.HealthPort = 8186
	}

	// Get API key from environment if not set in config
	if cfg.LLM.APIKey == "" {
		cfg.LLM.APIKey = os.Getenv("ANTHROPIC_API_KEY")
	}

	log := logger.New(logger.ComponentSummarizer)

	// Initialize SPIFFE workload client
	spiffeCfg := spiffe.Config{
		SocketPath:  cfg.SPIFFE.SocketPath,
		TrustDomain: cfg.SPIFFE.TrustDomain,
		MockMode:    cfg.Service.MockSPIFFE,
	}
	workloadClient := spiffe.NewWorkloadClient(spiffeCfg, log)

	// Build the agent's SPIFFE ID
	agentSPIFFEID := "spiffe://" + cfg.SPIFFE.TrustDomain + "/agent/summarizer"

	// Fetch identity from SPIRE Agent (unless in mock mode)
	ctx := context.Background()
	if !cfg.Service.MockSPIFFE {
		identity, err := workloadClient.FetchIdentity(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch SPIFFE identity: %w", err)
		}
		log.Info("SPIFFE identity acquired", "spiffe_id", identity.SPIFFEID)
		agentSPIFFEID = identity.SPIFFEID
	} else {
		workloadClient.SetMockIdentity(agentSPIFFEID)
	}

	// Create mTLS HTTP client for outgoing requests
	httpClient := workloadClient.CreateMTLSClient(30 * time.Second)

	// Initialize LLM client if API key is available
	var llmClient *llm.Client
	if cfg.LLM.APIKey != "" {
		var err error
		llmClient, err = llm.NewClient(cfg.LLM)
		if err != nil {
			return fmt.Errorf("failed to create LLM client: %w", err)
		}
		log.Info("LLM client initialized", "model", llmClient.Model())
	} else {
		log.Warn("LLM API key not configured - summarization will use mock responses")
	}

	svc := &SummarizerService{
		httpClient:         httpClient,
		documentServiceURL: cfg.DocumentServiceURL,
		log:                log,
		trustDomain:        cfg.SPIFFE.TrustDomain,
		workloadClient:     workloadClient,
		llmClient:          llmClient,
		agentSPIFFEID:      agentSPIFFEID,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", svc.handleHealth)
	mux.HandleFunc("/summarize", svc.handleSummarize)

	// Wrap with SPIFFE identity middleware
	handler := spiffe.IdentityMiddleware(cfg.Service.MockSPIFFE)(mux)

	server := workloadClient.CreateHTTPServer(cfg.Service.Addr(), handler)
	server.ReadTimeout = 10 * time.Second
	server.WriteTimeout = 120 * time.Second // Longer for LLM responses

	// Graceful shutdown
	done := make(chan bool)
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh

		log.Info("Shutting down summarizer service...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Error("Shutdown error", "error", err)
		}
		if err := workloadClient.Close(); err != nil {
			log.Error("Failed to close SPIFFE workload client", "error", err)
		}
		close(done)
	}()

	log.Section("STARTING SUMMARIZER SERVICE")
	log.Info("Summarizer Service starting", "addr", cfg.Service.Addr())
	log.Info("Health server starting", "addr", cfg.Service.HealthAddr())
	log.Info("Trust domain", "domain", cfg.SPIFFE.TrustDomain)
	log.Info("Agent SPIFFE ID", "id", agentSPIFFEID)
	log.Info("Document service", "url", cfg.DocumentServiceURL)
	log.Info("mTLS mode", "enabled", !cfg.Service.MockSPIFFE)
	if llmClient != nil {
		log.Info("LLM enabled", "model", llmClient.Model())
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

	// Start main server (mTLS if not in mock mode)
	var serverErr error
	if !cfg.Service.MockSPIFFE && server.TLSConfig != nil {
		serverErr = server.ListenAndServeTLS("", "")
	} else {
		serverErr = server.ListenAndServe()
	}
	if serverErr != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", serverErr)
	}

	<-done
	log.Info("Summarizer service stopped")
	return nil
}

func (s *SummarizerService) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func (s *SummarizerService) handleSummarize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	startTime := time.Now()

	var req SummarizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.log.Error("Invalid request body", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	s.log.Section("SUMMARIZE REQUEST")
	s.log.Info("Received summarization request",
		"document_id", req.DocumentID,
		"user", req.UserSPIFFEID,
		"user_departments", req.UserDepartments)

	// Validate required fields
	if req.DocumentID == "" || req.UserSPIFFEID == "" {
		s.log.Error("Missing required fields")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(SummarizeResponse{
			Allowed:          false,
			DocumentID:       req.DocumentID,
			Reason:           "document_id and user_spiffe_id are required",
			ProcessingTimeMs: time.Since(startTime).Milliseconds(),
		})
		return
	}

	// Fetch document from document-service with delegation context
	doc, err := s.fetchDocumentWithDelegation(r.Context(), req)
	if err != nil {
		s.log.Error("Failed to fetch document", "error", err)
		metrics.AuthorizationDecisions.WithLabelValues("summarizer-service", "error", "delegated").Inc()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(SummarizeResponse{
			Allowed:          false,
			DocumentID:       req.DocumentID,
			Reason:           err.Error(),
			ProcessingTimeMs: time.Since(startTime).Milliseconds(),
		})
		return
	}

	if doc == nil || doc["content"] == nil {
		s.log.Deny("Access denied by document service")
		metrics.AuthorizationDecisions.WithLabelValues("summarizer-service", "deny", "delegated").Inc()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(SummarizeResponse{
			Allowed:          false,
			DocumentID:       req.DocumentID,
			Reason:           "Access denied - permission intersection failed",
			ProcessingTimeMs: time.Since(startTime).Milliseconds(),
		})
		return
	}

	s.log.Allow("Document access granted")
	metrics.AuthorizationDecisions.WithLabelValues("summarizer-service", "allow", "delegated").Inc()

	// Extract document details
	title, _ := doc["title"].(string)
	content, _ := doc["content"].(string)

	// Generate summary using LLM
	var summary string
	if s.llmClient != nil {
		s.log.Info("Generating summary with LLM", "document", title)
		userPrompt := llm.FormatSummaryRequest(title, content)
		summary, err = s.llmClient.Complete(r.Context(), llm.SummarizerSystemPrompt, userPrompt)
		if err != nil {
			s.log.Error("LLM request failed", "error", err)
			summary = fmt.Sprintf("## Summary\n\nFailed to generate AI summary: %v\n\n### Document Preview\n\n%s", err, truncate(content, 500))
		} else {
			s.log.Success("Summary generated successfully")
		}
	} else {
		// Mock response when LLM is not configured
		summary = fmt.Sprintf("## Summary\n\n**Document:** %s\n\nThis is a mock summary. Configure ANTHROPIC_API_KEY to enable real AI summarization.\n\n### Document Preview\n\n%s", title, truncate(content, 500))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SummarizeResponse{
		Allowed:          true,
		DocumentID:       req.DocumentID,
		Summary:          summary,
		ProcessingTimeMs: time.Since(startTime).Milliseconds(),
	})
}

func (s *SummarizerService) fetchDocumentWithDelegation(ctx context.Context, req SummarizeRequest) (map[string]any, error) {
	delegation := map[string]any{
		"user_spiffe_id":  req.UserSPIFFEID,
		"agent_spiffe_id": s.agentSPIFFEID,
	}
	if len(req.UserDepartments) > 0 {
		delegation["user_departments"] = req.UserDepartments
	}
	reqBody := map[string]any{
		"document_id": req.DocumentID,
		"delegation":  delegation,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.documentServiceURL+"/access", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-SPIFFE-ID", s.agentSPIFFEID)

	s.log.Flow(logger.DirectionOutgoing, "Requesting document with delegation context")
	s.log.Info("Delegation details",
		"user", req.UserSPIFFEID,
		"agent", s.agentSPIFFEID,
		"document", req.DocumentID)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("document service request failed: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if resp.StatusCode == http.StatusForbidden {
		reason := "Access denied"
		if r, ok := result["reason"].(string); ok {
			reason = r
		}
		return nil, fmt.Errorf("%s", reason)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("document service returned status %d", resp.StatusCode)
	}

	// Extract document from response
	if doc, ok := result["document"].(map[string]any); ok {
		return doc, nil
	}

	return result, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
