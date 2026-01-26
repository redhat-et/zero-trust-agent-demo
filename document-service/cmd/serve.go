package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/redhat-et/zero-trust-agent-demo/document-service/internal/store"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/config"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/logger"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/metrics"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/spiffe"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the document service",
	Long:  `Start the document service on the configured port.`,
	RunE:  runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

type Config struct {
	config.CommonConfig `mapstructure:",squash"`
}

// Delegation represents delegation context from an agent request
type Delegation struct {
	UserSPIFFEID  string `json:"user_spiffe_id"`
	AgentSPIFFEID string `json:"agent_spiffe_id"`
}

// AccessRequest represents a document access request
type AccessRequest struct {
	DocumentID string      `json:"document_id"`
	Delegation *Delegation `json:"delegation,omitempty"`
}

// OPARequest represents a policy evaluation request to OPA
type OPARequest struct {
	Input OPAInput `json:"input"`
}

type OPAInput struct {
	CallerSPIFFEID string      `json:"caller_spiffe_id"`
	DocumentID     string      `json:"document_id"`
	Delegation     *Delegation `json:"delegation,omitempty"`
}

// OPAResponse represents the response from OPA
type OPAResponse struct {
	Result struct {
		Allow   bool           `json:"allow"`
		Reason  string         `json:"reason"`
		Details map[string]any `json:"details,omitempty"`
	} `json:"result"`
}

// DocumentService handles document access with authorization
type DocumentService struct {
	store          *store.DocumentStore
	opaClient      *http.Client
	opaURL         string
	log            *logger.Logger
	workloadClient *spiffe.WorkloadClient
	mockMode       bool
}

// jsonError writes a JSON error response
func jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{
		"error":  message,
		"reason": message,
	})
}

func runServe(cmd *cobra.Command, args []string) error {
	var cfg Config
	if err := config.Load(v, &cfg); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	log := logger.New(logger.ComponentDocService)

	// Initialize SPIFFE workload client
	spiffeCfg := spiffe.Config{
		SocketPath:  cfg.SPIFFE.SocketPath,
		TrustDomain: cfg.SPIFFE.TrustDomain,
		MockMode:    cfg.Service.MockSPIFFE,
	}
	workloadClient := spiffe.NewWorkloadClient(spiffeCfg, log)

	// Fetch identity from SPIRE Agent (unless in mock mode)
	ctx := context.Background()
	if !cfg.Service.MockSPIFFE {
		identity, err := workloadClient.FetchIdentity(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch SPIFFE identity: %w", err)
		}
		log.Info("SPIFFE identity acquired", "spiffe_id", identity.SPIFFEID)
	} else {
		workloadClient.SetMockIdentity("spiffe://" + cfg.SPIFFE.TrustDomain + "/service/document-service")
	}

	// Create mTLS HTTP client for OPA requests
	opaClient := workloadClient.CreateMTLSClient(5 * time.Second)

	// Determine OPA URL scheme based on mode
	opaScheme := "http"
	if !cfg.Service.MockSPIFFE {
		opaScheme = "https"
	}

	svc := &DocumentService{
		store:          store.NewDocumentStore(),
		opaClient:      opaClient,
		opaURL:         fmt.Sprintf("%s://%s:%d/v1/data/demo/authorization/decision", opaScheme, cfg.OPA.Host, cfg.OPA.Port),
		log:            log,
		workloadClient: workloadClient,
		mockMode:       cfg.Service.MockSPIFFE,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", svc.handleHealth)
	mux.HandleFunc("/documents", svc.handleListDocuments)
	mux.HandleFunc("/documents/", svc.handleDocument)
	mux.HandleFunc("/access", svc.handleAccess)

	// Wrap with SPIFFE identity middleware
	handler := spiffe.IdentityMiddleware(cfg.Service.MockSPIFFE)(mux)

	server := workloadClient.CreateHTTPServer(cfg.Service.Addr(), handler)
	server.ReadTimeout = 10 * time.Second
	server.WriteTimeout = 10 * time.Second

	// Graceful shutdown
	done := make(chan bool)
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh

		log.Info("Shutting down document service...")
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

	log.Section("STARTING DOCUMENT SERVICE")
	log.Info("Document Service starting", "addr", cfg.Service.Addr())
	log.Info("Health server starting", "addr", cfg.Service.HealthAddr())
	log.Info("Loaded documents", "count", len(svc.store.List()))
	log.Info("OPA endpoint", "url", svc.opaURL)
	log.Info("mTLS mode", "enabled", !cfg.Service.MockSPIFFE)

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
	log.Info("Document service stopped")
	return nil
}

func (s *DocumentService) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func (s *DocumentService) handleListDocuments(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	docs := s.store.List()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(docs)
}

func (s *DocumentService) handleDocument(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract document ID from path /documents/{id}
	path := strings.TrimPrefix(r.URL.Path, "/documents/")
	if path == "" {
		http.Error(w, "Document ID required", http.StatusBadRequest)
		return
	}

	doc, ok := s.store.Get(path)
	if !ok {
		http.Error(w, "Document not found", http.StatusNotFound)
		return
	}

	// Return document metadata (without content - use /access for content)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"id":                   doc.ID,
		"title":                doc.Title,
		"sensitivity":          doc.Sensitivity,
		"required_department":  doc.RequiredDepartment,
		"required_departments": doc.RequiredDepartments,
	})
}

func (s *DocumentService) handleAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.log.Error("Invalid request body", "error", err)
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// In this demo, the X-SPIFFE-ID header carries the "subject" identity
	// (which user is requesting access), while mTLS authenticates the calling service.
	// We use the header for authorization decisions.
	callerSPIFFEID := r.Header.Get("X-SPIFFE-ID")
	if callerSPIFFEID == "" {
		// Fall back to mTLS certificate if no header (e.g., direct calls)
		callerSPIFFEID = spiffe.GetSPIFFEIDFromRequest(r)
	}
	if callerSPIFFEID == "" {
		s.log.Error("No SPIFFE ID provided")
		jsonError(w, "SPIFFE ID required", http.StatusUnauthorized)
		return
	}

	s.log.Section("DOCUMENT ACCESS REQUEST")
	s.log.Info("Received access request",
		"document", req.DocumentID,
		"caller", callerSPIFFEID,
		"has_delegation", req.Delegation != nil)

	// Check if document exists
	doc, ok := s.store.Get(req.DocumentID)
	if !ok {
		s.log.Error("Document not found", "document_id", req.DocumentID)
		jsonError(w, "Document not found", http.StatusNotFound)
		return
	}

	// Query OPA for authorization
	allowed, reason, err := s.checkAuthorization(r.Context(), callerSPIFFEID, req.DocumentID, req.Delegation)
	if err != nil {
		s.log.Error("Authorization check failed", "error", err)
		jsonError(w, "Authorization failed", http.StatusInternalServerError)
		return
	}

	// Determine caller type for metrics
	callerType := "user"
	if req.Delegation != nil {
		callerType = "delegated"
	}

	if !allowed {
		s.log.Deny(reason)
		metrics.AuthorizationDecisions.WithLabelValues("document-service", "deny", callerType).Inc()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{
			"error":  "Access denied",
			"reason": reason,
		})
		return
	}

	s.log.Allow(reason)
	metrics.AuthorizationDecisions.WithLabelValues("document-service", "allow", callerType).Inc()
	s.log.Document(doc.ID, "Returning document content")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"document": doc,
		"access": map[string]any{
			"granted": true,
			"reason":  reason,
		},
	})
}

func (s *DocumentService) checkAuthorization(ctx context.Context, callerSPIFFEID, documentID string, delegation *Delegation) (bool, string, error) {
	queryLog := logger.New(logger.ComponentOPAQuery)

	opaReq := OPARequest{
		Input: OPAInput{
			CallerSPIFFEID: callerSPIFFEID,
			DocumentID:     documentID,
			Delegation:     delegation,
		},
	}

	queryLog.Info("Querying OPA for authorization",
		"caller", callerSPIFFEID,
		"document", documentID)

	if delegation != nil {
		queryLog.Info("Delegation context",
			"user", delegation.UserSPIFFEID,
			"agent", delegation.AgentSPIFFEID)
	}

	reqBody, err := json.Marshal(opaReq)
	if err != nil {
		return false, "", fmt.Errorf("failed to marshal OPA request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.opaURL, bytes.NewReader(reqBody))
	if err != nil {
		return false, "", fmt.Errorf("failed to create OPA request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.opaClient.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("OPA request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("OPA returned status %d", resp.StatusCode)
	}

	var opaResp OPAResponse
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return false, "", fmt.Errorf("failed to decode OPA response: %w", err)
	}

	evalLog := logger.New(logger.ComponentOPAEval)
	evalLog.Info("Policy evaluation complete",
		"allow", opaResp.Result.Allow,
		"reason", opaResp.Result.Reason)

	return opaResp.Result.Allow, opaResp.Result.Reason, nil
}
