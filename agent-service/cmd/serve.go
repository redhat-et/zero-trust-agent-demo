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

	"github.com/redhat-et/zero-trust-agent-demo/agent-service/internal/store"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/config"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/logger"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/metrics"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/spiffe"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the agent service",
	Long:  `Start the agent service on the configured port.`,
	RunE:  runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().String("document-service-url", "http://localhost:8084", "Document service URL")
	v.BindPFlag("document_service_url", serveCmd.Flags().Lookup("document-service-url"))
}

type Config struct {
	config.CommonConfig `mapstructure:",squash"`
	DocumentServiceURL  string `mapstructure:"document_service_url"`
}

// DelegatedAccessRequest represents a request from a user to access a document via agent
type DelegatedAccessRequest struct {
	UserSPIFFEID    string   `json:"user_spiffe_id"`
	DocumentID      string   `json:"document_id"`
	UserDepartments []string `json:"user_departments,omitempty"` // From JWT claims (OIDC mode)
}

// AgentService handles agent operations
type AgentService struct {
	store              *store.AgentStore
	httpClient         *http.Client
	documentServiceURL string
	log                *logger.Logger
	trustDomain        string
	workloadClient     *spiffe.WorkloadClient
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

	log := logger.New(logger.ComponentAgentSvc)

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
		workloadClient.SetMockIdentity("spiffe://" + cfg.SPIFFE.TrustDomain + "/service/agent-service")
	}

	// Create mTLS HTTP client for outgoing requests
	httpClient := workloadClient.CreateMTLSClient(10 * time.Second)

	svc := &AgentService{
		store:              store.NewAgentStore(cfg.SPIFFE.TrustDomain),
		httpClient:         httpClient,
		documentServiceURL: cfg.DocumentServiceURL,
		log:                log,
		trustDomain:        cfg.SPIFFE.TrustDomain,
		workloadClient:     workloadClient,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", svc.handleHealth)
	mux.HandleFunc("/agents", svc.handleListAgents)
	mux.HandleFunc("/agents/", svc.handleAgentRoutes)

	// Wrap with SPIFFE identity middleware
	handler := spiffe.IdentityMiddleware(cfg.Service.MockSPIFFE)(mux)

	server := workloadClient.CreateHTTPServer(cfg.Service.Addr(), handler)
	server.ReadTimeout = 10 * time.Second
	server.WriteTimeout = 30 * time.Second

	// Graceful shutdown
	done := make(chan bool)
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh

		log.Info("Shutting down agent service...")
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

	log.Section("STARTING AGENT SERVICE")
	log.Info("Agent Service starting", "addr", cfg.Service.Addr())
	log.Info("Health server starting", "addr", cfg.Service.HealthAddr())
	log.Info("Trust domain", "domain", cfg.SPIFFE.TrustDomain)
	log.Info("Document service", "url", cfg.DocumentServiceURL)
	log.Info("Loaded agents", "count", len(svc.store.List()))
	log.Info("mTLS mode", "enabled", !cfg.Service.MockSPIFFE)

	for _, agent := range svc.store.List() {
		log.Info("Registered agent",
			"id", agent.ID,
			"name", agent.Name,
			"capabilities", agent.Capabilities)
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
	log.Info("Agent service stopped")
	return nil
}

func (s *AgentService) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func (s *AgentService) handleListAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	agents := s.store.List()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agents)
}

func (s *AgentService) handleAgentRoutes(w http.ResponseWriter, r *http.Request) {
	// Parse path: /agents/{id} or /agents/{id}/access
	path := strings.TrimPrefix(r.URL.Path, "/agents/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "Agent ID required", http.StatusBadRequest)
		return
	}

	agentID := parts[0]
	agent, ok := s.store.Get(agentID)
	if !ok {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	if len(parts) == 1 {
		// GET /agents/{id}
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(agent)
		return
	}

	if parts[1] == "access" {
		// POST /agents/{id}/access
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleDelegatedAccess(w, r, agent)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

func (s *AgentService) handleDelegatedAccess(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	var req DelegatedAccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.log.Error("Invalid request body", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.UserSPIFFEID == "" {
		s.log.Section("AUTONOMOUS AGENT ACCESS ATTEMPT")
		s.log.Error("No user SPIFFE ID provided - agents cannot act autonomously")
		s.log.Deny("Agent requests require user delegation context")
		metrics.AuthorizationDecisions.WithLabelValues("agent-service", "deny", "autonomous").Inc()

		// Return a proper JSON response for the dashboard
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{
			"granted": false,
			"reason":  "Agent requests require user delegation context. Agents cannot access resources without explicit user delegation.",
			"agent":   agent.ID,
		})
		return
	}

	s.log.Section("DELEGATED AGENT ACCESS")
	s.log.Info("Agent accepting delegation",
		"agent", agent.Name,
		"agent_capabilities", agent.Capabilities)
	s.log.SVID(req.UserSPIFFEID, "Delegation from user")
	s.log.SVID(agent.SPIFFEID, "Agent SVID for request")

	s.log.Info("Computing permission intersection",
		"user_spiffe_id", req.UserSPIFFEID,
		"agent_spiffe_id", agent.SPIFFEID)

	// Make delegated request to document service
	result, err := s.accessDocumentDelegated(r.Context(), agent, req.UserSPIFFEID, req.DocumentID, req.UserDepartments)
	if err != nil {
		s.log.Error("Delegated access failed", "error", err)
		metrics.AuthorizationDecisions.WithLabelValues("agent-service", "error", "delegated").Inc()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Record metrics
	decision := "allow"
	if !result.Granted {
		decision = "deny"
	}
	metrics.AuthorizationDecisions.WithLabelValues("agent-service", decision, "delegated").Inc()

	w.Header().Set("Content-Type", "application/json")
	if !result.Granted {
		w.WriteHeader(http.StatusForbidden)
	}
	json.NewEncoder(w).Encode(result)
}

// AccessResult represents the result of a document access attempt
type AccessResult struct {
	Granted  bool   `json:"granted"`
	Reason   string `json:"reason"`
	Document any    `json:"document,omitempty"`
	Agent    string `json:"agent,omitempty"`
	User     string `json:"user,omitempty"`
}

func (s *AgentService) accessDocumentDelegated(ctx context.Context, agent *store.Agent, userSPIFFEID, documentID string, userDepartments []string) (*AccessResult, error) {
	delegation := map[string]any{
		"user_spiffe_id":  userSPIFFEID,
		"agent_spiffe_id": agent.SPIFFEID,
	}
	if len(userDepartments) > 0 {
		delegation["user_departments"] = userDepartments
	}
	reqBody := map[string]any{
		"document_id": documentID,
		"delegation":  delegation,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.documentServiceURL+"/access", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	// Agent uses its own SPIFFE ID for the mTLS connection
	req.Header.Set("X-SPIFFE-ID", agent.SPIFFEID)

	s.log.Flow(logger.DirectionOutgoing, "Making delegated request to Document Service")
	s.log.Info("Request details",
		"document", documentID,
		"user", userSPIFFEID,
		"agent", agent.SPIFFEID)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("document service request failed: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Extract user name from SPIFFE ID for response
	userParts := strings.Split(userSPIFFEID, "/")
	userName := userParts[len(userParts)-1]

	if resp.StatusCode == http.StatusForbidden {
		reason := "Access denied"
		if r, ok := result["reason"].(string); ok {
			reason = r
		}
		s.log.Deny(reason)
		s.log.Info("Permission intersection resulted in insufficient permissions")
		return &AccessResult{
			Granted: false,
			Reason:  reason,
			Agent:   agent.ID,
			User:    userName,
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("document service returned status %d", resp.StatusCode)
	}

	s.log.Success("Delegated access granted")
	s.log.Info("Agent successfully accessed document on behalf of user",
		"agent", agent.Name,
		"user", userName,
		"document", documentID)

	return &AccessResult{
		Granted:  true,
		Reason:   "Delegated access granted - permission intersection satisfied",
		Document: result["document"],
		Agent:    agent.ID,
		User:     userName,
	}, nil
}
