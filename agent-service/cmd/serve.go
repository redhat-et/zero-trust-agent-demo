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

	"github.com/spf13/cobra"

	"github.com/hardwaylabs/spiffe-spire-demo/agent-service/internal/store"
	"github.com/hardwaylabs/spiffe-spire-demo/pkg/config"
	"github.com/hardwaylabs/spiffe-spire-demo/pkg/logger"
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
	UserSPIFFEID string `json:"user_spiffe_id"`
	DocumentID   string `json:"document_id"`
}

// AgentService handles agent operations
type AgentService struct {
	store              *store.AgentStore
	httpClient         *http.Client
	documentServiceURL string
	log                *logger.Logger
	trustDomain        string
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

	svc := &AgentService{
		store: store.NewAgentStore(cfg.SPIFFE.TrustDomain),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		documentServiceURL: cfg.DocumentServiceURL,
		log:                log,
		trustDomain:        cfg.SPIFFE.TrustDomain,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", svc.handleHealth)
	mux.HandleFunc("/agents", svc.handleListAgents)
	mux.HandleFunc("/agents/", svc.handleAgentRoutes)

	server := &http.Server{
		Addr:         cfg.Service.Addr(),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Graceful shutdown
	done := make(chan bool)
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh

		log.Info("Shutting down agent service...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Error("Shutdown error", "error", err)
		}
		close(done)
	}()

	log.Section("STARTING AGENT SERVICE")
	log.Info("Agent Service starting", "addr", cfg.Service.Addr())
	log.Info("Trust domain", "domain", cfg.SPIFFE.TrustDomain)
	log.Info("Document service", "url", cfg.DocumentServiceURL)
	log.Info("Loaded agents", "count", len(svc.store.List()))

	for _, agent := range svc.store.List() {
		log.Info("Registered agent",
			"id", agent.ID,
			"name", agent.Name,
			"capabilities", agent.Capabilities)
	}

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
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
		s.log.Error("No user SPIFFE ID provided - agents cannot act autonomously")
		http.Error(w, "User SPIFFE ID required for delegation", http.StatusBadRequest)
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
	result, err := s.accessDocumentDelegated(r.Context(), agent, req.UserSPIFFEID, req.DocumentID)
	if err != nil {
		s.log.Error("Delegated access failed", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if !result.Granted {
		w.WriteHeader(http.StatusForbidden)
	}
	json.NewEncoder(w).Encode(result)
}

// AccessResult represents the result of a document access attempt
type AccessResult struct {
	Granted  bool        `json:"granted"`
	Reason   string      `json:"reason"`
	Document interface{} `json:"document,omitempty"`
	Agent    string      `json:"agent,omitempty"`
	User     string      `json:"user,omitempty"`
}

func (s *AgentService) accessDocumentDelegated(ctx context.Context, agent *store.Agent, userSPIFFEID, documentID string) (*AccessResult, error) {
	reqBody := map[string]interface{}{
		"document_id": documentID,
		"delegation": map[string]interface{}{
			"user_spiffe_id":  userSPIFFEID,
			"agent_spiffe_id": agent.SPIFFEID,
		},
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

	var result map[string]interface{}
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
