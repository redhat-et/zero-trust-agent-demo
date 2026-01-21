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

	"github.com/hardwaylabs/spiffe-spire-demo/pkg/config"
	"github.com/hardwaylabs/spiffe-spire-demo/pkg/logger"
	"github.com/hardwaylabs/spiffe-spire-demo/user-service/internal/store"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the user service",
	Long:  `Start the user service on the configured port.`,
	RunE:  runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().String("document-service-url", "http://localhost:8084", "Document service URL")
	serveCmd.Flags().String("agent-service-url", "http://localhost:8083", "Agent service URL")
	v.BindPFlag("document_service_url", serveCmd.Flags().Lookup("document-service-url"))
	v.BindPFlag("agent_service_url", serveCmd.Flags().Lookup("agent-service-url"))
}

type Config struct {
	config.CommonConfig `mapstructure:",squash"`
	DocumentServiceURL  string `mapstructure:"document_service_url"`
	AgentServiceURL     string `mapstructure:"agent_service_url"`
}

// DirectAccessRequest represents a request for direct document access
type DirectAccessRequest struct {
	UserID     string `json:"user_id"`
	DocumentID string `json:"document_id"`
}

// DelegateRequest represents a request to delegate to an agent
type DelegateRequest struct {
	UserID     string `json:"user_id"`
	AgentID    string `json:"agent_id"`
	DocumentID string `json:"document_id"`
}

// UserService handles user operations
type UserService struct {
	store              *store.UserStore
	httpClient         *http.Client
	documentServiceURL string
	agentServiceURL    string
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
	if cfg.AgentServiceURL == "" {
		cfg.AgentServiceURL = "http://localhost:8083"
	}

	log := logger.New(logger.ComponentUserService)

	svc := &UserService{
		store: store.NewUserStore(cfg.SPIFFE.TrustDomain),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		documentServiceURL: cfg.DocumentServiceURL,
		agentServiceURL:    cfg.AgentServiceURL,
		log:                log,
		trustDomain:        cfg.SPIFFE.TrustDomain,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", svc.handleHealth)
	mux.HandleFunc("/users", svc.handleListUsers)
	mux.HandleFunc("/users/", svc.handleUser)
	mux.HandleFunc("/access", svc.handleDirectAccess)
	mux.HandleFunc("/delegate", svc.handleDelegate)

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

		log.Info("Shutting down user service...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Error("Shutdown error", "error", err)
		}
		close(done)
	}()

	log.Section("STARTING USER SERVICE")
	log.Info("User Service starting", "addr", cfg.Service.Addr())
	log.Info("Trust domain", "domain", cfg.SPIFFE.TrustDomain)
	log.Info("Document service", "url", cfg.DocumentServiceURL)
	log.Info("Agent service", "url", cfg.AgentServiceURL)
	log.Info("Loaded users", "count", len(svc.store.List()))

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	<-done
	log.Info("User service stopped")
	return nil
}

func (s *UserService) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func (s *UserService) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	users := s.store.List()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func (s *UserService) handleUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/users/")
	if path == "" {
		http.Error(w, "User ID required", http.StatusBadRequest)
		return
	}

	user, ok := s.store.Get(path)
	if !ok {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (s *UserService) handleDirectAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DirectAccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.log.Error("Invalid request body", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, ok := s.store.Get(req.UserID)
	if !ok {
		s.log.Error("User not found", "user_id", req.UserID)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	s.log.Section("DIRECT USER ACCESS")
	s.log.Info("User initiating direct access",
		"user", user.Name,
		"document", req.DocumentID)
	s.log.SVID(user.SPIFFEID, "Using user SVID for authentication")

	// Make request to document service
	result, err := s.accessDocument(r.Context(), user.SPIFFEID, req.DocumentID, nil)
	if err != nil {
		s.log.Error("Document access failed", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if !result.Granted {
		w.WriteHeader(http.StatusForbidden)
	}
	json.NewEncoder(w).Encode(result)
}

func (s *UserService) handleDelegate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DelegateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.log.Error("Invalid request body", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, ok := s.store.Get(req.UserID)
	if !ok {
		s.log.Error("User not found", "user_id", req.UserID)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	s.log.Section("USER DELEGATION TO AGENT")
	s.log.Info("User initiating delegation",
		"user", user.Name,
		"agent", req.AgentID,
		"document", req.DocumentID)
	s.log.SVID(user.SPIFFEID, "User SVID for delegation context")

	// Forward delegation request to agent service
	result, err := s.delegateToAgent(r.Context(), user, req.AgentID, req.DocumentID)
	if err != nil {
		s.log.Error("Delegation failed", "error", err)
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
	User     string      `json:"user,omitempty"`
	Agent    string      `json:"agent,omitempty"`
}

func (s *UserService) accessDocument(ctx context.Context, spiffeID, documentID string, delegation *struct {
	UserSPIFFEID  string `json:"user_spiffe_id"`
	AgentSPIFFEID string `json:"agent_spiffe_id"`
}) (*AccessResult, error) {
	reqBody := map[string]interface{}{
		"document_id": documentID,
	}
	if delegation != nil {
		reqBody["delegation"] = delegation
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
	req.Header.Set("X-SPIFFE-ID", spiffeID)

	s.log.Flow(logger.DirectionOutgoing, "Requesting document from Document Service")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("document service request failed: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if resp.StatusCode == http.StatusForbidden {
		reason := "Access denied"
		if r, ok := result["reason"].(string); ok {
			reason = r
		}
		s.log.Deny(reason)
		return &AccessResult{
			Granted: false,
			Reason:  reason,
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("document service returned status %d", resp.StatusCode)
	}

	s.log.Success("Document access granted")

	return &AccessResult{
		Granted:  true,
		Reason:   "Access granted",
		Document: result["document"],
	}, nil
}

func (s *UserService) delegateToAgent(ctx context.Context, user *store.User, agentID, documentID string) (*AccessResult, error) {
	reqBody := map[string]interface{}{
		"user_spiffe_id": user.SPIFFEID,
		"document_id":    documentID,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/agents/%s/access", s.agentServiceURL, agentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	s.log.Flow(logger.DirectionOutgoing, "Delegating to Agent Service")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agent service request failed: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if resp.StatusCode == http.StatusForbidden {
		reason := "Access denied"
		if r, ok := result["reason"].(string); ok {
			reason = r
		}
		return &AccessResult{
			Granted: false,
			Reason:  reason,
			User:    user.ID,
			Agent:   agentID,
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent service returned status %d", resp.StatusCode)
	}

	return &AccessResult{
		Granted:  true,
		Reason:   "Delegated access granted",
		Document: result["document"],
		User:     user.ID,
		Agent:    agentID,
	}, nil
}
