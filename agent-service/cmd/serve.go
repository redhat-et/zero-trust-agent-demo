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
	"github.com/redhat-et/zero-trust-agent-demo/pkg/a2abridge"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/config"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/logger"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/metrics"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/spiffe"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/telemetry"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the agent service",
	Long:  `Start the agent service on the configured port.`,
	RunE:  runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().String("document-service-url", "http://localhost:8080", "Document service URL")
	serveCmd.Flags().Bool("enable-discovery", false, "Enable Kubernetes-based A2A agent discovery")
	serveCmd.Flags().String("discovery-namespace", "spiffe-demo", "Namespace to discover A2A agents in")
	serveCmd.Flags().Duration("discovery-interval", 30*time.Second, "Interval between discovery scans")
	serveCmd.Flags().String("discovery-scheme", "https", "URL scheme for discovered agents (http or https)")
	v.BindPFlag("document_service_url", serveCmd.Flags().Lookup("document-service-url"))
	v.BindPFlag("enable_discovery", serveCmd.Flags().Lookup("enable-discovery"))
	v.BindPFlag("discovery_namespace", serveCmd.Flags().Lookup("discovery-namespace"))
	v.BindPFlag("discovery_interval", serveCmd.Flags().Lookup("discovery-interval"))
	v.BindPFlag("discovery_scheme", serveCmd.Flags().Lookup("discovery-scheme"))
}

type Config struct {
	config.CommonConfig `mapstructure:",squash"`
	DocumentServiceURL  string        `mapstructure:"document_service_url"`
	EnableDiscovery     bool          `mapstructure:"enable_discovery"`
	DiscoveryNamespace  string        `mapstructure:"discovery_namespace"`
	DiscoveryInterval   time.Duration `mapstructure:"discovery_interval"`
	DiscoveryScheme     string        `mapstructure:"discovery_scheme"`
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
	a2aClient          *a2abridge.A2AClient
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func runServe(cmd *cobra.Command, args []string) error {
	var cfg Config
	if err := config.Load(v, &cfg); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize OpenTelemetry
	ctx := context.Background()
	otelShutdown, err := telemetry.Init(ctx, telemetry.Config{
		ServiceName:       "agent-service",
		Enabled:           cfg.OTel.Enabled,
		CollectorEndpoint: cfg.OTel.CollectorEndpoint,
	})
	if err != nil {
		return fmt.Errorf("failed to init telemetry: %w", err)
	}
	defer otelShutdown(ctx)

	// Set defaults
	if cfg.DocumentServiceURL == "" {
		cfg.DocumentServiceURL = "http://localhost:8080"
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
	// Timeout must be long enough for A2A agent invocations that include LLM calls
	httpClient := workloadClient.CreateMTLSClient(120 * time.Second)
	if cfg.OTel.Enabled {
		httpClient.Transport = telemetry.WrapTransport(httpClient.Transport)
	}

	a2aClient := a2abridge.NewA2AClient(httpClient, log.Logger)

	svc := &AgentService{
		store:              store.NewAgentStore(cfg.SPIFFE.TrustDomain),
		httpClient:         httpClient,
		documentServiceURL: cfg.DocumentServiceURL,
		log:                log,
		trustDomain:        cfg.SPIFFE.TrustDomain,
		workloadClient:     workloadClient,
		a2aClient:          a2aClient,
	}

	// Start A2A agent discovery loop if enabled
	if cfg.EnableDiscovery {
		discovery, err := a2abridge.NewAgentDiscovery(
			a2abridge.DiscoveryConfig{
				Namespace:   cfg.DiscoveryNamespace,
				TrustDomain: cfg.SPIFFE.TrustDomain,
				Scheme:      cfg.DiscoveryScheme,
			},
			httpClient,
			log.Logger,
		)
		if err != nil {
			return fmt.Errorf("failed to initialize agent discovery: %w", err)
		}
		go svc.runDiscoveryLoop(ctx, discovery, cfg.DiscoveryInterval)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", svc.handleHealth)
	mux.HandleFunc("/agents", svc.handleListAgents)
	mux.HandleFunc("/agents/", svc.handleAgentRoutes)

	// Wrap with SPIFFE identity middleware
	// In plain HTTP mode (behind Envoy proxy), use header-based identity like mock mode
	var handler http.Handler = spiffe.IdentityMiddleware(cfg.Service.MockSPIFFE || cfg.Service.ListenPlainHTTP)(mux)
	if cfg.OTel.Enabled {
		handler = telemetry.WrapHandler(handler, "agent-service")
	}

	var server *http.Server
	if cfg.Service.ListenPlainHTTP {
		server = &http.Server{Addr: cfg.Service.Addr(), Handler: handler}
	} else {
		server = workloadClient.CreateHTTPServer(cfg.Service.Addr(), handler)
	}
	server.ReadTimeout = 10 * time.Second
	server.WriteTimeout = 120 * time.Second

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
	log.Info("mTLS mode", "enabled", !cfg.Service.MockSPIFFE && !cfg.Service.ListenPlainHTTP)
	log.Info("Plain HTTP mode", "enabled", cfg.Service.ListenPlainHTTP)
	log.Info("A2A agent discovery", "enabled", cfg.EnableDiscovery)
	if cfg.EnableDiscovery {
		log.Info("Discovery config",
			"namespace", cfg.DiscoveryNamespace,
			"interval", cfg.DiscoveryInterval,
			"scheme", cfg.DiscoveryScheme)
	}

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

	// Start main server (mTLS if not in mock or plain HTTP mode)
	var serverErr error
	if !cfg.Service.MockSPIFFE && !cfg.Service.ListenPlainHTTP && server.TLSConfig != nil {
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

	if parts[1] == "invoke" {
		// POST /agents/{id}/invoke
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleInvoke(w, r, agent)
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

	ctx, span := telemetry.StartSpan(r.Context(), "agent.delegated_access",
		telemetry.AttrAgentID.String(agent.ID),
		telemetry.AttrAgentSPIFFEID.String(agent.SPIFFEID),
	)
	defer span.End()

	if req.UserSPIFFEID == "" {
		s.log.Section("AUTONOMOUS AGENT ACCESS ATTEMPT")
		s.log.Error("No user SPIFFE ID provided - agents cannot act autonomously")
		s.log.Deny("Agent requests require user delegation context")
		telemetry.SetSpanError(span, fmt.Errorf("autonomous agent access denied"))
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

	span.SetAttributes(
		telemetry.AttrUserSPIFFEID.String(req.UserSPIFFEID),
		telemetry.AttrDocumentID.String(req.DocumentID),
	)

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
	bearerToken := extractBearerToken(r)
	result, err := s.accessDocumentDelegated(ctx, agent, req.UserSPIFFEID, req.DocumentID, req.UserDepartments, bearerToken)
	if err != nil {
		telemetry.SetSpanError(span, err)
		s.log.Error("Delegated access failed", "error", err)
		metrics.AuthorizationDecisions.WithLabelValues("agent-service", "error", "delegated").Inc()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	span.SetAttributes(telemetry.AttrAccessGranted.Bool(result.Granted))

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

func (s *AgentService) accessDocumentDelegated(ctx context.Context, agent *store.Agent, userSPIFFEID, documentID string, userDepartments []string, bearerToken string) (*AccessResult, error) {
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
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

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

// InvokeRequest represents a request to invoke an A2A agent with delegation context.
type InvokeRequest struct {
	UserSPIFFEID    string   `json:"user_spiffe_id"`
	DocumentID      string   `json:"document_id"`
	UserDepartments []string `json:"user_departments,omitempty"`
	ReviewType      string   `json:"review_type,omitempty"`
}

// InvokeResponse represents the response from an A2A agent invocation.
type InvokeResponse struct {
	Granted bool   `json:"granted"`
	Reason  string `json:"reason,omitempty"`
	Agent   string `json:"agent"`
	User    string `json:"user,omitempty"`
	Result  string `json:"result,omitempty"`
	State   string `json:"state,omitempty"`
}

func (s *AgentService) handleInvoke(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	var req InvokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.log.Error("Invalid request body", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Only A2A agents can be invoked
	if agent.A2AURL == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"granted": false,
			"reason":  "Agent does not support A2A invocation",
			"agent":   agent.ID,
		})
		return
	}

	if req.UserSPIFFEID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{
			"granted": false,
			"reason":  "Agent requests require user delegation context",
			"agent":   agent.ID,
		})
		return
	}

	ctx := r.Context()

	s.log.Section("A2A AGENT INVOCATION")
	s.log.Info("Invoking A2A agent",
		"agent", agent.Name,
		"a2a_url", agent.A2AURL,
		"document_id", req.DocumentID,
		"user_spiffe_id", req.UserSPIFFEID)

	// First check OPA authorization via document-service
	bearerToken := extractBearerToken(r)
	accessResult, err := s.accessDocumentDelegated(ctx, agent, req.UserSPIFFEID, req.DocumentID, req.UserDepartments, bearerToken)
	if err != nil {
		s.log.Error("Authorization check failed", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !accessResult.Granted {
		s.log.Deny("A2A invocation denied - authorization failed")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(&InvokeResponse{
			Granted: false,
			Reason:  accessResult.Reason,
			Agent:   agent.ID,
			User:    accessResult.User,
		})
		return
	}

	// Authorization passed - invoke the A2A agent
	s.log.Success("Authorization granted, forwarding to A2A agent")

	invokeResult, err := s.a2aClient.Invoke(ctx, &a2abridge.InvokeRequest{
		AgentURL:      agent.A2AURL,
		Card:          agent.AgentCard,
		DocumentID:    req.DocumentID,
		ReviewType:    req.ReviewType,
		BearerToken:   bearerToken,
		UserSPIFFEID:  req.UserSPIFFEID,
		AgentSPIFFEID: agent.SPIFFEID,
	})
	if err != nil {
		s.log.Error("A2A invocation failed", "error", err)
		http.Error(w, fmt.Sprintf("A2A invocation failed: %v", err), http.StatusBadGateway)
		return
	}

	userParts := strings.Split(req.UserSPIFFEID, "/")
	userName := userParts[len(userParts)-1]

	s.log.Success("A2A agent invocation completed",
		"agent", agent.Name,
		"state", invokeResult.State)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&InvokeResponse{
		Granted: true,
		Reason:  "A2A invocation completed",
		Agent:   agent.ID,
		User:    userName,
		Result:  invokeResult.Text,
		State:   invokeResult.State,
	})
}

// runDiscoveryLoop periodically discovers A2A agents from Kubernetes.
func (s *AgentService) runDiscoveryLoop(ctx context.Context, discovery *a2abridge.AgentDiscovery, interval time.Duration) {
	s.log.Info("Starting A2A agent discovery loop", "interval", interval)

	// Run immediately on startup
	s.discoverAgents(ctx, discovery)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.log.Info("Stopping A2A agent discovery loop")
			return
		case <-ticker.C:
			s.discoverAgents(ctx, discovery)
		}
	}
}

func (s *AgentService) discoverAgents(ctx context.Context, discovery *a2abridge.AgentDiscovery) {
	agents, err := discovery.Discover(ctx)
	if err != nil {
		s.log.Error("Agent discovery failed", "error", err)
		return
	}

	// Track which discovered agents are still present
	foundIDs := make(map[string]bool)

	for _, discovered := range agents {
		foundIDs[discovered.ID] = true
		s.store.Register(&store.Agent{
			ID:           discovered.ID,
			Name:         discovered.Name,
			Capabilities: discovered.Capabilities,
			SPIFFEID:     discovered.SPIFFEID,
			Description:  discovered.Description,
			Source:       store.SourceDiscovered,
			A2AURL:       discovered.A2AURL,
			AgentCard:    discovered.Card,
		})
		s.log.Info("Registered discovered agent",
			"id", discovered.ID,
			"name", discovered.Name,
			"capabilities", discovered.Capabilities,
			"a2a_url", discovered.A2AURL)
	}

	// Remove previously discovered agents that no longer exist
	for _, id := range s.store.DiscoveredIDs() {
		if !foundIDs[id] {
			s.store.Remove(id)
			s.log.Info("Removed stale discovered agent", "id", id)
		}
	}
}
