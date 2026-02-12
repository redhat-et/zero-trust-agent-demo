package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/redhat-et/zero-trust-agent-demo/pkg/config"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/logger"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/metrics"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/spiffe"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/telemetry"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the OPA service",
	Long:  `Start the OPA policy evaluation service on the configured port.`,
	RunE:  runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().String("policy-dir", "policies", "Directory containing Rego policy files")
	v.BindPFlag("policy_dir", serveCmd.Flags().Lookup("policy-dir"))
}

type Config struct {
	config.CommonConfig `mapstructure:",squash"`
	PolicyDir           string `mapstructure:"policy_dir"`
}

type PolicyInput struct {
	CallerSPIFFEID   string           `json:"caller_spiffe_id"`
	DocumentID       string           `json:"document_id"`
	DocumentMetadata *DocumentMeta    `json:"document_metadata,omitempty"`
	Delegation       *Delegation      `json:"delegation,omitempty"`
}

type DocumentMeta struct {
	RequiredDepartment  string   `json:"required_department,omitempty"`
	RequiredDepartments []string `json:"required_departments,omitempty"`
	Sensitivity         string   `json:"sensitivity,omitempty"`
}

type Delegation struct {
	UserSPIFFEID  string `json:"user_spiffe_id"`
	AgentSPIFFEID string `json:"agent_spiffe_id"`
}

type PolicyDecision struct {
	Allow   bool           `json:"allow"`
	Reason  string         `json:"reason"`
	Details map[string]any `json:"details,omitempty"`
}

type OPAService struct {
	logger          *logger.Logger
	query           rego.PreparedEvalQuery
	managementQuery rego.PreparedEvalQuery
	decisionLog     *logger.Logger
	workloadClient  *spiffe.WorkloadClient
}

func runServe(cmd *cobra.Command, args []string) error {
	var cfg Config
	if err := config.Load(v, &cfg); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize OpenTelemetry
	ctx := context.Background()
	otelShutdown, err := telemetry.Init(ctx, telemetry.Config{
		ServiceName:       "opa-service",
		Enabled:           cfg.OTel.Enabled,
		CollectorEndpoint: cfg.OTel.CollectorEndpoint,
	})
	if err != nil {
		return fmt.Errorf("failed to init telemetry: %w", err)
	}
	defer otelShutdown(ctx)

	// Set default policy directory
	if cfg.PolicyDir == "" {
		cfg.PolicyDir = "policies"
	}

	log := logger.New(logger.ComponentOPAService)

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
		workloadClient.SetMockIdentity("spiffe://" + cfg.SPIFFE.TrustDomain + "/service/opa-service")
	}

	// Load and compile policies
	svc, err := newOPAService(log, cfg.PolicyDir, workloadClient)
	if err != nil {
		return fmt.Errorf("failed to initialize OPA service: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", svc.handleHealth)
	mux.HandleFunc("/v1/data/authz/allow", svc.handleAllow)
	mux.HandleFunc("/v1/data/demo/authorization/decision", svc.handleDecision)
	mux.HandleFunc("/v1/data/demo/authorization/management/decision", svc.handleManagementDecision)

	// Wrap with SPIFFE identity middleware
	var handler http.Handler = spiffe.IdentityMiddleware(cfg.Service.MockSPIFFE)(mux)
	if cfg.OTel.Enabled {
		handler = telemetry.WrapHandler(handler, "opa-service")
	}

	server := workloadClient.CreateHTTPServer(cfg.Service.Addr(), handler)
	server.ReadTimeout = 10 * time.Second
	server.WriteTimeout = 10 * time.Second

	// Graceful shutdown
	done := make(chan bool)
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh

		log.Info("Shutting down OPA service...")
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

	log.Section("STARTING OPA SERVICE")
	log.Info("OPA Service starting", "addr", cfg.Service.Addr())
	log.Info("Health server starting", "addr", cfg.Service.HealthAddr())
	log.Info("Policies loaded successfully")
	log.Info("Decision endpoint: /v1/data/demo/authorization/decision")
	log.Info("Health endpoint: /health (plain HTTP on health port)")
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
	log.Info("OPA service stopped")
	return nil
}

func newOPAService(log *logger.Logger, policyDir string, workloadClient *spiffe.WorkloadClient) (*OPAService, error) {
	// Read policy files from filesystem
	userPerms, err := os.ReadFile(filepath.Join(policyDir, "user_permissions.rego"))
	if err != nil {
		return nil, fmt.Errorf("failed to read user_permissions.rego: %w", err)
	}

	agentPerms, err := os.ReadFile(filepath.Join(policyDir, "agent_permissions.rego"))
	if err != nil {
		return nil, fmt.Errorf("failed to read agent_permissions.rego: %w", err)
	}

	delegation, err := os.ReadFile(filepath.Join(policyDir, "delegation.rego"))
	if err != nil {
		return nil, fmt.Errorf("failed to read delegation.rego: %w", err)
	}

	docManagement, err := os.ReadFile(filepath.Join(policyDir, "document_management.rego"))
	if err != nil {
		return nil, fmt.Errorf("failed to read document_management.rego: %w", err)
	}

	log.Info("Loading policy: user_permissions.rego")
	log.Info("Loading policy: agent_permissions.rego")
	log.Info("Loading policy: delegation.rego")
	log.Info("Loading policy: document_management.rego")

	// Prepare the authorization query
	query, err := rego.New(
		rego.Query("data.demo.authorization.decision"),
		rego.Module("user_permissions.rego", string(userPerms)),
		rego.Module("agent_permissions.rego", string(agentPerms)),
		rego.Module("delegation.rego", string(delegation)),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to prepare OPA query: %w", err)
	}

	// Prepare the management authorization query
	managementQuery, err := rego.New(
		rego.Query("data.demo.authorization.management.decision"),
		rego.Module("user_permissions.rego", string(userPerms)),
		rego.Module("document_management.rego", string(docManagement)),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to prepare OPA management query: %w", err)
	}

	return &OPAService{
		logger:          log,
		query:           query,
		managementQuery: managementQuery,
		decisionLog:     logger.New(logger.ComponentOPADecision),
		workloadClient:  workloadClient,
	}, nil
}

func (s *OPAService) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func (s *OPAService) handleAllow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Input PolicyInput `json:"input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	decision, err := s.evaluate(r.Context(), req.Input)
	if err != nil {
		s.logger.Error("Policy evaluation failed", "error", err)
		http.Error(w, "Policy evaluation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"result": decision.Allow})
}

func (s *OPAService) handleDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Input PolicyInput `json:"input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("Invalid request body", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	queryLog := logger.New(logger.ComponentOPAQuery)
	queryLog.Info("Evaluating policy request",
		"caller", req.Input.CallerSPIFFEID,
		"document", req.Input.DocumentID,
		"has_delegation", req.Input.Delegation != nil)

	decision, err := s.evaluate(r.Context(), req.Input)
	if err != nil {
		s.logger.Error("Policy evaluation failed", "error", err)
		http.Error(w, "Policy evaluation failed", http.StatusInternalServerError)
		return
	}

	if decision.Allow {
		s.decisionLog.Allow(decision.Reason)
	} else {
		s.decisionLog.Deny(decision.Reason)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"result": decision,
	})
}

func (s *OPAService) evaluate(ctx context.Context, input PolicyInput) (*PolicyDecision, error) {
	ctx, span := telemetry.StartSpan(ctx, "policy.evaluate",
		telemetry.AttrCallerSPIFFEID.String(input.CallerSPIFFEID),
		telemetry.AttrDocumentID.String(input.DocumentID),
	)
	defer span.End()

	start := time.Now()
	evalLog := logger.New(logger.ComponentOPAEval)

	// Convert input to map for OPA
	inputMap := map[string]any{
		"caller_spiffe_id": input.CallerSPIFFEID,
		"document_id":      input.DocumentID,
	}
	if input.DocumentMetadata != nil {
		metaMap := map[string]any{
			"sensitivity": input.DocumentMetadata.Sensitivity,
		}
		if input.DocumentMetadata.RequiredDepartment != "" {
			metaMap["required_department"] = input.DocumentMetadata.RequiredDepartment
		}
		if len(input.DocumentMetadata.RequiredDepartments) > 0 {
			metaMap["required_departments"] = input.DocumentMetadata.RequiredDepartments
		}
		inputMap["document_metadata"] = metaMap
	}
	if input.Delegation != nil {
		inputMap["delegation"] = map[string]any{
			"user_spiffe_id":  input.Delegation.UserSPIFFEID,
			"agent_spiffe_id": input.Delegation.AgentSPIFFEID,
		}
		evalLog.Info("Delegation context present",
			"user", input.Delegation.UserSPIFFEID,
			"agent", input.Delegation.AgentSPIFFEID)
	}

	results, err := s.query.Eval(ctx, rego.EvalInput(inputMap))
	if err != nil {
		return nil, fmt.Errorf("evaluation error: %w", err)
	}

	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return &PolicyDecision{
			Allow:  false,
			Reason: "No policy decision available",
		}, nil
	}

	// Extract decision from results
	resultMap, ok := results[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return &PolicyDecision{
			Allow:  false,
			Reason: "Invalid policy result format",
		}, nil
	}

	decision := &PolicyDecision{
		Allow: false,
	}

	if allow, ok := resultMap["allow"].(bool); ok {
		decision.Allow = allow
	}
	if reason, ok := resultMap["reason"].(string); ok {
		decision.Reason = reason
	}
	if details, ok := resultMap["details"].(map[string]any); ok {
		decision.Details = details
	}

	// Record metrics
	duration := time.Since(start).Seconds()
	metrics.AuthorizationDuration.WithLabelValues("opa-service").Observe(duration)

	decisionLabel := "deny"
	if decision.Allow {
		decisionLabel = "allow"
	}
	callerType := "user"
	if input.Delegation != nil {
		callerType = "delegated"
	}
	metrics.AuthorizationDecisions.WithLabelValues("opa-service", decisionLabel, callerType).Inc()

	span.SetAttributes(
		telemetry.AttrDecision.String(decisionLabel),
		telemetry.AttrReason.String(decision.Reason),
		telemetry.AttrCallerType.String(callerType),
	)

	return decision, nil
}

func (s *OPAService) handleManagementDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Input PolicyInput `json:"input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("Invalid request body", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	queryLog := logger.New(logger.ComponentOPAQuery)
	queryLog.Info("Evaluating management policy request",
		"caller", req.Input.CallerSPIFFEID)

	decision, err := s.evaluateManagement(r.Context(), req.Input)
	if err != nil {
		s.logger.Error("Management policy evaluation failed", "error", err)
		http.Error(w, "Policy evaluation failed", http.StatusInternalServerError)
		return
	}

	if decision.Allow {
		s.decisionLog.Allow(decision.Reason)
	} else {
		s.decisionLog.Deny(decision.Reason)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"result": decision,
	})
}

func (s *OPAService) evaluateManagement(ctx context.Context, input PolicyInput) (*PolicyDecision, error) {
	start := time.Now()

	// Convert input to map for OPA
	inputMap := map[string]any{
		"caller_spiffe_id": input.CallerSPIFFEID,
	}

	results, err := s.managementQuery.Eval(ctx, rego.EvalInput(inputMap))
	if err != nil {
		return nil, fmt.Errorf("management evaluation error: %w", err)
	}

	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return &PolicyDecision{
			Allow:  false,
			Reason: "No management policy decision available",
		}, nil
	}

	// Extract decision from results
	resultMap, ok := results[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return &PolicyDecision{
			Allow:  false,
			Reason: "Invalid management policy result format",
		}, nil
	}

	decision := &PolicyDecision{
		Allow: false,
	}

	if allow, ok := resultMap["allow"].(bool); ok {
		decision.Allow = allow
	}
	if reason, ok := resultMap["reason"].(string); ok {
		decision.Reason = reason
	}

	// Record metrics
	duration := time.Since(start).Seconds()
	metrics.AuthorizationDuration.WithLabelValues("opa-service-mgmt").Observe(duration)

	decisionLabel := "deny"
	if decision.Allow {
		decisionLabel = "allow"
	}
	metrics.AuthorizationDecisions.WithLabelValues("opa-service-mgmt", decisionLabel, "user").Inc()

	return decision, nil
}
