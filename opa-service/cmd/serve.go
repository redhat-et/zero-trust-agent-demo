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

	"github.com/open-policy-agent/opa/rego"
	"github.com/spf13/cobra"

	"github.com/hardwaylabs/spiffe-spire-demo/pkg/config"
	"github.com/hardwaylabs/spiffe-spire-demo/pkg/logger"
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
	CallerSPIFFEID string      `json:"caller_spiffe_id"`
	DocumentID     string      `json:"document_id"`
	Delegation     *Delegation `json:"delegation,omitempty"`
}

type Delegation struct {
	UserSPIFFEID  string `json:"user_spiffe_id"`
	AgentSPIFFEID string `json:"agent_spiffe_id"`
}

type PolicyDecision struct {
	Allow   bool                   `json:"allow"`
	Reason  string                 `json:"reason"`
	Details map[string]interface{} `json:"details,omitempty"`
}

type OPAService struct {
	logger      *logger.Logger
	query       rego.PreparedEvalQuery
	decisionLog *logger.Logger
}

func runServe(cmd *cobra.Command, args []string) error {
	var cfg Config
	if err := config.Load(v, &cfg); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Set default policy directory
	if cfg.PolicyDir == "" {
		cfg.PolicyDir = "policies"
	}

	log := logger.New(logger.ComponentOPAService)

	// Load and compile policies
	svc, err := newOPAService(log, cfg.PolicyDir)
	if err != nil {
		return fmt.Errorf("failed to initialize OPA service: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", svc.handleHealth)
	mux.HandleFunc("/v1/data/authz/allow", svc.handleAllow)
	mux.HandleFunc("/v1/data/demo/authorization/decision", svc.handleDecision)

	server := &http.Server{
		Addr:         cfg.Service.Addr(),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Graceful shutdown
	done := make(chan bool)
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh

		log.Info("Shutting down OPA service...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Error("Shutdown error", "error", err)
		}
		close(done)
	}()

	log.Section("STARTING OPA SERVICE")
	log.Info("OPA Service starting", "addr", cfg.Service.Addr())
	log.Info("Policies loaded successfully")
	log.Info("Decision endpoint: /v1/data/demo/authorization/decision")
	log.Info("Health endpoint: /health")

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	<-done
	log.Info("OPA service stopped")
	return nil
}

func newOPAService(log *logger.Logger, policyDir string) (*OPAService, error) {
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

	log.Info("Loading policy: user_permissions.rego")
	log.Info("Loading policy: agent_permissions.rego")
	log.Info("Loading policy: delegation.rego")

	// Prepare the query
	query, err := rego.New(
		rego.Query("data.demo.authorization.decision"),
		rego.Module("user_permissions.rego", string(userPerms)),
		rego.Module("agent_permissions.rego", string(agentPerms)),
		rego.Module("delegation.rego", string(delegation)),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to prepare OPA query: %w", err)
	}

	return &OPAService{
		logger:      log,
		query:       query,
		decisionLog: logger.New(logger.ComponentOPADecision),
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
	json.NewEncoder(w).Encode(map[string]interface{}{
		"result": decision,
	})
}

func (s *OPAService) evaluate(ctx context.Context, input PolicyInput) (*PolicyDecision, error) {
	evalLog := logger.New(logger.ComponentOPAEval)

	// Convert input to map for OPA
	inputMap := map[string]interface{}{
		"caller_spiffe_id": input.CallerSPIFFEID,
		"document_id":      input.DocumentID,
	}
	if input.Delegation != nil {
		inputMap["delegation"] = map[string]interface{}{
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
	resultMap, ok := results[0].Expressions[0].Value.(map[string]interface{})
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
	if details, ok := resultMap["details"].(map[string]interface{}); ok {
		decision.Details = details
	}

	return decision, nil
}
