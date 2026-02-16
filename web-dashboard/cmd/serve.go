package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/redhat-et/zero-trust-agent-demo/pkg/auth"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/config"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/logger"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/spiffe"
	"github.com/redhat-et/zero-trust-agent-demo/web-dashboard/internal/assets"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the web dashboard",
	Long:  `Start the web dashboard on the configured port.`,
	RunE:  runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().String("user-service-url", "http://localhost:8082", "User service URL")
	serveCmd.Flags().String("agent-service-url", "http://localhost:8083", "Agent service URL")
	serveCmd.Flags().String("document-service-url", "http://localhost:8084", "Document service URL")
	serveCmd.Flags().String("summarizer-service-url", "http://localhost:8086", "Summarizer service URL")
	serveCmd.Flags().String("reviewer-service-url", "http://localhost:8087", "Reviewer service URL")
	serveCmd.Flags().Bool("oidc-enabled", false, "Enable OIDC authentication")
	serveCmd.Flags().String("oidc-issuer-url", "http://localhost:8180/realms/spiffe-demo", "OIDC issuer URL")
	serveCmd.Flags().String("oidc-client-id", "spiffe-demo-dashboard", "OIDC client ID")
	serveCmd.Flags().String("oidc-redirect-url", "http://localhost:8080/auth/callback", "OIDC redirect URL")
	serveCmd.Flags().Bool("oidc-skip-expiry-check", false, "Skip token expiry check (for dev with clock skew)")
	v.BindPFlag("user_service_url", serveCmd.Flags().Lookup("user-service-url"))
	v.BindPFlag("agent_service_url", serveCmd.Flags().Lookup("agent-service-url"))
	v.BindPFlag("document_service_url", serveCmd.Flags().Lookup("document-service-url"))
	v.BindPFlag("summarizer_service_url", serveCmd.Flags().Lookup("summarizer-service-url"))
	v.BindPFlag("reviewer_service_url", serveCmd.Flags().Lookup("reviewer-service-url"))
	v.BindPFlag("oidc.enabled", serveCmd.Flags().Lookup("oidc-enabled"))
	v.BindPFlag("oidc.issuer_url", serveCmd.Flags().Lookup("oidc-issuer-url"))
	v.BindPFlag("oidc.client_id", serveCmd.Flags().Lookup("oidc-client-id"))
	v.BindPFlag("oidc.redirect_url", serveCmd.Flags().Lookup("oidc-redirect-url"))
	v.BindPFlag("oidc.skip_expiry_check", serveCmd.Flags().Lookup("oidc-skip-expiry-check"))
}

type Config struct {
	config.CommonConfig   `mapstructure:",squash"`
	UserServiceURL        string          `mapstructure:"user_service_url"`
	AgentServiceURL       string          `mapstructure:"agent_service_url"`
	DocumentServiceURL    string          `mapstructure:"document_service_url"`
	SummarizerServiceURL  string          `mapstructure:"summarizer_service_url"`
	ReviewerServiceURL    string          `mapstructure:"reviewer_service_url"`
	OIDC                  auth.OIDCConfig `mapstructure:"oidc"`
}

// Dashboard handles the web dashboard
type Dashboard struct {
	templates            *template.Template
	httpClient           *http.Client
	userServiceURL       string
	agentServiceURL      string
	documentServiceURL   string
	summarizerServiceURL string
	reviewerServiceURL   string
	log                  *logger.Logger
	sseClients           map[chan string]bool
	sseMutex             sync.Mutex
	workloadClient       *spiffe.WorkloadClient
	oidcEnabled          bool
	oidcProvider         *auth.OIDCProvider
	sessionStore         *auth.SessionStore
	stateStore           *auth.StateStore
	trustDomain          string
}

// LogEntry represents a log entry for SSE
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Component string `json:"component"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Color     string `json:"color"`
}

func runServe(cmd *cobra.Command, args []string) error {
	var cfg Config
	if err := config.Load(v, &cfg); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Set defaults
	if cfg.UserServiceURL == "" {
		cfg.UserServiceURL = "http://localhost:8082"
	}
	if cfg.AgentServiceURL == "" {
		cfg.AgentServiceURL = "http://localhost:8083"
	}
	if cfg.DocumentServiceURL == "" {
		cfg.DocumentServiceURL = "http://localhost:8084"
	}
	if cfg.SummarizerServiceURL == "" {
		cfg.SummarizerServiceURL = "http://localhost:8086"
	}
	if cfg.ReviewerServiceURL == "" {
		cfg.ReviewerServiceURL = "http://localhost:8087"
	}

	log := logger.New(logger.ComponentDashboard)

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
		workloadClient.SetMockIdentity("spiffe://" + cfg.SPIFFE.TrustDomain + "/service/web-dashboard")
	}

	// Parse templates
	tmpl, err := template.ParseFS(assets.TemplatesFS, "templates/*.html")
	if err != nil {
		return fmt.Errorf("failed to parse templates: %w", err)
	}

	// Create HTTP client (mTLS in real mode, regular in mock mode)
	httpClient := workloadClient.CreateMTLSClient(30 * time.Second)

	dashboard := &Dashboard{
		templates:            tmpl,
		httpClient:           httpClient,
		userServiceURL:       cfg.UserServiceURL,
		agentServiceURL:      cfg.AgentServiceURL,
		documentServiceURL:   cfg.DocumentServiceURL,
		summarizerServiceURL: cfg.SummarizerServiceURL,
		reviewerServiceURL:   cfg.ReviewerServiceURL,
		log:                  log,
		sseClients:           make(map[chan string]bool),
		workloadClient:       workloadClient,
		oidcEnabled:          cfg.OIDC.Enabled,
		trustDomain:          cfg.SPIFFE.TrustDomain,
	}

	// Initialize OIDC if enabled
	if cfg.OIDC.Enabled {
		log.Info("OIDC authentication enabled", "issuer", cfg.OIDC.IssuerURL)
		oidcProvider, err := auth.NewOIDCProvider(ctx, cfg.OIDC)
		if err != nil {
			return fmt.Errorf("failed to initialize OIDC provider: %w", err)
		}
		dashboard.oidcProvider = oidcProvider
		dashboard.sessionStore = auth.NewSessionStore(8 * time.Hour)
		dashboard.stateStore = auth.NewStateStore()
		log.Info("OIDC provider initialized", "client_id", cfg.OIDC.ClientID)
	}

	mux := http.NewServeMux()

	// Static files
	staticSub, _ := fs.Sub(assets.StaticFS, "static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Routes
	mux.HandleFunc("/", dashboard.handleIndex)
	mux.HandleFunc("/health", dashboard.handleHealth)
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/events", dashboard.handleSSE)
	mux.HandleFunc("/api/users", dashboard.handleGetUsers)
	mux.HandleFunc("/api/agents", dashboard.handleGetAgents)
	mux.HandleFunc("/api/documents", dashboard.handleGetDocuments)
	mux.HandleFunc("/api/access-direct", dashboard.handleDirectAccess)
	mux.HandleFunc("/api/access-delegated", dashboard.handleDelegatedAccess)
	mux.HandleFunc("/api/status", dashboard.handleStatus)
	mux.HandleFunc("/api/session", dashboard.handleGetSession)
	mux.HandleFunc("/api/summarize", dashboard.handleSummarize)
	mux.HandleFunc("/api/review", dashboard.handleReview)

	// Auth routes (only if OIDC is enabled)
	if cfg.OIDC.Enabled {
		mux.HandleFunc("/auth/login", dashboard.handleLogin)
		mux.HandleFunc("/auth/callback", dashboard.handleCallback)
		mux.HandleFunc("/auth/logout", dashboard.handleLogout)
	}

	server := &http.Server{
		Addr:         cfg.Service.Addr(),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second, // Longer for SSE
	}

	// Graceful shutdown
	done := make(chan bool)
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh

		log.Info("Shutting down web dashboard...")
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

	log.Section("STARTING WEB DASHBOARD")
	log.Info("Web Dashboard starting", "addr", cfg.Service.Addr())
	log.Info("User service", "url", cfg.UserServiceURL)
	log.Info("Agent service", "url", cfg.AgentServiceURL)
	log.Info("Document service", "url", cfg.DocumentServiceURL)
	log.Info("Summarizer service", "url", cfg.SummarizerServiceURL)
	log.Info("Reviewer service", "url", cfg.ReviewerServiceURL)
	log.Info("Dashboard ready at", "url", fmt.Sprintf("http://localhost:%d", cfg.Service.Port))

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	<-done
	log.Info("Web dashboard stopped")
	return nil
}

func (d *Dashboard) handleHealth(w http.ResponseWriter, r *http.Request) {
	d.log.Info("Health check request", "remote", r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	d.log.Info("Index page request", "path", r.URL.Path, "remote", r.RemoteAddr)
	if r.URL.Path != "/" {
		d.log.Info("Not found", "path", r.URL.Path)
		http.NotFound(w, r)
		return
	}

	data := map[string]any{
		"Title":       "SPIFFE/SPIRE Zero Trust Demo",
		"OIDCEnabled": d.oidcEnabled,
	}

	// Check for session if OIDC is enabled
	if d.oidcEnabled {
		if cookie, err := r.Cookie("session_id"); err == nil {
			if session := d.sessionStore.Get(cookie.Value); session != nil {
				data["Session"] = session
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.templates.ExecuteTemplate(w, "index.html", data); err != nil {
		d.log.Error("Template execution failed", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (d *Dashboard) handleSSE(w http.ResponseWriter, r *http.Request) {
	d.log.Info("SSE connection request", "remote", r.RemoteAddr)

	flusher, ok := w.(http.Flusher)
	if !ok {
		d.log.Error("SSE not supported by response writer")
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	clientChan := make(chan string, 10)

	d.sseMutex.Lock()
	d.sseClients[clientChan] = true
	clientCount := len(d.sseClients)
	d.sseMutex.Unlock()

	d.log.Info("SSE client connected", "remote", r.RemoteAddr, "total_clients", clientCount)

	defer func() {
		d.sseMutex.Lock()
		delete(d.sseClients, clientChan)
		remainingClients := len(d.sseClients)
		d.sseMutex.Unlock()
		close(clientChan)
		d.log.Info("SSE client disconnected", "remote", r.RemoteAddr, "remaining_clients", remainingClients)
	}()

	// Send initial connection message
	fmt.Fprintf(w, "data: %s\n\n", `{"type":"connected","message":"Connected to event stream"}`)
	flusher.Flush()

	for {
		select {
		case msg := <-clientChan:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-r.Context().Done():
			d.log.Info("SSE context done", "remote", r.RemoteAddr, "error", r.Context().Err())
			return
		}
	}
}

func (d *Dashboard) broadcastLog(entry LogEntry) {
	data, _ := json.Marshal(map[string]any{
		"type": "log",
		"log":  entry,
	})

	d.sseMutex.Lock()
	defer d.sseMutex.Unlock()

	for clientChan := range d.sseClients {
		select {
		case clientChan <- string(data):
		default:
			// Client buffer full, skip
		}
	}
}

func (d *Dashboard) handleGetUsers(w http.ResponseWriter, r *http.Request) {
	d.log.Info("Get users request", "remote", r.RemoteAddr)
	if r.Method != http.MethodGet {
		d.log.Error("Method not allowed", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	outReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, d.userServiceURL+"/users", nil)
	if err != nil {
		d.log.Error("Failed to create request", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	if token := d.getAccessToken(r); token != "" {
		outReq.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := d.httpClient.Do(outReq)
	if err != nil {
		d.log.Error("Failed to fetch users", "error", err)
		http.Error(w, "Failed to fetch users", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	d.log.Info("Users fetched successfully", "status", resp.StatusCode)
	w.Header().Set("Content-Type", "application/json")
	var users any
	json.NewDecoder(resp.Body).Decode(&users)
	json.NewEncoder(w).Encode(users)
}

func (d *Dashboard) handleGetAgents(w http.ResponseWriter, r *http.Request) {
	d.log.Info("Get agents request", "remote", r.RemoteAddr)
	if r.Method != http.MethodGet {
		d.log.Error("Method not allowed", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	outReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, d.agentServiceURL+"/agents", nil)
	if err != nil {
		d.log.Error("Failed to create request", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	if token := d.getAccessToken(r); token != "" {
		outReq.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := d.httpClient.Do(outReq)
	if err != nil {
		d.log.Error("Failed to fetch agents", "error", err)
		http.Error(w, "Failed to fetch agents", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	d.log.Info("Agents fetched successfully", "status", resp.StatusCode)
	w.Header().Set("Content-Type", "application/json")
	var agents any
	json.NewDecoder(resp.Body).Decode(&agents)
	json.NewEncoder(w).Encode(agents)
}

func (d *Dashboard) handleGetDocuments(w http.ResponseWriter, r *http.Request) {
	d.log.Info("Get documents request", "remote", r.RemoteAddr)
	if r.Method != http.MethodGet {
		d.log.Error("Method not allowed", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	outReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, d.documentServiceURL+"/documents", nil)
	if err != nil {
		d.log.Error("Failed to create request", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	if token := d.getAccessToken(r); token != "" {
		outReq.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := d.httpClient.Do(outReq)
	if err != nil {
		d.log.Error("Failed to fetch documents", "error", err)
		http.Error(w, "Failed to fetch documents", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	d.log.Info("Documents fetched successfully", "status", resp.StatusCode)
	w.Header().Set("Content-Type", "application/json")
	var documents any
	json.NewDecoder(resp.Body).Decode(&documents)
	json.NewEncoder(w).Encode(documents)
}

func (d *Dashboard) getAccessToken(r *http.Request) string {
	if !d.oidcEnabled {
		return ""
	}
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return ""
	}
	session := d.sessionStore.Get(cookie.Value)
	if session == nil {
		return ""
	}
	return session.AccessToken
}

func (d *Dashboard) handleDirectAccess(w http.ResponseWriter, r *http.Request) {
	d.log.Info("Direct access request", "remote", r.RemoteAddr)
	if r.Method != http.MethodPost {
		d.log.Error("Method not allowed", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UserID     string `json:"user_id"`
		DocumentID string `json:"document_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		d.log.Error("Invalid request body", "error", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	d.log.Info("Direct access params", "user", req.UserID, "document", req.DocumentID)

	// Get user departments from session (JWT groups) if OIDC is enabled
	var userDepartments []string
	if d.oidcEnabled {
		if cookie, err := r.Cookie("session_id"); err == nil {
			if session := d.sessionStore.Get(cookie.Value); session != nil {
				userDepartments = session.Groups
				d.log.Info("Using JWT groups as user departments", "groups", userDepartments)
			}
		}
	}

	d.broadcastLog(LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Component: "DASHBOARD",
		Level:     "INFO",
		Message:   fmt.Sprintf("Initiating direct access: User=%s, Document=%s", req.UserID, req.DocumentID),
		Color:     "white",
	})

	// Build request with user_departments if available
	reqBody := map[string]any{
		"user_id":     req.UserID,
		"document_id": req.DocumentID,
	}
	if len(userDepartments) > 0 {
		reqBody["user_departments"] = userDepartments
	}
	body, _ := json.Marshal(reqBody)
	d.log.Info("Calling user service", "url", d.userServiceURL+"/access")
	outReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		d.userServiceURL+"/access", bytes.NewReader(body))
	if err != nil {
		d.log.Error("Failed to create request", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	outReq.Header.Set("Content-Type", "application/json")
	if token := d.getAccessToken(r); token != "" {
		outReq.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := d.httpClient.Do(outReq)
	if err != nil {
		d.log.Error("User service request failed", "error", err)
		d.broadcastLog(LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Component: "DASHBOARD",
			Level:     "ERROR",
			Message:   fmt.Sprintf("Request failed: %v", err),
			Color:     "red",
		})
		http.Error(w, "Request failed", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	d.log.Info("User service response", "status", resp.StatusCode)
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	if resp.StatusCode == http.StatusForbidden {
		d.broadcastLog(LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Component: "DASHBOARD",
			Level:     "WARN",
			Message:   fmt.Sprintf("Access DENIED: %v", result["reason"]),
			Color:     "red",
		})
	} else {
		d.broadcastLog(LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Component: "DASHBOARD",
			Level:     "INFO",
			Message:   "Access GRANTED",
			Color:     "green",
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	json.NewEncoder(w).Encode(result)
}

func (d *Dashboard) handleDelegatedAccess(w http.ResponseWriter, r *http.Request) {
	d.log.Info("Delegated access request", "remote", r.RemoteAddr)
	if r.Method != http.MethodPost {
		d.log.Error("Method not allowed", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UserID     string `json:"user_id"`
		AgentID    string `json:"agent_id"`
		DocumentID string `json:"document_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		d.log.Error("Invalid request body", "error", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	d.log.Info("Delegated access params", "user", req.UserID, "agent", req.AgentID, "document", req.DocumentID)

	// Get user departments from session (JWT groups) if OIDC is enabled
	var userDepartments []string
	if d.oidcEnabled {
		if cookie, err := r.Cookie("session_id"); err == nil {
			if session := d.sessionStore.Get(cookie.Value); session != nil {
				userDepartments = session.Groups
				d.log.Info("Using JWT groups as user departments", "groups", userDepartments)
			}
		}
	}

	var resp *http.Response
	var err error

	// Check if this is agent-only access (no user delegation)
	if req.UserID == "" {
		// Agent-only access - call agent service directly without user context
		d.broadcastLog(LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Component: "DASHBOARD",
			Level:     "WARN",
			Message:   fmt.Sprintf("Agent %s attempting access WITHOUT user delegation for Document=%s", req.AgentID, req.DocumentID),
			Color:     "yellow",
		})

		// Call agent service directly - this should be denied by OPA
		agentReq := map[string]string{
			"document_id": req.DocumentID,
			// No user_spiffe_id - agent acting autonomously
		}
		body, _ := json.Marshal(agentReq)
		url := fmt.Sprintf("%s/agents/%s/access", d.agentServiceURL, req.AgentID)
		d.log.Info("Calling agent service directly (no user)", "url", url)
		outReq, reqErr := http.NewRequestWithContext(r.Context(), http.MethodPost, url, bytes.NewReader(body))
		if reqErr != nil {
			d.log.Error("Failed to create request", "error", reqErr)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		outReq.Header.Set("Content-Type", "application/json")
		if token := d.getAccessToken(r); token != "" {
			outReq.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err = d.httpClient.Do(outReq)
	} else {
		// Normal delegated access - go through user service
		d.broadcastLog(LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Component: "DASHBOARD",
			Level:     "INFO",
			Message:   fmt.Sprintf("Initiating delegated access: User=%s delegates to Agent=%s for Document=%s", req.UserID, req.AgentID, req.DocumentID),
			Color:     "white",
		})

		// Build request with user_departments if available
		reqBody := map[string]any{
			"user_id":     req.UserID,
			"agent_id":    req.AgentID,
			"document_id": req.DocumentID,
		}
		if len(userDepartments) > 0 {
			reqBody["user_departments"] = userDepartments
		}
		body, _ := json.Marshal(reqBody)
		d.log.Info("Calling user service for delegation", "url", d.userServiceURL+"/delegate")
		outReq, reqErr := http.NewRequestWithContext(r.Context(), http.MethodPost,
			d.userServiceURL+"/delegate", bytes.NewReader(body))
		if reqErr != nil {
			d.log.Error("Failed to create request", "error", reqErr)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		outReq.Header.Set("Content-Type", "application/json")
		if token := d.getAccessToken(r); token != "" {
			outReq.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err = d.httpClient.Do(outReq)
	}

	if err != nil {
		d.log.Error("Service request failed", "error", err)
		d.broadcastLog(LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Component: "DASHBOARD",
			Level:     "ERROR",
			Message:   fmt.Sprintf("Request failed: %v", err),
			Color:     "red",
		})
		http.Error(w, "Request failed", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	d.log.Info("Service response", "status", resp.StatusCode)
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	if resp.StatusCode == http.StatusForbidden || (result["granted"] != nil && result["granted"] == false) {
		reason := result["reason"]
		if reason == nil {
			reason = result["error"]
		}
		d.broadcastLog(LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Component: "DASHBOARD",
			Level:     "WARN",
			Message:   fmt.Sprintf("Access DENIED: %v", reason),
			Color:     "red",
		})
	} else if result["granted"] == true {
		d.broadcastLog(LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Component: "DASHBOARD",
			Level:     "INFO",
			Message:   "Delegated access GRANTED - Permission intersection satisfied",
			Color:     "green",
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	json.NewEncoder(w).Encode(result)
}

func (d *Dashboard) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := map[string]any{
		"services": map[string]any{},
	}

	services := map[string]string{
		"user-service":       d.userServiceURL + "/health",
		"agent-service":      d.agentServiceURL + "/health",
		"document-service":   d.documentServiceURL + "/health",
		"summarizer-service": d.summarizerServiceURL + "/health",
		"reviewer-service":   d.reviewerServiceURL + "/health",
	}

	// Forward JWT token for services behind AuthBridge (Envoy inbound
	// interception rejects unauthenticated requests including health checks)
	token := d.getAccessToken(r)

	for name, url := range services {
		outReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, url, nil)
		if err != nil {
			status["services"].(map[string]any)[name] = "offline"
			continue
		}
		if token != "" {
			outReq.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := d.httpClient.Do(outReq)
		if err != nil {
			status["services"].(map[string]any)[name] = "offline"
		} else {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				status["services"].(map[string]any)[name] = "healthy"
			} else {
				status["services"].(map[string]any)[name] = "unhealthy"
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (d *Dashboard) handleGetSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// If OIDC is not enabled, return empty session
	if !d.oidcEnabled {
		json.NewEncoder(w).Encode(map[string]any{
			"authenticated": false,
			"oidc_enabled":  false,
		})
		return
	}

	// Check for session cookie
	cookie, err := r.Cookie("session_id")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{
			"authenticated": false,
			"oidc_enabled":  true,
		})
		return
	}

	session := d.sessionStore.Get(cookie.Value)
	if session == nil {
		json.NewEncoder(w).Encode(map[string]any{
			"authenticated": false,
			"oidc_enabled":  true,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"authenticated": true,
		"oidc_enabled":  true,
		"user": map[string]any{
			"username": session.Username,
			"name":     session.Name,
			"email":    session.Email,
			"groups":   session.Groups,
		},
	})
}

func (d *Dashboard) handleLogin(w http.ResponseWriter, r *http.Request) {
	d.log.Info("Login request", "remote", r.RemoteAddr)

	if !d.oidcEnabled || d.oidcProvider == nil {
		http.Error(w, "OIDC not enabled", http.StatusNotFound)
		return
	}

	// Generate state for CSRF protection
	state := d.stateStore.GenerateState()

	// Store state in cookie for validation
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
		Path:     "/",
	})

	// Redirect to Keycloak
	url := d.oidcProvider.AuthCodeURL(state)
	d.log.Info("Redirecting to OIDC provider", "url", url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (d *Dashboard) handleCallback(w http.ResponseWriter, r *http.Request) {
	d.log.Info("OAuth callback", "remote", r.RemoteAddr)

	if !d.oidcEnabled || d.oidcProvider == nil {
		http.Error(w, "OIDC not enabled", http.StatusNotFound)
		return
	}

	// Verify state
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		d.log.Error("Missing state cookie", "error", err)
		http.Error(w, "Missing state cookie", http.StatusBadRequest)
		return
	}

	stateParam := r.URL.Query().Get("state")
	if stateCookie.Value != stateParam || !d.stateStore.Validate(stateParam) {
		d.log.Error("Invalid state", "cookie", stateCookie.Value, "param", stateParam)
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	// Check for error from provider
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		d.log.Error("OAuth error", "error", errParam, "description", errDesc)
		http.Error(w, fmt.Sprintf("Authentication failed: %s", errDesc), http.StatusUnauthorized)
		return
	}

	// Exchange code for token
	code := r.URL.Query().Get("code")
	token, err := d.oidcProvider.Exchange(r.Context(), code)
	if err != nil {
		d.log.Error("Token exchange failed", "error", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Extract and verify ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		d.log.Error("No ID token in response")
		http.Error(w, "No ID token in response", http.StatusInternalServerError)
		return
	}

	idToken, err := d.oidcProvider.Verify(r.Context(), rawIDToken)
	if err != nil {
		d.log.Error("Token verification failed", "error", err)
		http.Error(w, "Token verification failed", http.StatusUnauthorized)
		return
	}

	// Extract claims
	claims, err := auth.ExtractClaims(idToken)
	if err != nil {
		d.log.Error("Failed to extract claims", "error", err)
		http.Error(w, "Failed to extract claims", http.StatusInternalServerError)
		return
	}

	d.log.Info("User authenticated",
		"username", claims.PreferredUsername,
		"name", claims.Name,
		"groups", claims.Groups)

	// Create session
	session := d.sessionStore.Create(claims.PreferredUsername, claims.Name, claims.Email, claims.Groups, token.AccessToken)

	// Set session cookie
	// Use SameSiteLaxMode to allow the cookie on top-level navigations
	// (like redirects from OAuth providers). StrictMode would block the
	// cookie on the redirect from Keycloak, requiring a second click.
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    session.ID,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   int(8 * time.Hour / time.Second),
	})

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "oauth_state",
		Value:  "",
		MaxAge: -1,
		Path:   "/",
	})

	d.broadcastLog(LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Component: "DASHBOARD",
		Level:     "INFO",
		Message:   fmt.Sprintf("User %s logged in (groups: %v)", claims.PreferredUsername, claims.Groups),
		Color:     "green",
	})

	// Redirect to home
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (d *Dashboard) handleLogout(w http.ResponseWriter, r *http.Request) {
	d.log.Info("Logout request", "remote", r.RemoteAddr)

	// Get session for logging
	var username string
	if cookie, err := r.Cookie("session_id"); err == nil {
		if session := d.sessionStore.Get(cookie.Value); session != nil {
			username = session.Username
			d.sessionStore.Delete(cookie.Value)
		}
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		HttpOnly: true,
		MaxAge:   -1,
		Path:     "/",
	})

	if username != "" {
		d.log.Info("User logged out", "username", username)
		d.broadcastLog(LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Component: "DASHBOARD",
			Level:     "INFO",
			Message:   fmt.Sprintf("User %s logged out", username),
			Color:     "white",
		})

		// Redirect to Keycloak logout to clear the IdP session
		if d.oidcProvider != nil {
			logoutURL := d.oidcProvider.LogoutURL()
			d.log.Info("Redirecting to OIDC logout", "url", logoutURL)
			http.Redirect(w, r, logoutURL, http.StatusTemporaryRedirect)
			return
		}
	}

	// Redirect to home
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (d *Dashboard) handleSummarize(w http.ResponseWriter, r *http.Request) {
	d.log.Info("Summarize request", "remote", r.RemoteAddr)
	if r.Method != http.MethodPost {
		d.log.Error("Method not allowed", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UserID     string `json:"user_id"`
		DocumentID string `json:"document_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		d.log.Error("Invalid request body", "error", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	d.log.Info("Summarize params", "user", req.UserID, "document", req.DocumentID)

	// Get user departments from session (JWT groups) if OIDC is enabled
	var userDepartments []string
	if d.oidcEnabled {
		if cookie, err := r.Cookie("session_id"); err == nil {
			if session := d.sessionStore.Get(cookie.Value); session != nil {
				userDepartments = session.Groups
				d.log.Info("Using JWT groups as user departments", "groups", userDepartments)
			}
		}
	}

	d.broadcastLog(LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Component: "DASHBOARD",
		Level:     "INFO",
		Message:   fmt.Sprintf("Initiating AI summarization: User=%s, Document=%s", req.UserID, req.DocumentID),
		Color:     "white",
	})

	// Build the user's SPIFFE ID
	userSPIFFEID := "spiffe://" + d.trustDomain + "/user/" + req.UserID

	// Build request for summarizer service
	summarizeReq := map[string]any{
		"document_id":    req.DocumentID,
		"user_spiffe_id": userSPIFFEID,
	}
	if len(userDepartments) > 0 {
		summarizeReq["user_departments"] = userDepartments
	}
	body, _ := json.Marshal(summarizeReq)

	d.log.Info("Calling summarizer service", "url", d.summarizerServiceURL+"/summarize")
	outReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		d.summarizerServiceURL+"/summarize", bytes.NewReader(body))
	if err != nil {
		d.log.Error("Failed to create request", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	outReq.Header.Set("Content-Type", "application/json")
	if token := d.getAccessToken(r); token != "" {
		outReq.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := d.httpClient.Do(outReq)
	if err != nil {
		d.log.Error("Summarizer service request failed", "error", err)
		d.broadcastLog(LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Component: "DASHBOARD",
			Level:     "ERROR",
			Message:   fmt.Sprintf("Summarizer request failed: %v", err),
			Color:     "red",
		})
		http.Error(w, "Request failed", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	d.log.Info("Summarizer service response", "status", resp.StatusCode)
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	if resp.StatusCode == http.StatusForbidden || (result["allowed"] != nil && result["allowed"] == false) {
		reason := result["reason"]
		d.broadcastLog(LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Component: "DASHBOARD",
			Level:     "WARN",
			Message:   fmt.Sprintf("Summarization DENIED: %v", reason),
			Color:     "red",
		})
	} else if result["allowed"] == true {
		d.broadcastLog(LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Component: "DASHBOARD",
			Level:     "INFO",
			Message:   "Summarization completed successfully",
			Color:     "green",
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	json.NewEncoder(w).Encode(result)
}

func (d *Dashboard) handleReview(w http.ResponseWriter, r *http.Request) {
	d.log.Info("Review request", "remote", r.RemoteAddr)
	if r.Method != http.MethodPost {
		d.log.Error("Method not allowed", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UserID     string `json:"user_id"`
		DocumentID string `json:"document_id"`
		ReviewType string `json:"review_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		d.log.Error("Invalid request body", "error", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	d.log.Info("Review params", "user", req.UserID, "document", req.DocumentID, "review_type", req.ReviewType)

	// Get user departments from session (JWT groups) if OIDC is enabled
	var userDepartments []string
	if d.oidcEnabled {
		if cookie, err := r.Cookie("session_id"); err == nil {
			if session := d.sessionStore.Get(cookie.Value); session != nil {
				userDepartments = session.Groups
				d.log.Info("Using JWT groups as user departments", "groups", userDepartments)
			}
		}
	}

	d.broadcastLog(LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Component: "DASHBOARD",
		Level:     "INFO",
		Message:   fmt.Sprintf("Initiating AI review (%s): User=%s, Document=%s", req.ReviewType, req.UserID, req.DocumentID),
		Color:     "white",
	})

	// Build the user's SPIFFE ID
	userSPIFFEID := "spiffe://" + d.trustDomain + "/user/" + req.UserID

	// Build request for reviewer service
	reviewReq := map[string]any{
		"document_id":    req.DocumentID,
		"user_spiffe_id": userSPIFFEID,
		"review_type":    req.ReviewType,
	}
	if len(userDepartments) > 0 {
		reviewReq["user_departments"] = userDepartments
	}
	body, _ := json.Marshal(reviewReq)

	d.log.Info("Calling reviewer service", "url", d.reviewerServiceURL+"/review")
	outReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		d.reviewerServiceURL+"/review", bytes.NewReader(body))
	if err != nil {
		d.log.Error("Failed to create request", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	outReq.Header.Set("Content-Type", "application/json")
	if token := d.getAccessToken(r); token != "" {
		outReq.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := d.httpClient.Do(outReq)
	if err != nil {
		d.log.Error("Reviewer service request failed", "error", err)
		d.broadcastLog(LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Component: "DASHBOARD",
			Level:     "ERROR",
			Message:   fmt.Sprintf("Reviewer request failed: %v", err),
			Color:     "red",
		})
		http.Error(w, "Request failed", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	d.log.Info("Reviewer service response", "status", resp.StatusCode)
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	if resp.StatusCode == http.StatusForbidden || (result["allowed"] != nil && result["allowed"] == false) {
		reason := result["reason"]
		d.broadcastLog(LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Component: "DASHBOARD",
			Level:     "WARN",
			Message:   fmt.Sprintf("Review DENIED: %v", reason),
			Color:     "red",
		})
	} else if result["allowed"] == true {
		d.broadcastLog(LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Component: "DASHBOARD",
			Level:     "INFO",
			Message:   fmt.Sprintf("Review completed - %d issues found (%s severity)", result["issues_found"], result["severity"]),
			Color:     "green",
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	json.NewEncoder(w).Encode(result)
}
