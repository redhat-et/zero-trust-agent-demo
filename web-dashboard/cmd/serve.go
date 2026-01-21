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

	"github.com/spf13/cobra"

	"github.com/hardwaylabs/spiffe-spire-demo/pkg/config"
	"github.com/hardwaylabs/spiffe-spire-demo/pkg/logger"
	"github.com/hardwaylabs/spiffe-spire-demo/web-dashboard/internal/assets"
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
	v.BindPFlag("user_service_url", serveCmd.Flags().Lookup("user-service-url"))
	v.BindPFlag("agent_service_url", serveCmd.Flags().Lookup("agent-service-url"))
	v.BindPFlag("document_service_url", serveCmd.Flags().Lookup("document-service-url"))
}

type Config struct {
	config.CommonConfig `mapstructure:",squash"`
	UserServiceURL      string `mapstructure:"user_service_url"`
	AgentServiceURL     string `mapstructure:"agent_service_url"`
	DocumentServiceURL  string `mapstructure:"document_service_url"`
}

// Dashboard handles the web dashboard
type Dashboard struct {
	templates          *template.Template
	httpClient         *http.Client
	userServiceURL     string
	agentServiceURL    string
	documentServiceURL string
	log                *logger.Logger
	sseClients         map[chan string]bool
	sseMutex           sync.Mutex
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

	log := logger.New(logger.ComponentDashboard)

	// Parse templates
	tmpl, err := template.ParseFS(assets.TemplatesFS, "templates/*.html")
	if err != nil {
		return fmt.Errorf("failed to parse templates: %w", err)
	}

	dashboard := &Dashboard{
		templates: tmpl,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		userServiceURL:     cfg.UserServiceURL,
		agentServiceURL:    cfg.AgentServiceURL,
		documentServiceURL: cfg.DocumentServiceURL,
		log:                log,
		sseClients:         make(map[chan string]bool),
	}

	mux := http.NewServeMux()

	// Static files
	staticSub, _ := fs.Sub(assets.StaticFS, "static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Routes
	mux.HandleFunc("/", dashboard.handleIndex)
	mux.HandleFunc("/health", dashboard.handleHealth)
	mux.HandleFunc("/events", dashboard.handleSSE)
	mux.HandleFunc("/api/users", dashboard.handleGetUsers)
	mux.HandleFunc("/api/agents", dashboard.handleGetAgents)
	mux.HandleFunc("/api/documents", dashboard.handleGetDocuments)
	mux.HandleFunc("/api/access-direct", dashboard.handleDirectAccess)
	mux.HandleFunc("/api/access-delegated", dashboard.handleDelegatedAccess)
	mux.HandleFunc("/api/status", dashboard.handleStatus)

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
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Error("Shutdown error", "error", err)
		}
		close(done)
	}()

	log.Section("STARTING WEB DASHBOARD")
	log.Info("Web Dashboard starting", "addr", cfg.Service.Addr())
	log.Info("User service", "url", cfg.UserServiceURL)
	log.Info("Agent service", "url", cfg.AgentServiceURL)
	log.Info("Document service", "url", cfg.DocumentServiceURL)
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

	data := map[string]interface{}{
		"Title": "SPIFFE/SPIRE Zero Trust Demo",
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
	data, _ := json.Marshal(map[string]interface{}{
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

	resp, err := d.httpClient.Get(d.userServiceURL + "/users")
	if err != nil {
		d.log.Error("Failed to fetch users", "error", err)
		http.Error(w, "Failed to fetch users", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	d.log.Info("Users fetched successfully", "status", resp.StatusCode)
	w.Header().Set("Content-Type", "application/json")
	var users interface{}
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

	resp, err := d.httpClient.Get(d.agentServiceURL + "/agents")
	if err != nil {
		d.log.Error("Failed to fetch agents", "error", err)
		http.Error(w, "Failed to fetch agents", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	d.log.Info("Agents fetched successfully", "status", resp.StatusCode)
	w.Header().Set("Content-Type", "application/json")
	var agents interface{}
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

	resp, err := d.httpClient.Get(d.documentServiceURL + "/documents")
	if err != nil {
		d.log.Error("Failed to fetch documents", "error", err)
		http.Error(w, "Failed to fetch documents", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	d.log.Info("Documents fetched successfully", "status", resp.StatusCode)
	w.Header().Set("Content-Type", "application/json")
	var documents interface{}
	json.NewDecoder(resp.Body).Decode(&documents)
	json.NewEncoder(w).Encode(documents)
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

	d.broadcastLog(LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Component: "DASHBOARD",
		Level:     "INFO",
		Message:   fmt.Sprintf("Initiating direct access: User=%s, Document=%s", req.UserID, req.DocumentID),
		Color:     "white",
	})

	body, _ := json.Marshal(req)
	d.log.Info("Calling user service", "url", d.userServiceURL+"/access")
	resp, err := d.httpClient.Post(d.userServiceURL+"/access", "application/json", bytes.NewReader(body))
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
	var result map[string]interface{}
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

	d.broadcastLog(LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Component: "DASHBOARD",
		Level:     "INFO",
		Message:   fmt.Sprintf("Initiating delegated access: User=%s delegates to Agent=%s for Document=%s", req.UserID, req.AgentID, req.DocumentID),
		Color:     "white",
	})

	body, _ := json.Marshal(req)
	d.log.Info("Calling user service for delegation", "url", d.userServiceURL+"/delegate")
	resp, err := d.httpClient.Post(d.userServiceURL+"/delegate", "application/json", bytes.NewReader(body))
	if err != nil {
		d.log.Error("User service delegation request failed", "error", err)
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

	d.log.Info("User service delegation response", "status", resp.StatusCode)
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if resp.StatusCode == http.StatusForbidden {
		d.broadcastLog(LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Component: "DASHBOARD",
			Level:     "WARN",
			Message:   fmt.Sprintf("Delegated access DENIED: %v", result["reason"]),
			Color:     "red",
		})
	} else {
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

	status := map[string]interface{}{
		"services": map[string]interface{}{},
	}

	services := map[string]string{
		"user-service":     d.userServiceURL + "/health",
		"agent-service":    d.agentServiceURL + "/health",
		"document-service": d.documentServiceURL + "/health",
	}

	for name, url := range services {
		resp, err := d.httpClient.Get(url)
		if err != nil {
			status["services"].(map[string]interface{})[name] = "offline"
		} else {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				status["services"].(map[string]interface{})[name] = "healthy"
			} else {
				status["services"].(map[string]interface{})[name] = "unhealthy"
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}
