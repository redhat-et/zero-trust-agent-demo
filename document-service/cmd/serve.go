package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/redhat-et/zero-trust-agent-demo/pkg/auth"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/config"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/logger"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/metrics"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/spiffe"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/storage"
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

// JWTConfig holds JWT validation configuration
type JWTConfig struct {
	ValidationEnabled bool   `mapstructure:"validation_enabled"`
	IssuerURL         string `mapstructure:"issuer_url"`
	ExpectedAudience  string `mapstructure:"expected_audience"`
}

// Config holds the document service configuration
type Config struct {
	config.CommonConfig `mapstructure:",squash"`
	Storage             config.StorageConfig `mapstructure:"storage"`
	JWT                 JWTConfig            `mapstructure:"jwt"`
}

// Delegation represents delegation context from an agent request
type Delegation struct {
	UserSPIFFEID    string   `json:"user_spiffe_id"`
	AgentSPIFFEID   string   `json:"agent_spiffe_id"`
	UserDepartments []string `json:"user_departments,omitempty"` // From JWT claims (OIDC mode)
}

// AccessRequest represents a document access request
type AccessRequest struct {
	DocumentID      string      `json:"document_id"`
	Delegation      *Delegation `json:"delegation,omitempty"`
	UserDepartments []string    `json:"user_departments,omitempty"` // From JWT claims (OIDC mode, for direct access)
}

// OPARequest represents a policy evaluation request to OPA
type OPARequest struct {
	Input OPAInput `json:"input"`
}

// OPAInput represents the input to OPA for authorization
type OPAInput struct {
	CallerSPIFFEID   string           `json:"caller_spiffe_id"`
	DocumentID       string           `json:"document_id"`
	DocumentMetadata *OPADocumentMeta `json:"document_metadata,omitempty"`
	Delegation       *Delegation      `json:"delegation,omitempty"`
	UserDepartments  []string         `json:"user_departments,omitempty"` // From JWT claims (OIDC mode)
}

// OPADocumentMeta represents document metadata for OPA
type OPADocumentMeta struct {
	RequiredDepartment  string   `json:"required_department,omitempty"`
	RequiredDepartments []string `json:"required_departments,omitempty"`
	Sensitivity         string   `json:"sensitivity,omitempty"`
}

// OPAResponse represents the response from OPA
type OPAResponse struct {
	Result struct {
		Allow   bool           `json:"allow"`
		Reason  string         `json:"reason"`
		Details map[string]any `json:"details,omitempty"`
	} `json:"result"`
}

// CreateDocumentRequest represents a request to create a document (JSON mode)
type CreateDocumentRequest struct {
	ID                  string   `json:"id"`
	Title               string   `json:"title"`
	RequiredDepartment  string   `json:"required_department,omitempty"`
	RequiredDepartments []string `json:"required_departments,omitempty"`
	Sensitivity         string   `json:"sensitivity"`
	Content             string   `json:"content,omitempty"`
}

// DocumentService handles document access with authorization
type DocumentService struct {
	storage        storage.DocumentStorage
	opaClient      *http.Client
	opaURL         string
	opaManageURL   string
	log            *logger.Logger
	workloadClient *spiffe.WorkloadClient
	mockMode       bool
	jwtValidator   *auth.JWTValidator
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

	// Load OBC-style environment variables for storage
	config.LoadStorageConfigFromEnv(&cfg.Storage)

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

	// Initialize storage backend
	var store storage.DocumentStorage
	if cfg.Storage.Enabled {
		log.Info("Initializing S3 storage",
			"host", cfg.Storage.BucketHost,
			"port", cfg.Storage.BucketPort,
			"bucket", cfg.Storage.BucketName)

		s3Cfg := storage.S3Config{
			BucketHost:      cfg.Storage.BucketHost,
			BucketPort:      cfg.Storage.BucketPort,
			BucketName:      cfg.Storage.BucketName,
			UseSSL:          cfg.Storage.UseSSL,
			InsecureTLS:     cfg.Storage.InsecureTLS,
			Region:          cfg.Storage.Region,
			AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
			SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		}

		s3Store, err := storage.NewS3Storage(ctx, s3Cfg)
		if err != nil {
			return fmt.Errorf("failed to initialize S3 storage: %w", err)
		}

		// Verify connectivity
		if err := s3Store.Ping(ctx); err != nil {
			return fmt.Errorf("failed to connect to S3 storage: %w", err)
		}
		log.Info("S3 storage connected successfully")
		store = s3Store
	} else {
		log.Info("Using mock storage with sample documents")
		store = storage.NewMockStorage()
	}

	// Create mTLS HTTP client for OPA requests
	opaClient := workloadClient.CreateMTLSClient(5 * time.Second)

	// Determine OPA URL scheme based on mode
	opaScheme := "http"
	if !cfg.Service.MockSPIFFE {
		opaScheme = "https"
	}

	svc := &DocumentService{
		storage:        store,
		opaClient:      opaClient,
		opaURL:         fmt.Sprintf("%s://%s:%d/v1/data/demo/authorization/decision", opaScheme, cfg.OPA.Host, cfg.OPA.Port),
		opaManageURL:   fmt.Sprintf("%s://%s:%d/v1/data/demo/authorization/management/decision", opaScheme, cfg.OPA.Host, cfg.OPA.Port),
		log:            log,
		workloadClient: workloadClient,
		mockMode:       cfg.Service.MockSPIFFE,
	}

	// Initialize JWT validator if enabled
	if cfg.JWT.ValidationEnabled && cfg.JWT.IssuerURL != "" {
		svc.jwtValidator = auth.NewJWTValidatorFromIssuer(cfg.JWT.IssuerURL, cfg.JWT.ExpectedAudience)
		log.Info("JWT validation enabled",
			"issuer", cfg.JWT.IssuerURL,
			"audience", cfg.JWT.ExpectedAudience)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", svc.handleHealth)
	mux.HandleFunc("/documents", svc.handleDocuments)
	mux.HandleFunc("/documents/", svc.handleDocumentByID)
	mux.HandleFunc("/access", svc.handleAccess)

	// Wrap with SPIFFE identity middleware
	// In plain HTTP mode (AuthBridge/Envoy), use header-based identity like mock mode
	handler := spiffe.IdentityMiddleware(cfg.Service.MockSPIFFE || cfg.Service.ListenPlainHTTP)(mux)

	// Create server: plain HTTP when behind Envoy proxy, mTLS otherwise
	var server *http.Server
	if cfg.Service.ListenPlainHTTP {
		server = &http.Server{
			Addr:    cfg.Service.Addr(),
			Handler: handler,
		}
	} else {
		server = workloadClient.CreateHTTPServer(cfg.Service.Addr(), handler)
	}
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

	// Get document count
	docs, _ := store.ListMetadata(ctx)
	docCount := len(docs)

	log.Section("STARTING DOCUMENT SERVICE")
	log.Info("Document Service starting", "addr", cfg.Service.Addr())
	log.Info("Health server starting", "addr", cfg.Service.HealthAddr())
	log.Info("Loaded documents", "count", docCount)
	log.Info("Storage backend", "type", storageType(cfg.Storage.Enabled))
	log.Info("OPA endpoint", "url", svc.opaURL)
	log.Info("mTLS mode", "enabled", !cfg.Service.MockSPIFFE && !cfg.Service.ListenPlainHTTP)
	if cfg.Service.ListenPlainHTTP {
		log.Info("Plain HTTP listener enabled (AuthBridge/Envoy mode)")
	}
	log.Info("JWT validation", "enabled", svc.jwtValidator != nil)

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

	// Start main server (mTLS if not in mock mode and not behind Envoy)
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
	log.Info("Document service stopped")
	return nil
}

func storageType(enabled bool) string {
	if enabled {
		return "s3"
	}
	return "mock"
}

func (s *DocumentService) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

// handleDocuments handles GET (list) and POST (create) for /documents
func (s *DocumentService) handleDocuments(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListDocuments(w, r)
	case http.MethodPost:
		s.handleCreateDocument(w, r)
	default:
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDocumentByID handles requests to /documents/{id} and /documents/{id}/content
func (s *DocumentService) handleDocumentByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/documents/")
	if path == "" {
		jsonError(w, "Document ID required", http.StatusBadRequest)
		return
	}

	// Check if this is a content request
	if strings.HasSuffix(path, "/content") {
		docID := strings.TrimSuffix(path, "/content")
		s.handleDocumentContent(w, r, docID)
		return
	}

	// Handle document metadata operations
	switch r.Method {
	case http.MethodGet:
		s.handleGetDocument(w, r, path)
	case http.MethodPut:
		s.handleUpdateDocument(w, r, path)
	case http.MethodDelete:
		s.handleDeleteDocument(w, r, path)
	default:
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *DocumentService) handleListDocuments(w http.ResponseWriter, r *http.Request) {
	docs, err := s.storage.ListMetadata(r.Context())
	if err != nil {
		s.log.Error("Failed to list documents", "error", err)
		jsonError(w, "Failed to list documents", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(docs)
}

func (s *DocumentService) handleGetDocument(w http.ResponseWriter, r *http.Request, docID string) {
	meta, err := s.storage.GetMetadata(r.Context(), docID)
	if err != nil {
		var notFound *storage.ErrNotFound
		if errors.As(err, &notFound) {
			jsonError(w, "Document not found", http.StatusNotFound)
			return
		}
		s.log.Error("Failed to get document", "error", err)
		jsonError(w, "Failed to get document", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(meta)
}

func (s *DocumentService) handleDocumentContent(w http.ResponseWriter, r *http.Request, docID string) {
	if r.Method != http.MethodGet {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get caller SPIFFE ID
	callerSPIFFEID := r.Header.Get("X-SPIFFE-ID")
	if callerSPIFFEID == "" {
		callerSPIFFEID = spiffe.GetSPIFFEIDFromRequest(r)
	}
	if callerSPIFFEID == "" {
		jsonError(w, "SPIFFE ID required", http.StatusUnauthorized)
		return
	}

	// Get document metadata for authorization
	meta, err := s.storage.GetMetadata(r.Context(), docID)
	if err != nil {
		var notFound *storage.ErrNotFound
		if errors.As(err, &notFound) {
			jsonError(w, "Document not found", http.StatusNotFound)
			return
		}
		s.log.Error("Failed to get document metadata", "error", err)
		jsonError(w, "Failed to get document", http.StatusInternalServerError)
		return
	}

	// Check authorization (no user departments for this path - not JWT-authenticated)
	allowed, reason, err := s.checkAuthorization(r.Context(), callerSPIFFEID, docID, meta, nil, nil)
	if err != nil {
		s.log.Error("Authorization check failed", "error", err)
		jsonError(w, "Authorization failed", http.StatusInternalServerError)
		return
	}

	if !allowed {
		s.log.Deny(reason)
		metrics.AuthorizationDecisions.WithLabelValues("document-service", "deny", "user").Inc()
		jsonError(w, "Access denied: "+reason, http.StatusForbidden)
		return
	}

	s.log.Allow(reason)
	metrics.AuthorizationDecisions.WithLabelValues("document-service", "allow", "user").Inc()

	// Get content
	content, err := s.storage.GetContent(r.Context(), docID)
	if err != nil {
		var notFound *storage.ErrNotFound
		if errors.As(err, &notFound) {
			jsonError(w, "Document content not found", http.StatusNotFound)
			return
		}
		s.log.Error("Failed to get document content", "error", err)
		jsonError(w, "Failed to get content", http.StatusInternalServerError)
		return
	}
	defer content.Close()

	w.Header().Set("Content-Type", "text/markdown")
	io.Copy(w, content)
}

func (s *DocumentService) handleCreateDocument(w http.ResponseWriter, r *http.Request) {
	callerSPIFFEID := r.Header.Get("X-SPIFFE-ID")
	if callerSPIFFEID == "" {
		callerSPIFFEID = spiffe.GetSPIFFEIDFromRequest(r)
	}
	if callerSPIFFEID == "" {
		jsonError(w, "SPIFFE ID required", http.StatusUnauthorized)
		return
	}

	// Check management authorization
	allowed, reason, err := s.checkManagementAuthorization(r.Context(), callerSPIFFEID)
	if err != nil {
		s.log.Error("Management authorization check failed", "error", err)
		jsonError(w, "Authorization failed", http.StatusInternalServerError)
		return
	}
	if !allowed {
		s.log.Deny(reason)
		jsonError(w, "Access denied: "+reason, http.StatusForbidden)
		return
	}

	// Parse request - support both JSON and multipart
	contentType := r.Header.Get("Content-Type")
	var meta *storage.DocumentMetadata
	var content io.Reader

	if strings.HasPrefix(contentType, "multipart/form-data") {
		// Multipart form upload
		var parsedMeta *storage.DocumentMetadata
		var fileContent io.Reader
		var parseErr error
		parsedMeta, fileContent, parseErr = s.parseMultipartCreate(r)
		if parseErr != nil {
			jsonError(w, parseErr.Error(), http.StatusBadRequest)
			return
		}
		meta = parsedMeta
		content = fileContent
	} else {
		// JSON body
		var req CreateDocumentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if req.ID == "" || req.Title == "" {
			jsonError(w, "ID and title are required", http.StatusBadRequest)
			return
		}
		meta = &storage.DocumentMetadata{
			ID:                  req.ID,
			Title:               req.Title,
			RequiredDepartment:  req.RequiredDepartment,
			RequiredDepartments: req.RequiredDepartments,
			Sensitivity:         req.Sensitivity,
		}
		if req.Content != "" {
			content = strings.NewReader(req.Content)
		}
	}

	// Check if document already exists
	_, err = s.storage.GetMetadata(r.Context(), meta.ID)
	if err == nil {
		jsonError(w, "Document already exists", http.StatusConflict)
		return
	}
	var notFound *storage.ErrNotFound
	if !errors.As(err, &notFound) {
		s.log.Error("Failed to check document existence", "error", err)
		jsonError(w, "Failed to create document", http.StatusInternalServerError)
		return
	}

	// Save metadata
	if err := s.storage.PutMetadata(r.Context(), meta); err != nil {
		s.log.Error("Failed to save document metadata", "error", err)
		jsonError(w, "Failed to create document", http.StatusInternalServerError)
		return
	}

	// Save content if provided
	if content != nil {
		if err := s.storage.PutContent(r.Context(), meta.ID, content); err != nil {
			s.log.Error("Failed to save document content", "error", err)
			// Try to clean up metadata
			s.storage.DeleteMetadata(r.Context(), meta.ID)
			jsonError(w, "Failed to save document content", http.StatusInternalServerError)
			return
		}
	}

	s.log.Info("Document created", "id", meta.ID, "title", meta.Title)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(meta)
}

func (s *DocumentService) parseMultipartCreate(r *http.Request) (*storage.DocumentMetadata, io.Reader, error) {
	// Parse multipart form (max 10MB)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		return nil, nil, fmt.Errorf("failed to parse multipart form: %w", err)
	}

	// Get metadata from form
	metadataStr := r.FormValue("metadata")
	if metadataStr == "" {
		return nil, nil, fmt.Errorf("metadata field is required")
	}

	var req CreateDocumentRequest
	if err := json.Unmarshal([]byte(metadataStr), &req); err != nil {
		return nil, nil, fmt.Errorf("invalid metadata JSON: %w", err)
	}
	if req.ID == "" || req.Title == "" {
		return nil, nil, fmt.Errorf("id and title are required in metadata")
	}

	meta := &storage.DocumentMetadata{
		ID:                  req.ID,
		Title:               req.Title,
		RequiredDepartment:  req.RequiredDepartment,
		RequiredDepartments: req.RequiredDepartments,
		Sensitivity:         req.Sensitivity,
	}

	// Get file from form
	var content io.Reader
	file, _, err := r.FormFile("file")
	if err != nil && err != http.ErrMissingFile {
		return nil, nil, fmt.Errorf("failed to get file: %w", err)
	}
	if file != nil {
		// Read file into buffer since we need to return it
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, file); err != nil {
			file.Close()
			return nil, nil, fmt.Errorf("failed to read file: %w", err)
		}
		file.Close()
		content = buf
	}

	return meta, content, nil
}

func (s *DocumentService) handleUpdateDocument(w http.ResponseWriter, r *http.Request, docID string) {
	callerSPIFFEID := r.Header.Get("X-SPIFFE-ID")
	if callerSPIFFEID == "" {
		callerSPIFFEID = spiffe.GetSPIFFEIDFromRequest(r)
	}
	if callerSPIFFEID == "" {
		jsonError(w, "SPIFFE ID required", http.StatusUnauthorized)
		return
	}

	// Check management authorization
	allowed, reason, err := s.checkManagementAuthorization(r.Context(), callerSPIFFEID)
	if err != nil {
		s.log.Error("Management authorization check failed", "error", err)
		jsonError(w, "Authorization failed", http.StatusInternalServerError)
		return
	}
	if !allowed {
		s.log.Deny(reason)
		jsonError(w, "Access denied: "+reason, http.StatusForbidden)
		return
	}

	// Check if document exists
	_, err = s.storage.GetMetadata(r.Context(), docID)
	if err != nil {
		var notFound *storage.ErrNotFound
		if errors.As(err, &notFound) {
			jsonError(w, "Document not found", http.StatusNotFound)
			return
		}
		s.log.Error("Failed to get document", "error", err)
		jsonError(w, "Failed to update document", http.StatusInternalServerError)
		return
	}

	// Parse request
	contentType := r.Header.Get("Content-Type")
	var meta *storage.DocumentMetadata
	var content io.Reader

	if strings.HasPrefix(contentType, "multipart/form-data") {
		parsedMeta, fileContent, parseErr := s.parseMultipartCreate(r)
		if parseErr != nil {
			jsonError(w, parseErr.Error(), http.StatusBadRequest)
			return
		}
		// Ensure ID matches path
		parsedMeta.ID = docID
		meta = parsedMeta
		content = fileContent
	} else {
		var req CreateDocumentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		meta = &storage.DocumentMetadata{
			ID:                  docID,
			Title:               req.Title,
			RequiredDepartment:  req.RequiredDepartment,
			RequiredDepartments: req.RequiredDepartments,
			Sensitivity:         req.Sensitivity,
		}
		if req.Content != "" {
			content = strings.NewReader(req.Content)
		}
	}

	// Update metadata
	if err := s.storage.PutMetadata(r.Context(), meta); err != nil {
		s.log.Error("Failed to update document metadata", "error", err)
		jsonError(w, "Failed to update document", http.StatusInternalServerError)
		return
	}

	// Update content if provided
	if content != nil {
		if err := s.storage.PutContent(r.Context(), docID, content); err != nil {
			s.log.Error("Failed to update document content", "error", err)
			jsonError(w, "Failed to update document content", http.StatusInternalServerError)
			return
		}
	}

	s.log.Info("Document updated", "id", docID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(meta)
}

func (s *DocumentService) handleDeleteDocument(w http.ResponseWriter, r *http.Request, docID string) {
	callerSPIFFEID := r.Header.Get("X-SPIFFE-ID")
	if callerSPIFFEID == "" {
		callerSPIFFEID = spiffe.GetSPIFFEIDFromRequest(r)
	}
	if callerSPIFFEID == "" {
		jsonError(w, "SPIFFE ID required", http.StatusUnauthorized)
		return
	}

	// Check management authorization
	allowed, reason, err := s.checkManagementAuthorization(r.Context(), callerSPIFFEID)
	if err != nil {
		s.log.Error("Management authorization check failed", "error", err)
		jsonError(w, "Authorization failed", http.StatusInternalServerError)
		return
	}
	if !allowed {
		s.log.Deny(reason)
		jsonError(w, "Access denied: "+reason, http.StatusForbidden)
		return
	}

	// Delete content (ignore not found)
	_ = s.storage.DeleteContent(r.Context(), docID)

	// Delete metadata
	if err := s.storage.DeleteMetadata(r.Context(), docID); err != nil {
		var notFound *storage.ErrNotFound
		if errors.As(err, &notFound) {
			jsonError(w, "Document not found", http.StatusNotFound)
			return
		}
		s.log.Error("Failed to delete document", "error", err)
		jsonError(w, "Failed to delete document", http.StatusInternalServerError)
		return
	}

	s.log.Info("Document deleted", "id", docID)
	w.WriteHeader(http.StatusNoContent)
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

	// Check for JWT access token (AuthBridge token exchange mode)
	// JWT validation runs first because the caller SPIFFE ID may come from the JWT's azp claim
	var jwtClaims *auth.AccessTokenClaims
	if s.jwtValidator != nil {
		if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			claims, jwtErr := s.jwtValidator.ValidateAccessToken(tokenStr)
			if jwtErr != nil {
				s.log.Error("JWT validation failed", "error", jwtErr)
				jsonError(w, "JWT validation failed: "+jwtErr.Error(), http.StatusUnauthorized)
				return
			}
			jwtClaims = claims
			s.log.Info("JWT validated successfully",
				"sub", claims.Subject,
				"aud", []string(claims.Audience),
				"groups", claims.Groups,
				"azp", claims.AuthorizedParty)

			// Use JWT groups as user departments if not already provided in request body
			if len(req.UserDepartments) == 0 && req.Delegation == nil {
				req.UserDepartments = claims.Groups
			}
			if req.Delegation != nil && len(req.Delegation.UserDepartments) == 0 {
				req.Delegation.UserDepartments = claims.Groups
			}
		}
	}

	// Get caller SPIFFE ID from header, TLS peer cert, or JWT azp claim
	callerSPIFFEID := r.Header.Get("X-SPIFFE-ID")
	if callerSPIFFEID == "" {
		callerSPIFFEID = spiffe.GetSPIFFEIDFromRequest(r)
	}
	if callerSPIFFEID == "" && jwtClaims != nil {
		callerSPIFFEID = jwtClaims.AuthorizedParty
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
		"has_delegation", req.Delegation != nil,
		"jwt_authenticated", jwtClaims != nil)

	// Get document metadata
	meta, err := s.storage.GetMetadata(r.Context(), req.DocumentID)
	if err != nil {
		var notFound *storage.ErrNotFound
		if errors.As(err, &notFound) {
			s.log.Error("Document not found", "document_id", req.DocumentID)
			jsonError(w, "Document not found", http.StatusNotFound)
			return
		}
		s.log.Error("Failed to get document", "error", err)
		jsonError(w, "Failed to get document", http.StatusInternalServerError)
		return
	}

	// Query OPA for authorization
	// User departments come from:
	// - req.Delegation.UserDepartments for delegated access (agent on behalf of user)
	// - req.UserDepartments for direct access (user via dashboard)
	userDepts := req.UserDepartments
	if req.Delegation != nil && len(req.Delegation.UserDepartments) > 0 {
		userDepts = req.Delegation.UserDepartments
	}
	allowed, reason, err := s.checkAuthorization(r.Context(), callerSPIFFEID, req.DocumentID, meta, req.Delegation, userDepts)
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
	s.log.Document(meta.ID, "Returning document content")

	// Get content
	content, err := s.storage.GetContent(r.Context(), req.DocumentID)
	if err != nil {
		var notFound *storage.ErrNotFound
		if errors.As(err, &notFound) {
			// Document exists but no content - return metadata only
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"document": meta,
				"access": map[string]any{
					"granted": true,
					"reason":  reason,
				},
			})
			return
		}
		s.log.Error("Failed to get document content", "error", err)
		jsonError(w, "Failed to get content", http.StatusInternalServerError)
		return
	}
	defer content.Close()

	contentBytes, err := io.ReadAll(content)
	if err != nil {
		s.log.Error("Failed to read document content", "error", err)
		jsonError(w, "Failed to read content", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"document": map[string]any{
			"id":                   meta.ID,
			"title":                meta.Title,
			"sensitivity":          meta.Sensitivity,
			"required_department":  meta.RequiredDepartment,
			"required_departments": meta.RequiredDepartments,
			"content":              string(contentBytes),
		},
		"access": map[string]any{
			"granted": true,
			"reason":  reason,
		},
	})
}

func (s *DocumentService) checkAuthorization(ctx context.Context, callerSPIFFEID, documentID string, meta *storage.DocumentMetadata, delegation *Delegation, userDepartments []string) (bool, string, error) {
	queryLog := logger.New(logger.ComponentOPAQuery)

	// Build document metadata for OPA
	opaMeta := &OPADocumentMeta{
		RequiredDepartment:  meta.RequiredDepartment,
		RequiredDepartments: meta.RequiredDepartments,
		Sensitivity:         meta.Sensitivity,
	}

	// For delegation, user_departments is inside the delegation object
	// For direct access, user_departments comes from the request
	opaReq := OPARequest{
		Input: OPAInput{
			CallerSPIFFEID:   callerSPIFFEID,
			DocumentID:       documentID,
			DocumentMetadata: opaMeta,
			Delegation:       delegation,
			UserDepartments:  userDepartments,
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

func (s *DocumentService) checkManagementAuthorization(ctx context.Context, callerSPIFFEID string) (bool, string, error) {
	queryLog := logger.New(logger.ComponentOPAQuery)

	opaReq := OPARequest{
		Input: OPAInput{
			CallerSPIFFEID: callerSPIFFEID,
		},
	}

	queryLog.Info("Querying OPA for management authorization",
		"caller", callerSPIFFEID)

	reqBody, err := json.Marshal(opaReq)
	if err != nil {
		return false, "", fmt.Errorf("failed to marshal OPA request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.opaManageURL, bytes.NewReader(reqBody))
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
	evalLog.Info("Management policy evaluation complete",
		"allow", opaResp.Result.Allow,
		"reason", opaResp.Result.Reason)

	return opaResp.Result.Allow, opaResp.Result.Reason, nil
}

// Ensure multipart.File interface is satisfied
var _ io.Reader = (multipart.File)(nil)
