package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"

	"github.com/redhat-et/zero-trust-agent-demo/pkg/auth"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/config"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/logger"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/spiffe"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the credential gateway",
	Long:  `Start the credential gateway on the configured port.`,
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

// AWSConfig holds AWS STS configuration
type AWSConfig struct {
	RoleARN     string `mapstructure:"role_arn"`
	Region      string `mapstructure:"region"`
	S3Bucket    string `mapstructure:"s3_bucket"`
	STSDuration int32  `mapstructure:"sts_duration"`
}

// Config holds the credential gateway configuration
type Config struct {
	config.CommonConfig `mapstructure:",squash"`
	JWT                 JWTConfig `mapstructure:"jwt"`
	AWS                 AWSConfig `mapstructure:"aws"`
}

// CredentialRequest is the incoming request for scoped credentials
type CredentialRequest struct {
	TargetService string `json:"target_service"`
	Action        string `json:"action"`
}

// CredentialResponse is the response with scoped credentials
type CredentialResponse struct {
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key"`
	SessionToken    string    `json:"session_token"`
	Expiration      time.Time `json:"expiration"`
	SessionName     string    `json:"session_name"`
	ScopedPrefixes  []string  `json:"scoped_prefixes"`
}

// OPAIntersectionRequest is the request to OPA for permission intersection
type OPAIntersectionRequest struct {
	Input OPAIntersectionInput `json:"input"`
}

// OPAIntersectionInput is the input to OPA
type OPAIntersectionInput struct {
	User          string `json:"user"`
	Agent         string `json:"agent"`
	TargetService string `json:"target_service"`
	Action        string `json:"action"`
	S3Key         string `json:"s3_key,omitempty"`
}

// OPAIntersectionResponse is the response from OPA
type OPAIntersectionResponse struct {
	Result struct {
		Allow              bool     `json:"allow"`
		AllowedDepartments []string `json:"allowed_departments"`
		Reason             string   `json:"reason"`
	} `json:"result"`
}

// OPAProxyResponse is the response from OPA for per-object proxy decisions
type OPAProxyResponse struct {
	Result struct {
		Allow  bool   `json:"allow"`
		Reason string `json:"reason"`
	} `json:"result"`
}

// errOPAUnavailable signals that OPA could not be reached (distinct from policy deny)
var errOPAUnavailable = errors.New("OPA service unavailable")

// Gateway is the credential gateway service
type Gateway struct {
	stsClient    *sts.Client
	s3Client     *s3.Client
	opaClient    *http.Client
	opaURL       string
	proxyOPAURL  string
	jwtValidator *auth.JWTValidator
	devMode      bool
	log          *logger.Logger
	awsCfg       AWSConfig
}

// jsonError writes a JSON error response
func jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func runServe(cmd *cobra.Command, args []string) error {
	var cfg Config
	if err := config.Load(v, &cfg); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	log := logger.New(logger.ComponentCredGateway)

	// Validate required config
	if cfg.AWS.RoleARN == "" {
		return fmt.Errorf("aws.role_arn is required (set --aws-role-arn or SPIFFE_DEMO_AWS_ROLE_ARN)")
	}
	if cfg.AWS.S3Bucket == "" {
		return fmt.Errorf("aws.s3_bucket is required (set --s3-bucket or SPIFFE_DEMO_AWS_S3_BUCKET)")
	}

	ctx := context.Background()

	// Initialize AWS STS client
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.AWS.Region),
	)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}
	stsClient := sts.NewFromConfig(awsCfg)
	s3Client := s3.NewFromConfig(awsCfg)

	// Verify STS access
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("failed to verify AWS credentials: %w", err)
	}
	log.Info("AWS identity verified",
		"account", *identity.Account,
		"arn", *identity.Arn)

	// Initialize SPIFFE workload client (for mTLS to OPA)
	spiffeCfg := spiffe.Config{
		SocketPath:  cfg.SPIFFE.SocketPath,
		TrustDomain: cfg.SPIFFE.TrustDomain,
		MockMode:    cfg.Service.MockSPIFFE,
	}
	workloadClient := spiffe.NewWorkloadClient(spiffeCfg, log)

	if !cfg.Service.MockSPIFFE {
		identity, err := workloadClient.FetchIdentity(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch SPIFFE identity: %w", err)
		}
		log.Info("SPIFFE identity acquired", "spiffe_id", identity.SPIFFEID)
	} else {
		workloadClient.SetMockIdentity("spiffe://" + cfg.SPIFFE.TrustDomain + "/service/credential-gateway")
	}

	// Create mTLS HTTP client for OPA requests (follows document-service pattern)
	opaClient := workloadClient.CreateMTLSClient(5 * time.Second)
	opaScheme := "http"
	if !cfg.Service.MockSPIFFE {
		opaScheme = "https"
	}

	gw := &Gateway{
		stsClient:   stsClient,
		s3Client:    s3Client,
		opaClient:   opaClient,
		opaURL:      fmt.Sprintf("%s://%s:%d/v1/data/demo/credential_gateway/decision", opaScheme, cfg.OPA.Host, cfg.OPA.Port),
		proxyOPAURL: fmt.Sprintf("%s://%s:%d/v1/data/demo/credential_gateway/proxy_decision", opaScheme, cfg.OPA.Host, cfg.OPA.Port),
		log:         log,
		awsCfg:      cfg.AWS,
	}

	// Initialize JWT validator
	if cfg.JWT.ValidationEnabled && cfg.JWT.IssuerURL != "" {
		gw.jwtValidator = auth.NewJWTValidatorFromIssuer(cfg.JWT.IssuerURL, cfg.JWT.ExpectedAudience)
		log.Info("JWT validation enabled",
			"issuer", cfg.JWT.IssuerURL,
			"audience", cfg.JWT.ExpectedAudience)
	} else if !cfg.JWT.ValidationEnabled {
		gw.devMode = true
		log.Warn("JWT validation DISABLED (dev mode) -- tokens are not verified")
	} else {
		return fmt.Errorf("jwt validation is required (set --jwt-issuer-url or disable with --jwt-validation-enabled=false)")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", gw.handleHealth)
	mux.HandleFunc("/credentials", gw.handleCredentials)
	mux.HandleFunc("/s3-proxy/", gw.handleS3Proxy)

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

		log.Info("Shutting down credential gateway...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Error("Shutdown error", "error", err)
		}
		close(done)
	}()

	// Start health server
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", gw.handleHealth)
	healthMux.HandleFunc("/ready", gw.handleHealth)
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

	log.Section("STARTING CREDENTIAL GATEWAY")
	log.Info("Credential Gateway starting", "addr", cfg.Service.Addr())
	log.Info("Health server starting", "addr", cfg.Service.HealthAddr())
	log.Info("AWS role", "arn", cfg.AWS.RoleARN)
	log.Info("S3 bucket", "name", cfg.AWS.S3Bucket)
	log.Info("STS duration", "seconds", cfg.AWS.STSDuration)
	log.Info("OPA endpoint", "url", gw.opaURL)

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	<-done
	log.Info("Credential gateway stopped")
	return nil
}

func (gw *Gateway) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func (gw *Gateway) handleCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract and validate JWT
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		jsonError(w, "Authorization header with Bearer token required", http.StatusUnauthorized)
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	// Parse the JWT claims (validate if validator is configured, otherwise just decode)
	claims, err := gw.extractClaims(tokenStr)
	if err != nil {
		gw.log.Error("JWT validation failed", "error", err)
		jsonError(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Parse request body
	var req CredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.TargetService == "" {
		req.TargetService = "s3"
	}
	if req.Action == "" {
		req.Action = "read"
	}

	// Extract delegation chain from act claims
	user, agent := gw.extractDelegationChain(claims)

	gw.log.Section("CREDENTIAL REQUEST")
	gw.log.Info("Received credential request",
		"user", user,
		"agent", agent,
		"target", req.TargetService,
		"action", req.Action)

	// Query OPA for permission intersection
	departments, err := gw.queryOPAIntersection(r.Context(), user, agent, req.TargetService, req.Action)
	if err != nil {
		if errors.Is(err, errOPAUnavailable) {
			gw.log.Error("OPA service unavailable", "error", err)
			jsonError(w, "Policy engine unavailable", http.StatusServiceUnavailable)
		} else {
			gw.log.Error("OPA policy denied", "error", err)
			jsonError(w, "Authorization failed: "+err.Error(), http.StatusForbidden)
		}
		return
	}

	if len(departments) == 0 {
		gw.log.Info("No overlapping permissions", "user", user, "agent", agent)
		jsonError(w, "No overlapping permissions between user and agent", http.StatusForbidden)
		return
	}

	gw.log.Info("Permission intersection computed",
		"departments", departments)

	// Generate STS credentials scoped to the intersection
	creds, err := gw.assumeRoleWithSessionPolicy(r.Context(), user, agent, departments)
	if err != nil {
		gw.log.Error("STS AssumeRole failed", "error", err)
		jsonError(w, "Failed to generate credentials: "+err.Error(), http.StatusInternalServerError)
		return
	}

	gw.log.Info("Scoped credentials issued",
		"session", creds.SessionName,
		"prefixes", creds.ScopedPrefixes,
		"expires", creds.Expiration.Format(time.RFC3339))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(creds)
}

// extractClaims parses JWT claims, validating signature if validator is configured.
// In dev mode (mock-spiffe), it decodes without verification for local testing.
func (gw *Gateway) extractClaims(tokenStr string) (*auth.AccessTokenClaims, error) {
	if gw.jwtValidator != nil {
		return gw.jwtValidator.ValidateAccessToken(tokenStr)
	}

	if !gw.devMode {
		return nil, fmt.Errorf("JWT validation not configured")
	}

	// Dev mode only: decode payload without signature verification
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	payload, err := base64Decode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims auth.AccessTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	return &claims, nil
}

// extractDelegationChain extracts user and agent from JWT claims.
// With act claims (RFC 8693): sub=user, act.sub=immediate actor
// Without act claims: sub=user, azp=agent (authorized party fallback)
func (gw *Gateway) extractDelegationChain(claims *auth.AccessTokenClaims) (user, agent string) {
	user = claims.Subject
	if claims.PreferredUsername != "" {
		user = claims.PreferredUsername
	}

	// Prefer act claim (RFC 8693) over azp for agent identity
	if claims.Act != nil && claims.Act.Sub != "" {
		agent = claims.Act.Sub
	} else {
		agent = claims.AuthorizedParty
	}

	return user, agent
}

// queryOPAIntersection asks OPA for the permission intersection between user and agent
func (gw *Gateway) queryOPAIntersection(ctx context.Context, user, agent, targetService, action string) ([]string, error) {
	opaReq := OPAIntersectionRequest{
		Input: OPAIntersectionInput{
			User:          user,
			Agent:         agent,
			TargetService: targetService,
			Action:        action,
		},
	}

	reqBody, err := json.Marshal(opaReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OPA request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gw.opaURL, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to create OPA request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := gw.opaClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errOPAUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", errOPAUnavailable, resp.StatusCode)
	}

	var opaResp OPAIntersectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return nil, fmt.Errorf("failed to decode OPA response: %w", err)
	}

	if !opaResp.Result.Allow {
		return nil, fmt.Errorf("access denied: %s", opaResp.Result.Reason)
	}

	return opaResp.Result.AllowedDepartments, nil
}

// assumeRoleWithSessionPolicy calls STS AssumeRole with an inline session
// policy that restricts S3 access to the given department prefixes.
func (gw *Gateway) assumeRoleWithSessionPolicy(ctx context.Context, user, agent string, departments []string) (*CredentialResponse, error) {
	// Build session name for audit trail
	sessionName := sanitizeSessionName(fmt.Sprintf("%s-via-%s", user, agent))

	// Build S3 resource ARNs for each department prefix
	bucketARN := fmt.Sprintf("arn:aws:s3:::%s", gw.awsCfg.S3Bucket)
	objectARNs := make([]string, len(departments))
	for i, dept := range departments {
		objectARNs[i] = fmt.Sprintf("arn:aws:s3:::%s/%s/*", gw.awsCfg.S3Bucket, dept)
	}

	// Build session policy JSON
	sessionPolicy := buildSessionPolicy(bucketARN, objectARNs, departments)

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(gw.awsCfg.RoleARN),
		RoleSessionName: aws.String(sessionName),
		Policy:          aws.String(sessionPolicy),
		DurationSeconds: aws.Int32(gw.awsCfg.STSDuration),
	}

	result, err := gw.stsClient.AssumeRole(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("AssumeRole failed: %w", err)
	}

	prefixes := make([]string, len(departments))
	for i, d := range departments {
		prefixes[i] = d + "/"
	}

	return &CredentialResponse{
		AccessKeyID:     *result.Credentials.AccessKeyId,
		SecretAccessKey: *result.Credentials.SecretAccessKey,
		SessionToken:    *result.Credentials.SessionToken,
		Expiration:      *result.Credentials.Expiration,
		SessionName:     sessionName,
		ScopedPrefixes:  prefixes,
	}, nil
}

// buildSessionPolicy creates an IAM session policy JSON document.
// ListBucket is restricted to allowed prefixes via s3:prefix condition.
// GetObject is restricted via object-level ARNs.
func buildSessionPolicy(bucketARN string, objectARNs, prefixes []string) string {
	quotedObjectARNs := make([]string, len(objectARNs))
	for i, r := range objectARNs {
		quotedObjectARNs[i] = fmt.Sprintf("%q", r)
	}

	quotedPrefixes := make([]string, len(prefixes))
	for i, p := range prefixes {
		quotedPrefixes[i] = fmt.Sprintf("%q", p+"/*")
	}

	return fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": [%s]
    },
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": %q,
      "Condition": {
        "StringLike": {
          "s3:prefix": [%s]
        }
      }
    }
  ]
}`, strings.Join(quotedObjectARNs, ", "), bucketARN, strings.Join(quotedPrefixes, ", "))
}

// sanitizeSessionName ensures the session name is valid for AWS
// (alphanumeric, plus =,.@- and max 64 chars)
func sanitizeSessionName(name string) string {
	var b strings.Builder
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '=' || c == ',' || c == '.' || c == '@' || c == '-' {
			b.WriteRune(c)
		} else {
			b.WriteRune('-')
		}
	}
	s := b.String()
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

func (gw *Gateway) handleS3Proxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Strip /s3-proxy/ prefix to get the S3 key
	s3Key := strings.TrimPrefix(r.URL.Path, "/s3-proxy/")
	if s3Key == "" {
		jsonError(w, "S3 key is required", http.StatusBadRequest)
		return
	}

	// Extract and validate JWT
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	claims, err := gw.extractClaims(tokenStr)
	if err != nil {
		gw.log.Error("JWT validation failed", "error", err)
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	user, agent := gw.extractDelegationChain(claims)

	gw.log.Section("S3 PROXY REQUEST")
	gw.log.Info("Received S3 proxy request",
		"user", user,
		"agent", agent,
		"s3_key", s3Key)

	// Query OPA for per-object proxy decision
	allowed, reason, err := gw.queryOPAProxy(r.Context(), user, agent, s3Key)
	if err != nil {
		gw.log.Error("OPA proxy query failed", "error", err)
		jsonError(w, "upstream error", http.StatusBadGateway)
		return
	}

	if !allowed {
		gw.log.Info("S3 proxy access denied", "reason", reason)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"error":  "forbidden",
			"reason": reason,
		})
		return
	}

	gw.log.Info("S3 proxy access allowed", "reason", reason)

	// Get the permission intersection to scope the STS credentials
	departments, err := gw.queryOPAIntersection(r.Context(), user, agent, "s3", "read")
	if err != nil {
		gw.log.Error("OPA intersection query failed", "error", err)
		jsonError(w, "upstream error", http.StatusBadGateway)
		return
	}

	// Assume role with scoped session policy
	creds, err := gw.assumeRoleWithSessionPolicy(r.Context(), user, agent, departments)
	if err != nil {
		gw.log.Error("STS AssumeRole failed", "error", err)
		jsonError(w, "upstream error", http.StatusBadGateway)
		return
	}

	// Create a scoped S3 client using the temporary credentials
	scopedCfg, err := awsconfig.LoadDefaultConfig(r.Context(),
		awsconfig.WithRegion(gw.awsCfg.Region),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				creds.AccessKeyID,
				creds.SecretAccessKey,
				creds.SessionToken,
			),
		),
	)
	if err != nil {
		gw.log.Error("Failed to create scoped AWS config", "error", err)
		jsonError(w, "upstream error", http.StatusBadGateway)
		return
	}
	scopedS3 := s3.NewFromConfig(scopedCfg)

	// Fetch the S3 object using scoped credentials
	result, err := scopedS3.GetObject(r.Context(), &s3.GetObjectInput{
		Bucket: aws.String(gw.awsCfg.S3Bucket),
		Key:    aws.String(s3Key),
	})
	if err != nil {
		gw.log.Error("S3 GetObject failed", "error", err, "key", s3Key)
		// Check if it's a not-found error
		if strings.Contains(err.Error(), "NoSuchKey") {
			jsonError(w, "not found", http.StatusNotFound)
		} else if strings.Contains(err.Error(), "AccessDenied") {
			jsonError(w, "forbidden", http.StatusForbidden)
		} else {
			jsonError(w, "upstream error", http.StatusBadGateway)
		}
		return
	}
	defer result.Body.Close()

	gw.log.Info("S3 object fetched",
		"key", s3Key,
		"content_type", aws.ToString(result.ContentType),
		"content_length", aws.ToInt64(result.ContentLength))

	// Stream the object to the response
	w.Header().Set("Content-Type", "text/markdown")
	if result.ContentLength != nil {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", *result.ContentLength))
	}
	w.WriteHeader(http.StatusOK)
	io.Copy(w, result.Body)
}

// queryOPAProxy asks OPA for a per-object S3 proxy decision
func (gw *Gateway) queryOPAProxy(ctx context.Context, user, agent, s3Key string) (bool, string, error) {
	opaReq := OPAIntersectionRequest{
		Input: OPAIntersectionInput{
			User:          user,
			Agent:         agent,
			TargetService: "s3",
			Action:        "read",
			S3Key:         s3Key,
		},
	}

	reqBody, err := json.Marshal(opaReq)
	if err != nil {
		return false, "", fmt.Errorf("failed to marshal OPA request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gw.proxyOPAURL, strings.NewReader(string(reqBody)))
	if err != nil {
		return false, "", fmt.Errorf("failed to create OPA request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := gw.opaClient.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("%w: %v", errOPAUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("%w: status %d", errOPAUnavailable, resp.StatusCode)
	}

	var opaResp OPAProxyResponse
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return false, "", fmt.Errorf("failed to decode OPA response: %w", err)
	}

	return opaResp.Result.Allow, opaResp.Result.Reason, nil
}

// base64Decode handles URL-safe base64 with optional padding
func base64Decode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	return base64.URLEncoding.DecodeString(s)
}
