package spiffe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/redhat-et/zero-trust-agent-demo/pkg/logger"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Config holds SPIFFE-related configuration
type Config struct {
	SocketPath  string
	TrustDomain string
	MockMode    bool
}

// WorkloadIdentity represents a workload's SPIFFE identity
type WorkloadIdentity struct {
	SPIFFEID    string
	Certificate *x509.Certificate
	PrivateKey  any
	TrustBundle []*x509.Certificate
}

// MockIdentity creates a mock identity for local development
func MockIdentity(spiffeID string) *WorkloadIdentity {
	return &WorkloadIdentity{
		SPIFFEID: spiffeID,
	}
}

// WorkloadClient provides SPIFFE workload API functionality
type WorkloadClient struct {
	config     Config
	log        *logger.Logger
	identity   *WorkloadIdentity
	x509Source *workloadapi.X509Source
	mu         sync.RWMutex
}

// NewWorkloadClient creates a new workload client
func NewWorkloadClient(cfg Config, log *logger.Logger) *WorkloadClient {
	return &WorkloadClient{
		config: cfg,
		log:    log,
	}
}

// FetchIdentity fetches the workload's SVID from SPIRE Agent
func (c *WorkloadClient) FetchIdentity(ctx context.Context) (*WorkloadIdentity, error) {
	if c.config.MockMode {
		c.log.Info("Mock mode: Skipping SPIRE Agent connection")
		return nil, nil
	}

	c.log.Info("Connecting to SPIRE Agent", "socket", c.config.SocketPath)

	// Create X509Source - this connects to the SPIRE Agent
	opts := []workloadapi.X509SourceOption{}
	if c.config.SocketPath != "" {
		opts = append(opts, workloadapi.WithClientOptions(
			workloadapi.WithAddr(c.config.SocketPath),
		))
	}

	source, err := workloadapi.NewX509Source(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create X509Source: %w", err)
	}

	// Get the current SVID
	svid, err := source.GetX509SVID()
	if err != nil {
		source.Close()
		return nil, fmt.Errorf("failed to get X509SVID: %w", err)
	}

	// Get the trust bundle
	bundle, err := source.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
	if err != nil {
		source.Close()
		return nil, fmt.Errorf("failed to get trust bundle: %w", err)
	}

	c.mu.Lock()
	c.x509Source = source
	c.identity = &WorkloadIdentity{
		SPIFFEID:    svid.ID.String(),
		Certificate: svid.Certificates[0],
		PrivateKey:  svid.PrivateKey,
		TrustBundle: bundle.X509Authorities(),
	}
	c.mu.Unlock()

	c.log.SVID(c.identity.SPIFFEID, "Acquired X509-SVID from SPIRE Agent")
	c.log.Info("Certificate details",
		"notBefore", c.identity.Certificate.NotBefore,
		"notAfter", c.identity.Certificate.NotAfter,
	)

	return c.identity, nil
}

// SetMockIdentity sets a mock identity for testing
func (c *WorkloadClient) SetMockIdentity(spiffeID string) {
	c.mu.Lock()
	c.identity = MockIdentity(spiffeID)
	c.mu.Unlock()
	c.log.SVID(spiffeID, "Using mock SPIFFE identity")
}

// GetIdentity returns the current identity
func (c *WorkloadClient) GetIdentity() *WorkloadIdentity {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.identity
}

// GetX509Source returns the X509Source for advanced use cases
func (c *WorkloadClient) GetX509Source() *workloadapi.X509Source {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.x509Source
}

// Close closes the X509Source and releases resources
func (c *WorkloadClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.x509Source != nil {
		return c.x509Source.Close()
	}
	return nil
}

// CreateMTLSClient creates an HTTP client configured for mTLS
func (c *WorkloadClient) CreateMTLSClient(timeout time.Duration) *http.Client {
	if c.config.MockMode {
		// In mock mode, return a regular HTTP client
		return &http.Client{
			Timeout: timeout,
		}
	}

	c.mu.RLock()
	source := c.x509Source
	c.mu.RUnlock()

	if source == nil {
		c.log.Error("X509Source not initialized - call FetchIdentity first")
		return &http.Client{Timeout: timeout}
	}

	// Configure mTLS: present our SVID, verify peer's SVID
	tlsConfig := tlsconfig.MTLSClientConfig(
		source,                   // Our identity (X509Source implements X509SVIDSource)
		source,                   // Trust bundle for verifying peers (X509Source implements X509BundleSource)
		tlsconfig.AuthorizeAny(), // Accept any SPIFFE ID in our trust domain
	)

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

// CreateMTLSServerConfig creates a TLS config for mTLS servers
func (c *WorkloadClient) CreateMTLSServerConfig() *tls.Config {
	if c.config.MockMode {
		return nil
	}

	c.mu.RLock()
	source := c.x509Source
	c.mu.RUnlock()

	if source == nil {
		c.log.Error("X509Source not initialized - call FetchIdentity first")
		return nil
	}

	// Configure mTLS server: present our SVID, verify client's SVID
	return tlsconfig.MTLSServerConfig(
		source,                   // Our identity
		source,                   // Trust bundle for verifying clients
		tlsconfig.AuthorizeAny(), // Accept any SPIFFE ID in our trust domain
	)
}

// CreateHTTPServer creates an HTTP server with optional mTLS
func (c *WorkloadClient) CreateHTTPServer(addr string, handler http.Handler) *http.Server {
	server := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	if !c.config.MockMode {
		tlsConfig := c.CreateMTLSServerConfig()
		if tlsConfig != nil {
			server.TLSConfig = tlsConfig
		}
	}

	return server
}

// IdentityMiddleware creates middleware that extracts SPIFFE ID from mTLS
func IdentityMiddleware(mockMode bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if mockMode {
				// In mock mode, SPIFFE ID comes from header
				spiffeID := r.Header.Get("X-SPIFFE-ID")
				if spiffeID != "" {
					r = r.WithContext(context.WithValue(r.Context(), spiffeIDKey, spiffeID))
				}
			} else {
				// In real mode, extract from peer certificate
				if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
					cert := r.TLS.PeerCertificates[0]
					if len(cert.URIs) > 0 {
						spiffeID := cert.URIs[0].String()
						r = r.WithContext(context.WithValue(r.Context(), spiffeIDKey, spiffeID))
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

type contextKey string

const spiffeIDKey contextKey = "spiffe-id"

// GetSPIFFEIDFromContext extracts the SPIFFE ID from the request context
func GetSPIFFEIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(spiffeIDKey).(string); ok {
		return id
	}
	return ""
}

// GetSPIFFEIDFromRequest extracts the SPIFFE ID from the request
func GetSPIFFEIDFromRequest(r *http.Request) string {
	// First try context
	if id := GetSPIFFEIDFromContext(r.Context()); id != "" {
		return id
	}
	// Fall back to header (mock mode)
	return r.Header.Get("X-SPIFFE-ID")
}
