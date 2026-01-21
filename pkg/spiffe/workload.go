package spiffe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	"github.com/hardwaylabs/spiffe-spire-demo/pkg/logger"
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
	PrivateKey  interface{}
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
	config   Config
	log      *logger.Logger
	identity *WorkloadIdentity
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

	// In real implementation, this would use go-spiffe/v2/workloadapi
	// For now, return a placeholder
	c.log.Info("Connecting to SPIRE Agent", "socket", c.config.SocketPath)
	return nil, fmt.Errorf("real SPIFFE not implemented - use mock mode")
}

// SetMockIdentity sets a mock identity for testing
func (c *WorkloadClient) SetMockIdentity(spiffeID string) {
	c.identity = MockIdentity(spiffeID)
	c.log.SVID(spiffeID, "Using mock SPIFFE identity")
}

// GetIdentity returns the current identity
func (c *WorkloadClient) GetIdentity() *WorkloadIdentity {
	return c.identity
}

// CreateMTLSClient creates an HTTP client configured for mTLS
func (c *WorkloadClient) CreateMTLSClient(timeout time.Duration) *http.Client {
	if c.config.MockMode {
		// In mock mode, return a regular HTTP client
		return &http.Client{
			Timeout: timeout,
		}
	}

	// In real implementation, this would configure TLS with the SVID
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Would be false in production with proper cert verification
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
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
