package a2abridge

import (
	"context"
	"net/http"
)

// DelegationContext carries user and agent SPIFFE IDs through the request
// context so that outbound HTTP requests can include delegation headers
// without the agent code being aware of authentication.
type DelegationContext struct {
	UserSPIFFEID  string
	AgentSPIFFEID string
}

type delegationKey struct{}

// WithDelegation stores delegation context in a Go context.
func WithDelegation(ctx context.Context, dc DelegationContext) context.Context {
	return context.WithValue(ctx, delegationKey{}, dc)
}

// DelegationFrom retrieves delegation context from a Go context.
func DelegationFrom(ctx context.Context) (DelegationContext, bool) {
	dc, ok := ctx.Value(delegationKey{}).(DelegationContext)
	return dc, ok
}

// DelegationTransport is an http.RoundTripper that injects X-Delegation-User
// and X-Delegation-Agent headers from the request context into outbound HTTP
// requests. This allows delegation context to flow transparently through
// agent code that has no knowledge of authentication or authorization.
//
// Usage:
//
//	httpClient := &http.Client{
//	    Transport: &a2abridge.DelegationTransport{Base: http.DefaultTransport},
//	    Timeout:   30 * time.Second,
//	}
type DelegationTransport struct {
	Base http.RoundTripper
}

// RoundTrip implements http.RoundTripper. If the request context contains
// delegation info, it clones the request and adds the delegation headers.
func (t *DelegationTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	dc, ok := DelegationFrom(req.Context())
	if ok && (dc.UserSPIFFEID != "" || dc.AgentSPIFFEID != "") {
		req = req.Clone(req.Context())
		if dc.UserSPIFFEID != "" {
			req.Header.Set("X-Delegation-User", dc.UserSPIFFEID)
		}
		if dc.AgentSPIFFEID != "" {
			req.Header.Set("X-Delegation-Agent", dc.AgentSPIFFEID)
		}
	}
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}
