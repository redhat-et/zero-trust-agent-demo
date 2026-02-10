package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// AccessTokenClaims represents claims extracted from an access token
type AccessTokenClaims struct {
	Subject           string   `json:"sub"`
	PreferredUsername  string   `json:"preferred_username"`
	Issuer            string   `json:"iss"`
	Audience          audience `json:"aud"`
	Groups            []string `json:"groups"`
	ExpiresAt         int64    `json:"exp"`
	IssuedAt          int64    `json:"iat"`
	AuthorizedParty   string   `json:"azp"`
	Scope             string   `json:"scope"`
}

// audience handles both string and []string forms of the "aud" claim
type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	// Try string first
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*a = audience{s}
		return nil
	}
	// Try []string
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return fmt.Errorf("aud claim is neither string nor array: %w", err)
	}
	*a = audience(arr)
	return nil
}

// JWTValidator validates JWT access tokens using JWKS from Keycloak
type JWTValidator struct {
	jwksURL          string
	expectedIssuer   string
	expectedAudience string

	mu      sync.RWMutex
	jwks    *jose.JSONWebKeySet
	fetched time.Time
}

// NewJWTValidator creates a new JWT access token validator
func NewJWTValidator(jwksURL, expectedIssuer, expectedAudience string) *JWTValidator {
	return &JWTValidator{
		jwksURL:          jwksURL,
		expectedIssuer:   expectedIssuer,
		expectedAudience: expectedAudience,
	}
}

// NewJWTValidatorFromIssuer creates a validator using the issuer URL to derive the JWKS URL
func NewJWTValidatorFromIssuer(issuerURL, expectedAudience string) *JWTValidator {
	jwksURL := strings.TrimSuffix(issuerURL, "/") + "/protocol/openid-connect/certs"
	return NewJWTValidator(jwksURL, issuerURL, expectedAudience)
}

// ValidateAccessToken validates a JWT access token and returns the parsed claims
func (v *JWTValidator) ValidateAccessToken(tokenString string) (*AccessTokenClaims, error) {
	// Parse the JWS
	jws, err := jose.ParseSigned(tokenString, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Get JWKS
	keySet, err := v.getJWKS()
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}

	// Find the signing key
	if len(jws.Signatures) == 0 {
		return nil, fmt.Errorf("no signatures in JWT")
	}
	kid := jws.Signatures[0].Header.KeyID

	keys := keySet.Key(kid)
	if len(keys) == 0 {
		// Try refreshing JWKS in case keys were rotated
		v.invalidateJWKS()
		keySet, err = v.getJWKS()
		if err != nil {
			return nil, fmt.Errorf("failed to refresh JWKS: %w", err)
		}
		keys = keySet.Key(kid)
		if len(keys) == 0 {
			return nil, fmt.Errorf("no matching key found for kid %q", kid)
		}
	}

	// Verify signature
	payload, err := jws.Verify(keys[0].Key)
	if err != nil {
		return nil, fmt.Errorf("JWT signature verification failed: %w", err)
	}

	// Parse claims
	var claims AccessTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// Validate expiration
	now := time.Now().Unix()
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt {
		return nil, fmt.Errorf("token expired at %d, current time %d", claims.ExpiresAt, now)
	}

	// Validate issuer
	if v.expectedIssuer != "" && claims.Issuer != v.expectedIssuer {
		return nil, fmt.Errorf("invalid issuer: got %q, expected %q", claims.Issuer, v.expectedIssuer)
	}

	// Validate audience
	if v.expectedAudience != "" {
		found := false
		for _, aud := range claims.Audience {
			if aud == v.expectedAudience {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("token audience %v does not contain expected audience %q",
				[]string(claims.Audience), v.expectedAudience)
		}
	}

	return &claims, nil
}

// getJWKS returns the cached JWKS or fetches it
func (v *JWTValidator) getJWKS() (*jose.JSONWebKeySet, error) {
	v.mu.RLock()
	if v.jwks != nil && time.Since(v.fetched) < 5*time.Minute {
		defer v.mu.RUnlock()
		return v.jwks, nil
	}
	v.mu.RUnlock()

	return v.fetchJWKS()
}

// invalidateJWKS forces the next getJWKS call to fetch fresh keys
func (v *JWTValidator) invalidateJWKS() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.fetched = time.Time{}
}

// fetchJWKS fetches the JWKS from the remote endpoint
func (v *JWTValidator) fetchJWKS() (*jose.JSONWebKeySet, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Double-check after acquiring write lock
	if v.jwks != nil && time.Since(v.fetched) < 5*time.Minute {
		return v.jwks, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", v.jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	v.jwks = &keySet
	v.fetched = time.Now()

	return v.jwks, nil
}
