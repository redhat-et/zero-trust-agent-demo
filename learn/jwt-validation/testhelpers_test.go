package main

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestKeyPair holds an RSA key pair for testing.
// The private key signs tokens, the public key verifies them.
type TestKeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string
}

// GenerateTestKeyPair creates a new RSA key pair for testing.
func GenerateTestKeyPair(t *testing.T, kid string) *TestKeyPair {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	return &TestKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Kid:        kid,
	}
}

// TokenBuilder provides a fluent API for building test JWTs.
type TokenBuilder struct {
	t          *testing.T
	keyPair    *TestKeyPair
	subject    string
	azp        string
	audience   []string
	groups     []string
	expiration time.Time
	issuedAt   time.Time
	issuer     string
}

// NewTokenBuilder creates a new token builder with sensible defaults.
func NewTokenBuilder(t *testing.T, keyPair *TestKeyPair) *TokenBuilder {
	t.Helper()
	return &TokenBuilder{
		t:          t,
		keyPair:    keyPair,
		subject:    "test-user",
		azp:        "test-client",
		audience:   []string{"test-audience"},
		groups:     []string{},
		expiration: time.Now().Add(time.Hour),
		issuedAt:   time.Now(),
		issuer:     "http://test-issuer",
	}
}

// WithSubject sets the subject claim.
func (b *TokenBuilder) WithSubject(sub string) *TokenBuilder {
	b.subject = sub
	return b
}

// WithAzp sets the authorized party claim.
func (b *TokenBuilder) WithAzp(azp string) *TokenBuilder {
	b.azp = azp
	return b
}

// WithAudience sets the audience claim.
func (b *TokenBuilder) WithAudience(aud ...string) *TokenBuilder {
	b.audience = aud
	return b
}

// WithGroups sets the groups claim.
func (b *TokenBuilder) WithGroups(groups ...string) *TokenBuilder {
	b.groups = groups
	return b
}

// WithExpiration sets when the token expires.
func (b *TokenBuilder) WithExpiration(exp time.Time) *TokenBuilder {
	b.expiration = exp
	return b
}

// Expired sets the token to have expired 1 hour ago.
func (b *TokenBuilder) Expired() *TokenBuilder {
	b.expiration = time.Now().Add(-time.Hour)
	return b
}

// ExpiresIn sets the token to expire in the given duration.
func (b *TokenBuilder) ExpiresIn(d time.Duration) *TokenBuilder {
	b.expiration = time.Now().Add(d)
	return b
}

// WithIssuer sets the issuer claim.
func (b *TokenBuilder) WithIssuer(iss string) *TokenBuilder {
	b.issuer = iss
	return b
}

// Delegated sets up the token to represent delegated access.
// sub will be the user, azp will be the agent.
func (b *TokenBuilder) Delegated(user, agent string) *TokenBuilder {
	b.subject = user
	b.azp = agent
	return b
}

// Direct sets up the token to represent direct access (sub == azp).
func (b *TokenBuilder) Direct(identity string) *TokenBuilder {
	b.subject = identity
	b.azp = identity
	return b
}

// customClaims extends RegisteredClaims with our custom fields.
type customClaims struct {
	jwt.RegisteredClaims
	Azp    string   `json:"azp,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

// Build creates and signs the JWT, returning the token string.
func (b *TokenBuilder) Build() string {
	b.t.Helper()

	claims := customClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   b.subject,
			Issuer:    b.issuer,
			Audience:  b.audience,
			ExpiresAt: jwt.NewNumericDate(b.expiration),
			IssuedAt:  jwt.NewNumericDate(b.issuedAt),
		},
		Azp:    b.azp,
		Groups: b.groups,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = b.keyPair.Kid

	tokenString, err := token.SignedString(b.keyPair.PrivateKey)
	if err != nil {
		b.t.Fatalf("Failed to sign token: %v", err)
	}

	return tokenString
}
