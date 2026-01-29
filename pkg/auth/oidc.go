package auth

import (
	"context"
	"fmt"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig holds OIDC configuration
type OIDCConfig struct {
	IssuerURL       string `mapstructure:"issuer_url"`
	ClientID        string `mapstructure:"client_id"`
	RedirectURL     string `mapstructure:"redirect_url"`
	Enabled         bool   `mapstructure:"enabled"`
	SkipExpiryCheck bool   `mapstructure:"skip_expiry_check"` // For development with clock skew
	PostLogoutURL   string `mapstructure:"post_logout_url"`   // Where to redirect after logout
}

// OIDCProvider wraps the OIDC provider and OAuth2 configuration
type OIDCProvider struct {
	provider      *oidc.Provider
	oauth2Config  *oauth2.Config
	verifier      *oidc.IDTokenVerifier
	issuerURL     string
	clientID      string
	postLogoutURL string
}

// NewOIDCProvider creates a new OIDC provider
func NewOIDCProvider(ctx context.Context, cfg OIDCConfig) (*OIDCProvider, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:    cfg.ClientID,
		RedirectURL: cfg.RedirectURL,
		Endpoint:    provider.Endpoint(),
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}

	// Configure verifier - skip expiry check if there's clock skew (dev mode)
	verifierConfig := &oidc.Config{
		ClientID: cfg.ClientID,
	}
	if cfg.SkipExpiryCheck {
		verifierConfig.SkipExpiryCheck = true
	}
	verifier := provider.Verifier(verifierConfig)

	// Determine post-logout URL (default to redirect URL's origin)
	postLogoutURL := cfg.PostLogoutURL
	if postLogoutURL == "" {
		// Parse redirect URL and extract origin (scheme + host)
		if u, err := url.Parse(cfg.RedirectURL); err == nil {
			postLogoutURL = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		} else {
			postLogoutURL = cfg.RedirectURL
		}
	}

	return &OIDCProvider{
		provider:      provider,
		oauth2Config:  oauth2Config,
		verifier:      verifier,
		issuerURL:     cfg.IssuerURL,
		clientID:      cfg.ClientID,
		postLogoutURL: postLogoutURL,
	}, nil
}

// AuthCodeURL returns the URL to redirect the user for authentication
func (p *OIDCProvider) AuthCodeURL(state string) string {
	return p.oauth2Config.AuthCodeURL(state)
}

// Exchange exchanges the authorization code for tokens
func (p *OIDCProvider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.oauth2Config.Exchange(ctx, code)
}

// Verify verifies the ID token and returns the parsed token
func (p *OIDCProvider) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	return p.verifier.Verify(ctx, rawIDToken)
}

// LogoutURL returns the URL to redirect to for logging out of the OIDC provider
func (p *OIDCProvider) LogoutURL() string {
	return fmt.Sprintf("%s/protocol/openid-connect/logout?client_id=%s&post_logout_redirect_uri=%s",
		p.issuerURL, p.clientID, p.postLogoutURL)
}

// Claims represents the claims extracted from the ID token
type Claims struct {
	Subject           string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Email             string   `json:"email"`
	Groups            []string `json:"groups"`
}

// ExtractClaims extracts claims from an ID token
func ExtractClaims(idToken *oidc.IDToken) (*Claims, error) {
	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}
	return &claims, nil
}
