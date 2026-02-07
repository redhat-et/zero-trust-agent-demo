// Package main contains token exchange logic implementing RFC 8693.
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Token type URNs from RFC 8693
const (
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken  = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken       = "urn:ietf:params:oauth:token-type:id_token"
)

// Claims represents the JWT claims we care about.
type Claims struct {
	Iss               string   `json:"iss"`
	Sub               string   `json:"sub"`
	Aud               Audience `json:"aud"`
	Exp               int64    `json:"exp"`
	Iat               int64    `json:"iat"`
	Azp               string   `json:"azp"`
	Groups            []string `json:"groups"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
}

type Audience []string

// ExchangeRequest contains the parameters for RFC 8693 token exchange.
type ExchangeRequest struct {
	SubjectToken   string
	TargetAudience string
	Scopes         []string
}

// BuildRequestBody creates the form-encoded body for token exchange.
//
// RFC 8693 required parameters:
//   - grant_type: urn:ietf:params:oauth:grant-type:token-exchange
//   - subject_token: the JWT to exchange
//   - subject_token_type: urn:ietf:params:oauth:token-type:access_token
//   - audience: target service
//
// Optional parameters:
//   - requested_token_type: what kind of token you want back
//   - scope: space-separated list of scopes
func (r *ExchangeRequest) BuildRequestBody() url.Values {
	values := url.Values{}
	values.Set("grant_type", GrantTypeTokenExchange)
	values.Set("subject_token", r.SubjectToken)
	values.Set("subject_token_type", TokenTypeAccessToken)
	values.Set("audience", r.TargetAudience)
	values.Set("requested_token_type", TokenTypeAccessToken)
	if len(r.Scopes) > 0 {
		values.Set("scope", strings.Join(r.Scopes, " "))
	}
	return values
}

// ExchangeToken performs the RFC 8693 token exchange.
// Returns the new access token or an error.
//
// Steps:
// 1. Build the request body using BuildRequestBody
// 2. Add client authentication (client_id, client_secret)
// 3. POST to the token endpoint
// 4. Parse the response
// 5. Return the new access_token or error
func ExchangeToken(cfg *Config, req *ExchangeRequest) (string, error) {
	reqBody := req.BuildRequestBody()
	reqBody.Set("client_id", cfg.ClientID)
	reqBody.Set("client_secret", cfg.ClientSecret)
	resp, err := http.PostForm(cfg.TokenURL, reqBody)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	response := make(map[string]any)
	err = json.Unmarshal(body, &response)
	if err != nil {
		return "", err
	}
	if errMsg, ok := response["error"].(string); ok {
		desc, _ := response["error_description"].(string)
		return "", fmt.Errorf("%s: %s", errMsg, desc)
	}
	accessToken, ok := response["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("access_token not found in response")
	}
	return accessToken, nil
}

// ExchangeResponse represents the token endpoint response.
type ExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	IssuedTokenType string `json:"issued_token_type"`

	// Error fields (present on failure)
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func VerifyExchange(originalToken, exchangedToken, expectedAudience string) error {
	originalClaims, err := ParseClaims(originalToken)
	if err != nil {
		return err
	}
	exchangedClaims, err := ParseClaims(exchangedToken)
	if err != nil {
		return err
	}
	if originalClaims.Sub != exchangedClaims.Sub {
		return fmt.Errorf("sub claims do not match: %s != %s", originalClaims.Sub, exchangedClaims.Sub)
	}
	if !slices.Contains(exchangedClaims.Aud, expectedAudience) {
		return fmt.Errorf("exchanged token aud %v does not contain expected audience: %s", exchangedClaims.Aud, expectedAudience)
	}
	if exchangedClaims.Exp < time.Now().Unix() {
		return fmt.Errorf("exchanged token is expired: %d", exchangedClaims.Exp)
	}
	return nil
}

func IntrospectToken(cfg *Config, token string) (bool, error) {
	resp, err := http.PostForm(cfg.TokenURL+"/introspect", url.Values{
		"token":         {token},
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
	})
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	response := make(map[string]any)
	err = json.Unmarshal(body, &response)
	if err != nil {
		return false, err
	}
	if errMsg, ok := response["error"].(string); ok {
		desc, _ := response["error_description"].(string)
		return false, fmt.Errorf("%s: %s", errMsg, desc)
	}
	active, ok := response["active"].(bool)
	if !ok {
		return false, fmt.Errorf("unexpected introspection response: missing 'active' field")
	}
	return active, nil
}

// PrintTokenComparison displays a before/after comparison of token claims.
// Useful for debugging and understanding what changed during exchange.
func PrintTokenComparison(originalToken, exchangedToken string) {
	originalClaims, err := ParseClaims(originalToken)
	if err != nil {
		fmt.Println("Error parsing original token:", err)
		return
	}
	exchangedClaims, err := ParseClaims(exchangedToken)
	if err != nil {
		fmt.Println("Error parsing exchanged token:", err)
		return
	}
	fmt.Println("Original Token:")
	fmt.Printf("  sub: %s\n", originalClaims.Sub)
	fmt.Printf("  azp: %s\n", originalClaims.Azp)
	fmt.Printf("  aud: %v\n", originalClaims.Aud)
	fmt.Println("Exchanged Token:")
	fmt.Printf("  sub: %s\n", exchangedClaims.Sub)
	fmt.Printf("  azp: %s\n", exchangedClaims.Azp)
	fmt.Printf("  aud: %v\n", exchangedClaims.Aud)
}

func ParseClaims(tokenString string) (*Claims, error) {
	var claims Claims
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

func (a *Audience) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*a = []string{s}
		return nil
	}
	var ss []string
	if err := json.Unmarshal(data, &ss); err == nil {
		*a = ss
		return nil
	}
	return errors.New("invalid audience")
}
