// Package main contains token exchange logic implementing RFC 8693.
package main

import (
	"fmt"
	"net/url"
	"strings"
)

// Token type URNs from RFC 8693
const (
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken  = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken       = "urn:ietf:params:oauth:token-type:id_token"
)

// TODO: Task 3 - Define ExchangeRequest struct
//
// Create a struct that holds the parameters for token exchange:
//
//	type ExchangeRequest struct {
//	    SubjectToken   string   // The token to exchange
//	    TargetAudience string   // The desired audience
//	    Scopes         []string // Optional: requested scopes
//	}

// ExchangeRequest contains the parameters for RFC 8693 token exchange.
type ExchangeRequest struct {
	// TODO: Add fields
	// SubjectToken   string
	// TargetAudience string
	// Scopes         []string
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
	// TODO: Task 3 - Build the request body
	//
	// Example:
	//   values := url.Values{}
	//   values.Set("grant_type", GrantTypeTokenExchange)
	//   values.Set("subject_token", r.SubjectToken)
	//   ...
	//
	// Hints:
	// - Use the constants defined above for URNs
	// - Scopes should be joined with spaces: strings.Join(r.Scopes, " ")

	_ = strings.Join // Remove when you use strings.Join

	return url.Values{}
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
	// TODO: Task 4 - Implement token exchange
	//
	// HTTP request:
	//   POST {cfg.TokenURL}
	//   Content-Type: application/x-www-form-urlencoded
	//   Body: <form-encoded parameters>
	//
	// Response parsing:
	//   Success: {"access_token": "eyJ...", "token_type": "Bearer", ...}
	//   Error: {"error": "access_denied", "error_description": "..."}
	//
	// Hints:
	// - Use http.PostForm or build the request manually
	// - Check response status code
	// - Parse JSON response into a map or struct
	// - Return error if "error" field is present in response

	_ = cfg // Remove when you use cfg
	_ = req // Remove when you use req

	return "", fmt.Errorf("ExchangeToken not implemented")
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

// TODO: Task 5 - Implement VerifyExchange
//
// VerifyExchange checks that the exchanged token has the expected properties:
// 1. The aud claim matches the requested audience
// 2. The sub claim is preserved (same user)
// 3. The token is not expired
//
// Hints:
// - Parse both tokens to extract claims
// - Compare the sub claims to ensure they match
// - Check that aud contains the expected audience
// - You can reuse code from jwt-validation or copy the Claims parsing

func VerifyExchange(originalToken, exchangedToken, expectedAudience string) error {
	// TODO: Implement verification
	//
	// Steps:
	// 1. Parse original token claims
	// 2. Parse exchanged token claims
	// 3. Verify sub claims match
	// 4. Verify aud contains expectedAudience
	// 5. Verify exchanged token is not expired

	_ = originalToken    // Remove when you use
	_ = exchangedToken   // Remove when you use
	_ = expectedAudience // Remove when you use

	return fmt.Errorf("VerifyExchange not implemented")
}

// PrintTokenComparison displays a before/after comparison of token claims.
// Useful for debugging and understanding what changed during exchange.
func PrintTokenComparison(originalToken, exchangedToken string) {
	// TODO: Implement comparison display
	//
	// Output format:
	//   Original Token:
	//     sub: alice
	//     azp: agent-service
	//     aud: [agent-service]
	//
	//   Exchanged Token:
	//     sub: alice
	//     azp: agent-service
	//     aud: [document-service]
	//
	// Hints:
	// - Parse both tokens
	// - Print key claims side by side

	fmt.Println("PrintTokenComparison not implemented")
}
