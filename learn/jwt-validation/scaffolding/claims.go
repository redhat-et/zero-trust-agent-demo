// Package main contains JWT claim structures and delegation detection.
package main

// TODO: Task 3 - Define Claims struct
//
// Create a struct that represents JWT claims from Keycloak.
// Your test token should have claims like:
//
//	{
//	  "iss": "http://localhost:8080/realms/demo",
//	  "sub": "alice",
//	  "aud": "document-service",  // Can also be ["doc-svc", "other-svc"]
//	  "exp": 1738600000,
//	  "iat": 1738596400,
//	  "azp": "spiffe://demo.example.com/agent/gpt4",
//	  "groups": ["engineering", "finance"],
//	  "preferred_username": "alice"
//	}
//
// Hints:
// - Use json struct tags for unmarshaling
// - The "aud" claim can be string OR []string - consider using a custom type
// - Timestamps (exp, iat) are Unix seconds (int64)
// - Groups and some other claims may be absent

// Claims represents the JWT claims we care about.
type Claims struct {
	// TODO: Add fields for standard claims
	// Iss string `json:"iss"`
	// Sub string `json:"sub"`
	// ... etc

	// TODO: Add fields for Keycloak-specific claims
	// Groups []string `json:"groups"`
	// PreferredUsername string `json:"preferred_username"`
}

// Audience is a custom type that handles "aud" being string or []string.
// This is optional but recommended.
//
// Hint: Implement UnmarshalJSON to handle both cases:
//
//	func (a *Audience) UnmarshalJSON(data []byte) error {
//	    // Try to unmarshal as string first
//	    // If that fails, try as []string
//	}
type Audience []string

// TODO: Task 7 - Implement DetectDelegation
//
// DetectDelegation analyzes the token claims to determine if this is
// delegated access (an agent acting on behalf of a user).
//
// Delegation detection logic:
// - If sub == azp: direct access (user or service acting as itself)
// - If sub != azp: delegated access (azp client acting on behalf of sub user)
//
// Returns nil if this is direct access (no delegation).
// Returns DelegationInfo if this is delegated access.

// DelegationInfo contains information about a delegated request.
type DelegationInfo struct {
	UserID  string   // The human user (from sub claim)
	AgentID string   // The agent/client (from azp claim)
	Groups  []string // User's groups (from groups claim)
}

func DetectDelegation(claims *Claims) *DelegationInfo {
	// YOUR CODE HERE
	return nil
}

// ParseClaims extracts claims from a JWT payload.
// You'll use this in Tasks 4 and 7.
//
// Hint: This is similar to DecodePayloadUnsafe from the example,
// but it unmarshals into your Claims struct instead of map[string]any.
func ParseClaims(tokenString string) (*Claims, error) {
	// YOUR CODE HERE
	return nil, nil
}
