// Package main contains JWT claim structures and delegation detection.
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

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
	if claims.Sub == claims.Azp {
		return nil
	}
	return &DelegationInfo{
		UserID:  claims.Sub,
		AgentID: claims.Azp,
		Groups:  claims.Groups,
	}
}

// ParseClaims extracts claims from a JWT payload.
// You'll use this in Tasks 4 and 7.
//
// Hint: This is similar to DecodePayloadUnsafe from the example,
// but it unmarshals into your Claims struct instead of map[string]any.
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

func (d *DelegationInfo) String() string {
	groups := strings.Join(d.Groups, ", ")
	return fmt.Sprintf("UserID: %s\nAgentID: %s\nGroups: %v", d.UserID, d.AgentID, groups)
}

func (c *Claims) String() string {
	issuedTime := time.Unix(c.Iat, 0).Format(time.RFC3339)
	expirationTime := time.Unix(c.Exp, 0).Format(time.RFC3339)
	audience := strings.Join(c.Aud, ", ")
	groups := strings.Join(c.Groups, ", ")
	return fmt.Sprintf("Iss: %s\nSub: %s\nAud: %v\nExp: %s\nIat: %s\nAzp: %s\nGroups: %v\nPreferredUsername: %s\nEmail: %s", c.Iss, c.Sub, audience, expirationTime, issuedTime, c.Azp, groups, c.PreferredUsername, c.Email)
}
