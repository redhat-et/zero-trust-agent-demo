# JWT validation learning project

Learn how to validate JWTs using JWKS (JSON Web Key Sets) in Go. This is a foundational skill for integrating AuthBridge with document-service.

## Learning objectives

By completing this project, you will understand:

1. How JWTs are structured (header, payload, signature)
2. How JWKS endpoints work and why they exist
3. How to fetch and cache public keys from JWKS
4. How to validate JWT signatures cryptographically
5. How to extract and interpret claims (sub, azp, aud, groups)
6. How to detect delegation by comparing claims

## Prerequisites

- Go 1.21+
- Keycloak running with the demo realm configured
- A valid JWT from Keycloak (you'll obtain this in Task 1)

## Project structure

```text
jwt-validation/
├── main.go              # CLI entry point (Task 8) - SOLUTION
├── jwt.go               # JWT parsing utilities (Tasks 2, 4, 6) - SOLUTION
├── jwks.go              # JWKS fetching (Task 5) - SOLUTION
├── claims.go            # Claim structures and delegation (Tasks 3, 7) - SOLUTION
├── *_test.go            # Unit and integration tests
├── testhelpers_test.go  # Test helpers for generating tokens
├── go.mod
├── Makefile
├── README.md
└── scaffolding/         # Original TODO files for starting fresh
    ├── main.go
    ├── jwt.go
    ├── jwks.go
    ├── claims.go
    └── README.md
```

### For learners starting fresh

Copy the scaffolding files to start with TODO markers:

```bash
cp scaffolding/*.go .
```

### Test helpers

The `testhelpers_test.go` file provides utilities for generating test tokens:

```go
// Generate a key pair for testing
keyPair := GenerateTestKeyPair(t, "test-kid")

// Build tokens with fluent API
token := NewTokenBuilder(t, keyPair).
    WithSubject("alice").
    WithAzp("agent-gpt4").
    WithGroups("engineering", "finance").
    Expired().  // or .ExpiresIn(time.Hour)
    Build()
```

## Getting started

```bash
cd learn/jwt-validation
go mod tidy
```

---

## Example: Decoding JWT without validation

This example shows how to decode a JWT's payload **without** validating the signature. This is provided as a starting point - you'll add validation in the tasks.

```go
// example_decode.go - PROVIDED FOR REFERENCE
package main

import (
    "encoding/base64"
    "encoding/json"
    "fmt"
    "strings"
)

// DecodePayloadUnsafe decodes the JWT payload WITHOUT validating the signature.
// WARNING: Never use this in production - anyone can forge a JWT payload.
// This is only for learning/debugging purposes.
func DecodePayloadUnsafe(tokenString string) (map[string]any, error) {
    // JWT structure: header.payload.signature
    parts := strings.Split(tokenString, ".")
    if len(parts) != 3 {
        return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
    }

    // The payload is the second part, base64url encoded
    // Note: base64url uses - and _ instead of + and /
    payloadB64 := parts[1]

    // Add padding if needed (base64 requires padding to multiple of 4)
    switch len(payloadB64) % 4 {
    case 2:
        payloadB64 += "=="
    case 3:
        payloadB64 += "="
    }

    // Decode from base64url
    payloadBytes, err := base64.URLEncoding.DecodeString(payloadB64)
    if err != nil {
        return nil, fmt.Errorf("failed to decode payload: %w", err)
    }

    // Parse as JSON
    var claims map[string]any
    if err := json.Unmarshal(payloadBytes, &claims); err != nil {
        return nil, fmt.Errorf("failed to parse claims: %w", err)
    }

    return claims, nil
}
```

**Key patterns to notice:**

1. JWTs have three dot-separated parts
2. Base64url encoding differs from standard base64
3. The payload is JSON containing "claims"
4. This is UNSAFE because we don't verify the signature

---

## Tasks

### Task 1: Obtain a test JWT from Keycloak

**Objective**: Get a real JWT from your Keycloak server to use for testing.

**Steps**:

1. Port-forward Keycloak: `kubectl port-forward service/keycloak-service -n keycloak 8080:8080`
2. Use curl to obtain a token using the client credentials grant
3. Save the token to a file for use in later tasks

**Hints**:

- The token endpoint is: `http://localhost:8080/realms/demo/protocol/openid-connect/token`
- You need `client_id` and `client_secret` from the AuthBridge setup
- The grant type is `client_credentials`
- Use `jq` to extract `.access_token` from the response

**Success criteria**:

- [ ] You have a file `test-token.txt` containing a JWT
- [ ] The JWT has three dot-separated parts
- [ ] You can decode it with: `cat test-token.txt | cut -d. -f2 | base64 -d 2>/dev/null | jq`

**Pitfalls**:

- Base64 padding errors are common - the shell command above handles this loosely
- Make sure you're getting `access_token`, not `id_token` or `refresh_token`

---

### Task 2: Parse the JWT header

**Objective**: Write a function to decode and parse the JWT header (first part).

**File**: `jwt.go`

**Function signature**:

```go
// ParseHeader decodes the JWT header and returns the algorithm and key ID.
// The header contains "alg" (algorithm) and "kid" (key ID) fields.
func ParseHeader(tokenString string) (alg string, kid string, err error)
```

**Hints**:

- The header is the first part (before the first dot)
- It's base64url encoded JSON
- You'll need the `kid` to find the correct key in the JWKS
- Look at the example's base64 decoding pattern

**Success criteria**:

- [ ] Function returns `alg: "RS256"` for your test token
- [ ] Function returns a non-empty `kid` value
- [ ] Function returns an error for malformed input (e.g., "not.a.jwt")

---

### Task 3: Create JWT structure types

**Objective**: Define Go structs that represent JWT claims relevant to our use case.

**File**: `claims.go`

**Hints**:

- Standard claims: `iss`, `sub`, `aud`, `exp`, `iat`, `azp`
- Custom claims from Keycloak: `groups`, `preferred_username`, `email`
- The `aud` claim can be a string OR an array of strings - handle both
- Use `json` struct tags for unmarshaling

**Success criteria**:

- [ ] Struct can represent all claims from your test token
- [ ] Handles `aud` as both string and []string
- [ ] Includes `exp` as a numeric timestamp (not string)

**Pitfalls**:

- JWT timestamps are Unix seconds, not milliseconds
- Some claims are optional - use pointers or omitempty

---

### Task 4: Validate token expiration

**Objective**: Write a function that checks if a token has expired.

**File**: `jwt.go`

**Function signature**:

```go
// IsExpired checks if the token's exp claim is in the past.
// Returns true if expired, false if still valid.
// Also returns an error if the token cannot be parsed.
func IsExpired(tokenString string) (bool, error)
```

**Hints**:

- The `exp` claim is a Unix timestamp (seconds since epoch)
- Use `time.Now().Unix()` for comparison
- Consider adding a small clock skew tolerance (e.g., 30 seconds)

**Success criteria**:

- [ ] Returns `false` for a fresh token
- [ ] Returns `true` for an expired token (wait for expiration or use an old token)
- [ ] Handles missing `exp` claim gracefully

---

### Task 5: Fetch JWKS from Keycloak

**Objective**: Write a function that fetches the JWKS from Keycloak's well-known endpoint.

**File**: `jwks.go`

**Function signature**:

```go
// FetchJWKS retrieves the JSON Web Key Set from the given URL.
// Returns a map of kid -> public key.
func FetchJWKS(jwksURL string) (map[string]*rsa.PublicKey, error)
```

**Hints**:

- Keycloak's JWKS URL: `http://localhost:8080/realms/demo/protocol/openid-connect/certs`
- The response contains a `keys` array
- Each key has `kid`, `kty`, `alg`, `n` (modulus), and `e` (exponent)
- `n` and `e` are base64url encoded big integers
- Use `crypto/rsa` and `math/big` for key construction

**Success criteria**:

- [ ] Successfully fetches keys from Keycloak
- [ ] Returns at least one RSA public key
- [ ] Keys are indexed by `kid` for quick lookup

**Pitfalls**:

- The `e` exponent is usually "AQAB" which decodes to 65537
- Make sure to filter for `kty: "RSA"` and `use: "sig"` (signing keys only)

---

### Task 6: Verify JWT signature

**Objective**: Verify the JWT signature using the fetched public key.

**File**: `jwt.go`

**Function signature**:

```go
// VerifySignature validates the JWT signature using RSA-SHA256.
// Returns nil if valid, error if invalid or verification fails.
func VerifySignature(tokenString string, publicKey *rsa.PublicKey) error
```

**Hints**:

- RS256 = RSA with SHA-256
- The signature is over: `base64url(header) + "." + base64url(payload)`
- The signature itself is the third part, base64url decoded
- Use `crypto/rsa.VerifyPKCS1v15` with `crypto.SHA256`

**Success criteria**:

- [ ] Returns `nil` for your valid test token
- [ ] Returns an error if you modify any character in the token
- [ ] Returns an error if you use the wrong public key

**Pitfalls**:

- Don't forget to hash the signed content before verification
- The signature must be decoded from base64url first

---

### Task 7: Detect delegation

**Objective**: Determine if a token represents delegated access (agent acting on behalf of user).

**File**: `claims.go`

**Function signature**:

```go
// DetectDelegation analyzes the token claims to determine if this is
// delegated access. Returns delegation info or nil if direct access.
type DelegationInfo struct {
    UserID    string   // The human user (from sub)
    AgentID   string   // The agent/client (from azp)
    Groups    []string // User's groups
}

func DetectDelegation(claims *Claims) *DelegationInfo
```

**Hints**:

- If `sub` equals `azp`, it's direct access (no delegation)
- If `sub` differs from `azp`, the `azp` client is acting on behalf of `sub` user
- The `groups` claim contains the user's group memberships

**Success criteria**:

- [ ] Returns `nil` for a service account token (sub == azp)
- [ ] Returns delegation info when sub != azp
- [ ] Correctly extracts groups from the token

---

### Task 8: Build the CLI

**Objective**: Create a CLI that ties everything together.

**File**: `main.go`

**Usage**:

```bash
# Validate a token from file
./jwt-validation validate --token-file test-token.txt --jwks-url http://localhost:8080/realms/demo/protocol/openid-connect/certs

# Validate a token from environment
JWT_TOKEN="eyJ..." ./jwt-validation validate --jwks-url http://localhost:8080/realms/demo/protocol/openid-connect/certs
```

**Output should include**:

- Header info (alg, kid)
- Signature validation result
- Expiration status
- Key claims (sub, azp, aud, groups)
- Delegation detection result

**Hints**:

- Use the `flag` package for argument parsing
- Consider using colors for valid/invalid status (optional)
- Print claims in a readable format

**Success criteria**:

- [ ] Can validate your test token successfully
- [ ] Shows clear error messages for invalid tokens
- [ ] Detects delegation correctly
- [ ] Exits with non-zero code on validation failure

---

## Stretch goals

Once you complete all tasks, consider these extensions:

1. **Add JWKS caching**: Don't fetch on every validation
2. **Support multiple algorithms**: Handle RS384, RS512, ES256
3. **Add audience validation**: Verify the token was meant for your service
4. **Create a validation middleware**: HTTP middleware for use in services

## Connecting to the main project

After completing this project, you'll integrate these concepts into `document-service`:

1. The JWKS fetching logic goes into a new `pkg/jwt/` package
2. The claim extraction feeds into OPA input construction
3. The delegation detection determines how to build the OPA request

See [AuthBridge Integration Learning Guide](../../docs/AUTHBRIDGE_INTEGRATION_LEARNING.md) for the full context.
