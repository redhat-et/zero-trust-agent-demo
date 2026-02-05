# STS token exchange learning project

Learn how to implement RFC 8693 OAuth 2.0 Token Exchange with Keycloak. This is foundational for understanding how AuthBridge transforms tokens for different target services.

## Learning objectives

By completing this project, you will understand:

1. What RFC 8693 Token Exchange is and why it exists
2. How to configure Keycloak for token exchange
3. How to construct a token exchange request
4. How audience transformation works
5. How delegation claims (sub, azp, act) are preserved
6. Error handling for token exchange failures

## Prerequisites

- Completed: jwt-validation project
- Keycloak running with the demo realm
- Understanding of OAuth 2.0 basics

## Project structure

```text
sts-token-exchange/
├── main.go              # CLI entry point (Task 6) - SOLUTION
├── exchange.go          # Token exchange logic (Tasks 3, 4, 5) - SOLUTION
├── config.go            # Configuration handling (Task 2) - SOLUTION
├── *_test.go            # Unit tests
├── go.mod
├── Makefile
├── README.md
└── scaffolding/         # Original TODO files for starting fresh
    ├── main.go
    ├── exchange.go
    └── config.go
```

### For learners starting fresh

Copy the scaffolding files to start with TODO markers:

```bash
cp scaffolding/*.go .
```

## Getting started

```bash
cd learn/sts-token-exchange
go mod tidy
```

---

## Background: Why token exchange?

In a zero-trust architecture, tokens should be scoped to specific services:

```
Agent Token (audience: "agent-service")
    ↓ exchange
Document Token (audience: "document-service")
    ↓ exchange
Database Token (audience: "database-service")
```

This ensures:

1. **Least privilege**: Each token only works for its intended service
2. **Audit trail**: Token exchanges are logged
3. **Revocation**: Compromised tokens have limited blast radius

### The token exchange flow

```
┌─────────┐      ┌──────────────┐      ┌────────────────┐
│  Agent  │─────▶│   Keycloak   │─────▶│ Target Service │
│         │  1   │              │  3   │                │
│         │◀─────│              │      │                │
│         │  2   │              │      │                │
└─────────┘      └──────────────┘      └────────────────┘

1. Agent sends: subject_token + desired audience
2. Keycloak returns: new token with updated audience
3. Agent calls target with new token
```

---

## Tasks

### Task 1: Configure Keycloak for token exchange

**Objective**: Enable token exchange in your Keycloak realm.

**Steps**:

1. Access Keycloak admin console: `http://localhost:8080/admin`
2. Select the `demo` realm
3. For each client that needs to exchange tokens:
   - Go to Client → Settings
   - Ensure "Service accounts roles" is enabled
   - Go to Client → Service account roles
   - Add `realm-management` → `token-exchange` role

4. Configure the target client (e.g., `document-service`):
   - Go to Client → Permissions
   - Enable permissions
   - Click on "token-exchange" permission
   - Add the source client (e.g., `agent-service`) as permitted

**Verification**:

```bash
# Check that token exchange is enabled (look for grant_types_supported)
curl -s http://localhost:8080/realms/demo/.well-known/openid-configuration | jq '.grant_types_supported'
```

Should include: `urn:ietf:params:oauth:grant-type:token-exchange`

**Success criteria**:

- [ ] Token exchange grant type is supported
- [ ] Source client has token-exchange role
- [ ] Target client permits exchange from source

**Pitfalls**:

- Token exchange is disabled by default in some Keycloak versions
- You may need to enable it via startup flag: `--features=token-exchange`

---

### Task 2: Obtain an initial token

**Objective**: Get a token that you will exchange.

**File**: `config.go`

**Function signature**:

```go
// Config holds the token exchange configuration
type Config struct {
    TokenURL     string // Keycloak token endpoint
    ClientID     string // Client performing the exchange
    ClientSecret string // Client credentials
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (*Config, error)
```

**Steps**:

1. Create a config struct for token exchange parameters
2. Load from environment variables with sensible defaults
3. Obtain an initial token using client_credentials grant

**Hints**:

- Token URL: `http://localhost:8080/realms/demo/protocol/openid-connect/token`
- Use the agent-service client credentials
- This is similar to what you did in jwt-validation Task 1

**Success criteria**:

- [ ] Config loads from environment variables
- [ ] Can obtain an initial access token
- [ ] Token has the agent's client_id as `azp`

---

### Task 3: Build the token exchange request

**Objective**: Construct the RFC 8693 token exchange request body.

**File**: `exchange.go`

**Function signature**:

```go
// ExchangeRequest contains the parameters for token exchange
type ExchangeRequest struct {
    SubjectToken     string // The token to exchange
    TargetAudience   string // The desired audience for the new token
    Scopes           []string // Optional: requested scopes
}

// BuildRequestBody creates the form-encoded body for token exchange
func (r *ExchangeRequest) BuildRequestBody() url.Values
```

**RFC 8693 required parameters**:

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<the JWT to exchange>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
audience=<target service>
```

**Optional parameters**:

```
requested_token_type=urn:ietf:params:oauth:token-type:access_token
scope=openid profile email
```

**Hints**:

- Use `url.Values` from `net/url` package
- The `grant_type` is a URN, not a simple string
- `subject_token_type` tells Keycloak what kind of token you're exchanging

**Success criteria**:

- [ ] Request body includes all required parameters
- [ ] Parameters are properly URL-encoded
- [ ] Scopes are space-separated when provided

---

### Task 4: Execute the token exchange

**Objective**: Call Keycloak's token endpoint to exchange the token.

**File**: `exchange.go`

**Function signature**:

```go
// ExchangeToken performs the RFC 8693 token exchange
// Returns the new access token or an error
func ExchangeToken(cfg *Config, req *ExchangeRequest) (string, error)
```

**Hints**:

- POST to the token endpoint with `application/x-www-form-urlencoded`
- Include client authentication (Basic auth or form parameters)
- Parse the JSON response to extract `access_token`
- Handle error responses (check for `error` field in response)

**Response structure**:

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 300,
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"
}
```

**Error response**:

```json
{
  "error": "access_denied",
  "error_description": "Client not allowed to exchange"
}
```

**Success criteria**:

- [ ] Successfully exchanges a token
- [ ] Returns the new access token string
- [ ] Returns meaningful error for failures

---

### Task 5: Verify the exchanged token

**Objective**: Parse and validate the exchanged token to verify audience changed.

**File**: `exchange.go`

**Function signature**:

```go
// VerifyExchange checks that the exchanged token has the expected properties
func VerifyExchange(originalToken, exchangedToken, expectedAudience string) error
```

**Things to verify**:

1. The `aud` claim matches the requested audience
2. The `sub` claim is preserved (same user)
3. The `azp` claim may change (now the exchanger's client_id)
4. The token is not expired

**Hints**:

- Reuse your `ParseClaims` logic from jwt-validation
- Or use the Claims struct you built there
- You can import from `../jwt-validation` or copy the code

**Success criteria**:

- [ ] Verifies audience matches target
- [ ] Confirms subject is preserved
- [ ] Checks token is not expired
- [ ] Returns clear error if verification fails

---

### Task 6: Build the CLI

**Objective**: Create a CLI that demonstrates token exchange.

**File**: `main.go`

**Usage**:

```bash
# Exchange a token for a new audience
./sts-token-exchange exchange \
  --subject-token "eyJ..." \
  --audience "document-service"

# Or get a fresh token and exchange it
./sts-token-exchange demo \
  --target-audience "document-service"
```

**Output should include**:

- Original token claims (sub, azp, aud)
- Exchange request details
- New token claims (sub, azp, aud)
- Verification result

**Success criteria**:

- [ ] Exchanges tokens successfully
- [ ] Shows before/after comparison
- [ ] Clear error messages on failure
- [ ] Non-zero exit code on error

---

## Stretch goals

1. **Token introspection**: Use Keycloak's introspection endpoint to verify tokens server-side
2. **Actor claims**: Explore the `act` claim for chained delegation
3. **Scope downscoping**: Request fewer scopes in the exchanged token
4. **Caching**: Cache exchanged tokens until near expiry

## Connecting to the main project

After completing this project, you'll understand the core of what AuthBridge's ext-proc does:

1. Extract the subject token from incoming requests
2. Exchange it for a token scoped to the target service
3. Replace the Authorization header with the new token

The next project (envoy-ext-proc) wraps this logic in an Envoy external processor.

## References

- [RFC 8693: OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [Keycloak Token Exchange Documentation](https://www.keycloak.org/docs/latest/securing_apps/#_token-exchange)
- [AuthBridge exchangeToken implementation](https://github.com/kagenti/kagenti-extensions/blob/main/AuthBridge/AuthProxy/go-processor/main.go)
