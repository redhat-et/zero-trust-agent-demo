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

```text
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

```text
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

- Token exchange was disabled by default in older Keycloak versions and
  required the startup flag `--features=token-exchange`. Since Keycloak
  26.2, token exchange is enabled by default (no flag needed).

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

```text
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<the JWT to exchange>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
audience=<target service>
```

**Optional parameters**:

```text
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

### Token introspection vs local JWKS validation

There are two ways to verify a token, and choosing between them matters in production.

**Local JWKS validation** verifies the cryptographic signature offline.
You fetch the public keys once (and cache them), then validate any token
without contacting Keycloak again.
It answers: "Was this token signed by a key I trust, and is it not expired?"

**Introspection** ([RFC 7662][rfc7662]) asks the authorization server directly.
It answers a broader question: "Is this token *currently* valid?" -- which
includes things that local validation cannot check:

- **Token revocation**: If a user logs out or an admin revokes a token,
  the JWT signature is still valid (it's a self-contained signed blob),
  but introspection will return `active: false`.
- **Session termination**: If the Keycloak session is killed, local
  validation won't know.
- **Real-time policy changes**: If a user's roles or groups change after
  the token was issued, introspection can reflect that.

**Tradeoff summary:**

| | Local JWKS | Introspection |
| --- | --- | --- |
| Latency | None after key fetch | Network call per validation |
| Revocation-aware | No | Yes |
| Availability | Works if Keycloak is down | Depends on Keycloak |
| Load on Keycloak | Minimal | One request per validation |

**When to use which:**

- **Local JWKS** is the common choice for service-to-service calls where
  tokens are short-lived (5-15 minutes). If a token lives for only 5 minutes,
  the revocation gap is acceptable, and you avoid extra load on Keycloak.
- **Introspection** makes sense when you need immediate revocation awareness
  (e.g., financial transactions, sensitive operations), or when tokens are
  longer-lived and you can't tolerate the gap.

In practice, many systems use local validation for the hot path and reserve
introspection for specific high-sensitivity operations. The main demo project
uses the first approach -- the OPA service validates tokens using JWKS without
calling back to Keycloak.

[rfc7662]: https://datatracker.ietf.org/doc/html/rfc7662

### Actor claims and delegation chains

In agentic workflows a request often passes through multiple agents before
reaching the target service. The `act` (actor) claim from
[RFC 8693 Section 4.1][rfc8693-act] records who is acting on behalf of the
subject, preserving the full chain of custody.

In a delegation chain like `Alice → Agent-A → Agent-B → Document-Service`,
the token arriving at Document-Service would ideally contain:

```json
{
  "sub": "alice",
  "aud": "document-service",
  "act": {
    "sub": "agent-b",
    "act": {
      "sub": "agent-a"
    }
  }
}
```

This tells Document-Service: "This request is for Alice, performed by
Agent-B, which was called by Agent-A."

**Who sets it?** The authorization server (Keycloak) does, not the agents.
Each agent performs a standard token exchange -- it sends its subject token
and requests a new one for the next hop. The STS is responsible for adding
or nesting the `act` claim based on who is performing the exchange. An agent
should never modify JWT claims directly; that would break the signature.

**The exchange flow:**

1. Alice authenticates, gets a token with `sub: alice`
1. Agent-A exchanges Alice's token for one targeting Agent-B. Keycloak
   returns a token with `sub: alice, act: {sub: agent-a}`
1. Agent-B exchanges that token for one targeting Document-Service. Keycloak
   returns a token with `sub: alice, act: {sub: agent-b, act: {sub: agent-a}}`

Each agent does the same simple operation (token exchange), and the STS
builds up the nesting automatically.

**Setting up `act` claims in Keycloak (single-hop):**

Keycloak does not add `act` claims automatically during token exchange.
For single-hop delegation (user → agent → service), you can use a
Hardcoded claim mapper:

1. Go to Clients → `agent-service`
1. Open the **Client scopes** tab
1. Open the `agent-service-dedicated` scope
1. Click **Add mapper** → **By mapper type** → **Hardcoded claim**
1. Configure the mapper:
   - Name: `Actor Claim Mapper` (or any descriptive name)
   - Token Claim Name: `act`
   - Claim value: `{"sub": "agent-service"}`
   - Claim JSON Type: **JSON** (critical -- without this, Keycloak
     embeds the value as a literal string, not a JSON object)
   - Add to access token: **On**
   - Add to ID token: **Off** (only needed for service-to-service)

After this, tokens issued for `agent-service` will include:

```json
{
  "sub": "alice",
  "act": { "sub": "agent-service" }
}
```

**Limitation -- multi-hop nesting:**

This hardcoded approach works for a single hop, but it does not support
nested `act` claims for multi-hop chains. If Agent-B exchanges a token
that already has `act: {"sub": "agent-a"}`, the hardcoded mapper
overwrites it rather than nesting. The result is always
`act: {"sub": "agent-b"}`, losing the information that Agent-A was in
the chain.

For proper nesting, possible approaches include:

- **Script mapper** in Keycloak that reads the incoming token's existing
  `act` claim and wraps it: `{"sub": "agent-b", "act": <previous act>}`
- **Custom SPI** for more complex logic and better performance than
  script mappers
- **Alternative STS** that supports `act` nesting natively

This is one of the harder parts of building a production agentic
delegation chain. The token exchange itself (RFC 8693) is well-supported,
but `act` claim nesting is not universally implemented. This is an open
problem for the project -- see discussion with the team on which path
to take.

[rfc8693-act]: https://datatracker.ietf.org/doc/html/rfc8693#section-4.1

### Scope downscoping vs policy intersection

The demo's permission intersection (Alice's departments ∩ Summarizer's
capabilities) happens at the policy layer -- OPA computes the overlap at
decision time. The token itself still carries Alice's full claims.

Scope downscoping is different -- it operates at the token level during
exchange. When you exchange a token, you can request fewer OAuth scopes
than the original:

```text
Original token scopes:  openid profile documents:read documents:write
Exchange request:       scope=openid documents:read
Resulting token scopes: openid documents:read
```

The new token is cryptographically incapable of being used for
`documents:write`. It's not a policy decision -- it's baked into the token.

**How it works in practice:**

1. **Keycloak**: Define client scopes like `documents:read`,
   `documents:write` (these are just labels -- Keycloak has no idea what
   "read" or "write" means in your application)
1. **Keycloak**: Assign them as optional scopes to the relevant clients
1. **Token exchange**: The agent requests only the scopes it needs
   (e.g., `documents:read`)
1. **Resource server**: The document-service checks the token's `scope`
   claim and refuses operations that aren't covered

**Where are scope semantics defined?** Not in Keycloak. OAuth scopes are
just strings. The resource server (document-service) defines what each
scope means in its own code:

```go
func handleDocumentUpdate(w http.ResponseWriter, r *http.Request) {
    scopes := extractScopes(r) // from the token's "scope" claim
    if !slices.Contains(scopes, "documents:write") {
        http.Error(w, "insufficient scope", http.StatusForbidden)
        return
    }
    // proceed with update
}
```

There is no protocol-level way for a service to ask Keycloak "what does
`documents:read` mean?" The contract is a convention: Keycloak manages
which clients can request which scope strings, and the resource server
checks for the strings it cares about.

**Scopes vs OPA policies -- when to use which:**

Scopes work well for coarse-grained operation-level gating (read vs write,
admin vs user). They become unwieldy for fine-grained domain-specific
authorization like "user is in finance AND agent has finance capability
AND document requires finance."

The OPA-based approach in the main demo is more powerful for that use case
because it encodes domain semantics (departments, capabilities,
intersections) in policy, not in token claims.

In practice, many production systems use both: scopes for broad
operation-level gating at the gateway, and a policy engine like OPA for
fine-grained business logic behind it.

**Open question: How do services advertise their scopes?**

Ideally, document-service would announce which scopes it supports and
what they mean, so you know what to configure in Keycloak and request
during token exchange. This is a real gap in the standard OAuth ecosystem.
In most setups, the answer is documentation -- someone writes down that
`documents:read` means read-only access and everyone agrees to use it.

Approaches that exist to formalize this:

- **[UMA 2.0][uma2]** (User-Managed Access) lets resource servers register
  their resources and scopes with the authorization server programmatically.
  Keycloak supports UMA via the Authorization tab of a client. However, UMA
  adds significant complexity and is designed more for user-to-user sharing
  scenarios than service-to-service.
- **OpenAPI security schemes** can declare required scopes per endpoint,
  serving as both documentation and a machine-readable contract:

  ```yaml
  paths:
    /documents/{id}:
      get:
        security:
          - oauth2: [documents:read]
      put:
        security:
          - oauth2: [documents:write]
  components:
    securitySchemes:
      oauth2:
        type: oauth2
        flows:
          clientCredentials:
            scopes:
              documents:read: Read-only access to documents
              documents:write: Create and update documents
  ```

  An API gateway (like Envoy) could potentially enforce these
  automatically, and a setup script could provision the corresponding
  client scopes in Keycloak from the same spec.

None of these approaches provide fully automated end-to-end scope
discovery and provisioning. This is an area where the specs provide
building blocks but the integration is left to each organization.

For the current prototype, the OPA-based approach sidesteps this
entirely -- the policy files are the authoritative definition of what
permissions exist and what they mean, all in one place. Scope
advertisement and registration is a gap to address in a future iteration.

[uma2]: https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html

### Caching exchanged tokens

In the current demo, every agent operation triggers a token exchange with
Keycloak. If Alice summarizes five documents in a row, that's five
round-trips -- even though the exchanged token from the first request is
still valid. Token caching means keeping the exchanged token in memory
and reusing it until it's close to expiring.

**Cache key design:**

The key must capture what makes each exchanged token unique. You can't
cache by target audience alone because Alice's token and Bob's token for
the same audience are different. A good cache key is:

```text
key = hash(subject_sub + target_audience + sorted_scopes)
```

Use the subject's `sub` claim rather than the full token string -- the
subject token changes on refresh, but `sub` stays the same for the same
user.

**Expiry strategy:**

Tokens have an `exp` claim, but you don't want to serve a token that's
about to expire -- the target service might reject it mid-flight. A
common pattern is to consider a token "stale" at 75-80% of its lifetime:

```go
func isStale(token *CachedToken) bool {
    lifetime := token.ExpiresAt.Sub(token.IssuedAt)
    threshold := token.IssuedAt.Add(
        time.Duration(float64(lifetime) * 0.8),
    )
    return time.Now().After(threshold)
}
```

For a 5-minute token, this triggers a refresh after ~4 minutes.

**Tradeoffs:**

The same tension from the introspection discussion applies here. Cached
tokens won't reflect revocations or permission changes that happen after
the exchange. This is acceptable when tokens are short-lived (5-15
minutes), but becomes a problem with longer-lived tokens.

**Implementation complexity levels:**

| Approach | Pros | Cons |
| --- | --- | --- |
| `sync.Map` or mutex-guarded map | Simple, no dependencies | Per-instance, lost on restart |
| LRU cache with size limit | Bounded memory | Need to choose eviction policy |
| Shared cache (Redis) | Works across replicas | Operational overhead, new dependency |

For a single-replica agent service, an in-memory map with TTL-based
eviction is sufficient. Multi-replica deployments can either accept
per-instance cache duplication (each replica exchanges independently)
or introduce a shared cache.

**Where caching fits in the architecture:**

In the main demo project, caching would live in the agent services
(summarizer-service, reviewer-service) -- they are the ones performing
token exchanges before calling document-service. If AuthBridge's
ext-proc handles token exchange at the Envoy sidecar level, the cache
would live there instead, shared across all requests for a given pod.

This is a nice-to-have optimization for the prototype. The current
per-request exchange is correct and simpler to debug. Caching should
be added when Keycloak round-trip latency becomes a measurable
bottleneck.

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
