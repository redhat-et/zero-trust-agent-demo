# Plan: RFC 8693 act claim chaining for delegation tracking

## Context

Multi-hop delegation (user -> agent-service -> summarizer -> document-service)
currently lacks cryptographic proof of the delegation chain in JWTs. The
`X-Delegation-*` headers carry context but are unsigned and could be forged.

The Keycloak SPI (`keycloak-act-claim-spi`) is already built and deployed --
it injects nested `act` claims during token exchange when `actor_token` is
provided. But AuthProxy never sends `actor_token`, so no `act` claims appear.

**Goal**: Modify AuthProxy to send its own identity as `actor_token` during
token exchange, producing JWTs like:

```json
{"sub": "alice", "act": {"sub": "summarizer-sa", "act": {"sub": "agent-sa"}}}
```

## Key decisions

- **SPIFFE IDs only**: No static clients for summarizer/reviewer in realm JSON.
  Auto-registration creates them with SPIFFE ID as client_id. Audience scopes
  use `included.custom.audience` with SPIFFE ID strings.
- **Per-target routing**: Include routes.yaml for agent-service now (not deferred).
- **Implementation order**: Realm + docs first (this repo), then AuthProxy (kagenti).

## Repositories involved

| Repo | Role | Branch |
|------|------|--------|
| `zero-trust-agent-demo` | Docs, realm JSON, test scripts, deployment | `feature/act-claim-chaining` |
| `kagenti-extensions` (fork) | AuthProxy ext-proc code changes | TBD |
| `keycloak-act-claim-spi` | Keycloak SPI (already done, read-only) | N/A |

## Phase 1: AuthProxy code changes (kagenti-extensions, LATER)

**File**: `AuthBridge/AuthProxy/go-processor/main.go`

### 1a. Add actor token cache

After the `Config` struct (~line 38), add:

```go
type actorTokenCache struct {
    mu        sync.RWMutex
    token     string
    expiresAt time.Time
}

var globalActorCache = &actorTokenCache{}
var actorTokenEnabled = true
```

Add a `getActorToken(clientID, clientSecret, tokenURL string) (string, error)`
method that:

- Returns cached token if still valid (with 30s safety margin)
- Otherwise calls `clientCredentialsGrant()` to get a fresh one
- Caches the result with TTL from `expires_in`

Both the actor token and the client-credentials fallback (no auth header on
outbound) use the same `clientCredentialsGrant()`. They should share the
cached token since same client_id/secret/tokenURL.

### 1b. Refactor clientCredentialsGrant to return expiry

Current signature: `(string, error)`. Change to `(string, int, error)` where
second return is `ExpiresIn`. Update call site in `handleOutbound()` (~line
573) to ignore the new value.

### 1c. Modify exchangeToken to accept actor token

Add `actorToken string` parameter. Inside, after existing `data.Set()` calls
(~line 315):

```go
if actorToken != "" {
    data.Set("actor_token", actorToken)
    data.Set("actor_token_type", "urn:ietf:params:oauth:token-type:access_token")
}
```

### 1d. Modify handleOutbound to obtain and pass actor token

Before calling `exchangeToken()` (~line 540):

```go
var actorToken string
if actorTokenEnabled {
    actorToken, _ = globalActorCache.getActorToken(clientID, clientSecret, tokenURL)
}
```

Pass `actorToken` to `exchangeToken()`.

### 1e. Initialize feature flag in main()

```go
if v := os.Getenv("ACTOR_TOKEN_ENABLED"); v == "false" {
    actorTokenEnabled = false
}
```

### 1f. Tests

**File**: `AuthBridge/AuthProxy/go-processor/main_test.go`

- Test actor token cache: returns cached value, refreshes on expiry
- Test `exchangeToken` sends `actor_token` params when non-empty
- Test `exchangeToken` omits `actor_token` params when empty

Use `httptest.NewServer` as mock token endpoint.

## Phase 2: Keycloak realm updates (zero-trust-agent-demo, DO FIRST)

**File**: `deploy/k8s/base/realm-spiffe-demo.json`

### 2a. Users already exist in Keycloak

Alice, bob, carol are already configured in Keycloak with passwords and group
memberships. No changes needed.

### 2b. NO static clients for summarizer/reviewer

Auto-registration creates clients with SPIFFE IDs as client_id. We do NOT
add static `summarizer-service` or `reviewer-service` clients to realm JSON.
The auto-registered clients will get scopes via `defaultOptionalClientScopes`.

### 2c. Add audience scopes for summarizer and reviewer

Follow the `agent-service-spiffe-aud` pattern (line 1461) using
`included.custom.audience` with SPIFFE ID strings:

- `summarizer-service-aud` with
  `included.custom.audience: "spiffe://demo.example.com/service/summarizer-service"`
- `reviewer-service-aud` with
  `included.custom.audience: "spiffe://demo.example.com/service/reviewer-service"`

### 2d. Add new audience scopes to agent-service optional scopes

At line 1060, add `"summarizer-service-aud"` and `"reviewer-service-aud"` to
agent-service's `optionalClientScopes`.

### 2e. Add scopes to defaultOptionalClientScopes

So auto-registered SPIFFE-ID clients can also request these audiences.

## Phase 3: Per-service routing for agent-service

**Problem**: All services share `TARGET_AUDIENCE: "document-service"`. When
agent-service calls summarizer, it exchanges for `aud=document-service`
instead of `aud=summarizer-service`.

**Solution**: Add a `routes.yaml` ConfigMap for agent-service.

### 3a. Create routes ConfigMap

**File**: New ConfigMap in the authbridge overlays (both Kind and OpenShift)

```yaml
- host: "summarizer-service**"
  target_audience: "spiffe://demo.example.com/service/summarizer-service"
  token_scopes: "openid summarizer-service-aud"
- host: "reviewer-service**"
  target_audience: "spiffe://demo.example.com/service/reviewer-service"
  token_scopes: "openid reviewer-service-aud"
# Default (document-service) falls through to global TARGET_AUDIENCE
```

Note: audiences use SPIFFE IDs to match the auto-registered client_ids.

### 3b. Mount routes.yaml in agent-service envoy-proxy

Update agent-service authbridge patch to:
- Mount the routes ConfigMap at `/etc/authproxy/routes.yaml`
- Add `ROUTES_CONFIG_PATH` env var (or rely on default path)

### 3c. Decide: per-service or shared routes

Summarizer and reviewer only call document-service, so they can keep the
global `TARGET_AUDIENCE=document-service`. Only agent-service needs routes.

## Phase 4: Test script updates (zero-trust-agent-demo)

**File**: `scripts/test-authbridge.sh`

### 4a. Prerequisite: obtain alice's user token

Use password grant via `spiffe-demo-dashboard` client (public client with
`directAccessGrantsEnabled`) or agent-service client. Depends on Phase 2a
(alice user exists in realm).

### 4b. Test: single-hop act claim

Exchange alice's token with agent-service as actor. Verify `act.sub` matches
agent-service service account.

### 4c. Test: multi-hop act chain

1. Exchange alice's token at agent-service (actor=agent) -> token with `act: {sub: agent-sa}`
2. Exchange that token at summarizer (actor=summarizer) -> token with `act: {sub: summarizer-sa, act: {sub: agent-sa}}`
3. Verify nested structure

### 4d. Test: live E2E via A2A invoke

Trigger an A2A invoke, then inspect document-service's received token from
envoy-proxy logs for the `act` claim.

## Phase 5: Documentation (zero-trust-agent-demo)

### 5a. ADR-0010: act claim chaining

**File**: `docs/adr/0010-act-claim-chaining.md`

- Context: unsigned delegation headers
- Decision: RFC 8693 actor_token + Keycloak SPI
- Alternatives: SPI-only (Option 1) vs AuthProxy+SPI (Option 2, chosen)

### 5b. Update AUTHBRIDGE.md

Add section on act claim chaining with example JWT and flow diagram.

## Implementation order (this session)

1. **Phase 5a** -- ADR-0010 (captures the decision before code changes)
2. **Phase 2** -- Realm JSON (audience scopes, defaultOptionalScopes)
3. **Phase 3** -- Routes ConfigMap + agent-service patch
4. **Phase 4** -- Test script updates (act claim verification tests)
5. **Phase 5b** -- Update AUTHBRIDGE.md

AuthProxy code changes (Phase 1) will be done in a separate session in the
kagenti-extensions repo.

## Verification

1. Deploy updated realm JSON to Keycloak (`--import-realm`)
2. Verify users alice/bob/carol can log in via password grant
3. Verify audience scopes exist: `summarizer-service-aud`, `reviewer-service-aud`
4. Verify agent-service routes.yaml is mounted
5. (After AuthProxy changes) Run `scripts/test-authbridge.sh` -- act claim tests
6. (After AuthProxy changes) Inspect JWT at document-service for nested `act`
