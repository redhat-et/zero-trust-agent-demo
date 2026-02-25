# Kagenti integration refactoring

## Goal

Refactor the agent services (summarizer-service, reviewer-service) so that
the agent code contains **zero authentication logic**. The
SPIFFE/mTLS/token-exchange concerns move entirely to the deployment layer
(AuthBridge sidecar, Kustomize overlays). This enables a two-stage demo:

1. **Without auth harness**: Agent calls document-service over plain HTTP.
   Only open documents are accessible.
2. **With auth harness**: Same agent binary, but AuthBridge sidecar
   intercepts traffic, performs token exchange, and document-service
   enforces OPA policies. Restricted documents become accessible.

The agent binary is identical in both deployments.

## Completed work

### Phase 1: Clean up agent binaries (done)

Both `summarizer-service/cmd/serve.go` and `reviewer-service/cmd/serve.go`
have been refactored:

- Removed all SPIFFE imports and initialization
- Service structs contain only `httpClient`, `documentServiceURL`, `log`,
  `llmProvider` (no `trustDomain`, `workloadClient`, `agentSPIFFEID`)
- Uses plain `http.Client` and `http.Server` (no mTLS)
- `fetchDocument()` does simple `GET /documents/{id}` (no delegation
  context, no `POST /access`, no `X-SPIFFE-ID` header)
- Removed `fetchDocumentForA2A()` adapter functions
- Request structs contain only functional fields (`DocumentID`,
  `ReviewType`) — no `UserSPIFFEID`, `UserDepartments`
- No identity middleware in HTTP handler chain
- Default port changed to 8000 (Kagenti default) for both services
- Root command descriptions updated (no SPIFFE references)
- `agent-service/cmd/serve.go` updated to use simplified
  `InvokeRequest` (no identity fields)

### Phase 2: Refactor `pkg/a2abridge` (done)

- **`message.go`**: Replaced `DelegationContext` struct and
  `ExtractDelegationContext()` with `ExtractDocumentID()` (supports
  DataPart with `document_id` or DOC-NNN pattern in text) and
  `ExtractReviewType()` for the reviewer's optional parameter
- **`executor.go`**: Renamed `DelegatedExecutor` to `AgentExecutor`.
  `DocumentFetcher` signature is `func(ctx, documentID, bearerToken
  string)`. Delegation context is extracted from HTTP headers
  (`X-Delegation-User`, `X-Delegation-Agent`) and stored in Go context
  via `WithDelegation()` — the agent's `FetchDocument` callback never
  sees delegation fields
- **`client.go`**: `InvokeRequest` carries `DocumentID`, `ReviewType`,
  `BearerToken`, `UserSPIFFEID`, and `AgentSPIFFEID`. Delegation is
  sent as HTTP headers via CallMeta (not in the A2A DataPart)
- **`delegation.go`** (new): `DelegationContext` struct,
  `WithDelegation`/`DelegationFrom` context helpers, and
  `DelegationTransport` (an `http.RoundTripper` that injects
  `X-Delegation-*` headers from context into outbound HTTP requests)

### Phase 6: Delegation header forwarding (done)

Delegation context now flows transparently as HTTP headers through
the A2A chain, replacing the interim Phase 5a approach that embedded
delegation logic in agent code.

**Headers:**

- `X-Delegation-User` — User SPIFFE ID
- `X-Delegation-Agent` — Agent SPIFFE ID

**Changes made:**

- **`pkg/a2abridge/delegation.go`** (new): `DelegationTransport`
  wraps `http.RoundTripper`, injects `X-Delegation-*` headers from
  Go context. Context helpers: `WithDelegation`/`DelegationFrom`
- **`pkg/a2abridge/executor.go`**: Extracts delegation from HTTP
  headers (via CallMeta), stores in context. `DocumentFetcher`
  simplified to `func(ctx, documentID, bearerToken string)`
- **`pkg/a2abridge/client.go`**: Sends delegation as CallMeta
  headers (`x-delegation-user`, `x-delegation-agent`), not DataPart
- **`pkg/a2abridge/message.go`**: Removed `ExtractUserSPIFFEID()`
- **Summarizer/reviewer `cmd/serve.go`**: Removed
  `fetchDocumentWithDelegation()`, `fetchDocument` is a simple GET.
  HTTP client wrapped with `DelegationTransport`
- **Document-service `cmd/serve.go`**: GET handler reads
  `X-Delegation-User` and `X-Delegation-Agent` as fallback when
  JWT `sub` is a Keycloak UUID (not a SPIFFE ID)
- **Agent-service `cmd/serve.go`**: Passes `AgentSPIFFEID` in
  `InvokeRequest` so delegation headers include agent identity
- **Ext-proc** (`kagenti-extensions`): Outbound handler logs
  delegation headers as OTel span attributes

**Security considerations (future hardening):**

- Inbound ext-proc could strip `X-Delegation-*` from external
  requests to prevent spoofing (not yet implemented)
- Headers are only meaningful when JWT validation is active

### Phase 3: Config cleanup — remove MockSPIFFE (deferred)

`MockSPIFFE` and `ListenPlainHTTP` overlap: both result in plain HTTP,
header-based identity, and no SPIRE connection. The naming is confusing
— "mock SPIFFE" suggests something is being faked, when it really just
means "plain HTTP without SPIRE." Additionally, AI agent AuthBridge
overlays set `MOCK_SPIFFE=true` but the binary ignores it (Phase 1
removed all SPIFFE code from agents) — it's dead config.

**Plan:** Remove `MockSPIFFE` entirely. Make `ListenPlainHTTP` the
single flag that controls plain HTTP mode (and skips SPIRE connection).

Two clean modes remain:

| Mode | ListenPlainHTTP | Behavior |
| --- | --- | --- |
| mTLS (default) | false | Connect to SPIRE, mTLS server, cert-based identity |
| Plain HTTP | true | Skip SPIRE, plain HTTP server, header-based identity |

**Files to change:**

| Area | Change |
| --- | --- |
| `pkg/config/config.go` | Remove `MockSPIFFE` field, CLI flag, viper binding |
| `pkg/spiffe/` | Skip SPIRE connection when `ListenPlainHTTP=true` |
| 5 service `cmd/serve.go` | Replace `MockSPIFFE` with `ListenPlainHTTP` in conditionals |
| `mock` overlay | Remove or convert to `ListenPlainHTTP=true` |
| `mock-ai-agents` overlay | Same |
| `local` overlay | Remove `MOCK_SPIFFE=false` patches (it's the default) |
| AuthBridge AI agent patches | Remove dead `MOCK_SPIFFE=true` env vars |
| `deploy/k8s/deployments.yaml` | Remove `MOCK_SPIFFE` env vars |
| Documentation | Update all references |

Individual service debugging (`make run-document` etc.) would use
`--listen-plain-http` flag instead of `--mock-spiffe`.

## Remaining work

### Phase 4: Standalone module (for kagenti contribution)

When contributing to `kagenti/agent-examples`, the summarizer needs its
own `go.mod` — it can't depend on the monorepo's shared packages. See
the target directory structure and package mapping below.

```text
a2a/a2a_summarizer/
├── go.mod              # standalone module
├── go.sum
├── main.go
├── cmd/
│   ├── root.go
│   └── serve.go
├── internal/
│   ├── agent/          # A2A executor, agent card builder
│   ├── llm/            # LLM provider interface + implementations
│   └── document/       # document-service client
├── Dockerfile
└── README.md
```

Packages to inline (copy and simplify, not import):

| Monorepo package | Destination      | What to keep                                   |
| ---------------- | ---------------- | ---------------------------------------------- |
| `pkg/a2abridge`  | `internal/agent` | `BuildAgentCard`, simplified executor          |
| `pkg/llm`        | `internal/llm`   | `Provider` interface, implementations, prompts |
| `pkg/logger`     | remove           | Use `log/slog` directly                        |
| `pkg/config`     | remove           | Use Viper directly in `cmd/`                   |
| `pkg/metrics`    | remove           | Optional Prometheus metrics                    |
| `pkg/spiffe`     | **do not copy**  | Not needed in the agent                        |

### Phase 5: Document-service changes

The document-service needs to support both modes. This is outside the
agent refactoring but required for the demo.

**Without auth (default)**:

- `GET /documents/{id}` returns any document, no auth check
- OPA evaluation skipped or runs with a permissive default policy

**With auth (overlay-enabled)**:

- AuthBridge sidecar injects `Authorization: Bearer <token>` on requests
- Document-service validates JWT, extracts claims
- OPA evaluates policy using token claims (agent identity, user identity,
  departments)
- Returns 403 if policy denies access

The key point: the document-service API path stays the same (`GET
/documents/{id}`). The difference is whether an auth token is present in
the request headers. When no token is present, the service either allows
open access or denies restricted documents — depending on the document's
classification.

### Phase 6: Ext-proc delegation header forwarding (done)

See "Completed work" section above for details.

### Phase 7: `act` claim chain of custody

**Goal:** Track the full delegation chain across multi-hop agent
invocations using the RFC 8693 `act` (actor) claim. Each token exchange
hop nests the previous actor, producing an auditable chain of custody.

**Example:** For the chain `alice → agent-service → summarizer →
document-service`, the final token would contain:

```json
{
  "sub": "spiffe://demo.example.com/user/alice",
  "act": {
    "sub": "spiffe://demo.example.com/service/agent-service",
    "act": {
      "sub": "spiffe://demo.example.com/agent/summarizer"
    }
  }
}
```

**Workstreams:**

1. **Keycloak research** — Determine whether Keycloak produces nested
   `act` claims on chained token exchanges natively (RFC 8693 Section
   4.1). If not, identify whether a custom protocol mapper or token
   exchange SPI is needed. Test against the current Keycloak instance.

1. **Ext-proc changes** — After token exchange, extract and log the
   `act` chain as OpenTelemetry span attributes. Optionally enforce a
   configurable maximum chain depth (e.g., reject chains deeper than
   5 hops). This fits naturally as another feature flag alongside
   token exchange and telemetry.

1. **Document-service** — Read and log the `act` chain for audit
   purposes. Optionally expose the chain in OPA input so policies can
   inspect or constrain the delegation path.

1. **Dashboard visualization** — Display the delegation chain in the
   web dashboard when showing access decisions. The `act` claim
   provides a complete audit trail that is compelling for enterprise
   demos.

**Dependencies:**

- Phase 6 (delegation header forwarding) should land first — `act`
  tracking builds on the same ext-proc code paths
- Keycloak research may uncover limitations that affect the design

**Open questions:**

- Does Keycloak preserve nested `act` claims when the subject token
  already contains an `act` claim, or does it overwrite?
- Should the ext-proc validate the `act` chain (e.g., check that
  each actor is a known SPIFFE ID) or just pass it through?
- What is the performance impact of deeply nested `act` claims on
  token size and validation time?

## Target state

### Agent code (auth-free)

The agent `cmd/serve.go` files now:

- Create a plain `http.Client` (no mTLS)
- Start a plain HTTP server (no TLS)
- Fetch documents via a simple `GET /documents/{id}` (no delegation
  context)
- Have no imports from `pkg/spiffe`
- Have no `MockSPIFFE` flag (there's nothing to mock)

### AuthBridge sidecar handles auth and delegation transparently

The [AuthBridge][authbridge] sidecar (deployed via Kustomize overlay)
handles:

- Outbound: intercepts HTTP to document-service, performs Keycloak token
  exchange, injects `Authorization: Bearer <token>`
- Outbound: forwards `X-Delegation-User` and `X-Delegation-Agent`
  headers for OPA policy evaluation at document-service (Phase 6)
- Outbound: token exchange produces JWT with nested `act` claim for
  chain of custody auditing (Phase 7)
- Inbound: validates caller identity (optional, for service-to-service
  trust)
- The agent never sees tokens, certificates, SPIFFE IDs, or delegation
  context

[authbridge]: https://github.com/kagenti/kagenti-extensions/tree/main/AuthBridge

### Document-service handles policy

The document-service operates in two modes:

- **No auth**: serves all documents without access checks
- **With auth**: validates JWT from request, evaluates OPA policies using
  claims (agent identity, user identity, departments)

## Environment variables

### Agent services (simplified)

```text
# Required
LLM_API_KEY=sk-...            # or ANTHROPIC_API_KEY
LLM_PROVIDER=anthropic        # anthropic | openai | litellm

# Optional
LLM_MODEL=claude-sonnet-4-20250514
LLM_BASE_URL=                  # for OpenAI-compatible endpoints
LLM_MAX_TOKENS=4096
LLM_TIMEOUT=45
DOCUMENT_SERVICE_URL=http://document-service:8080
PORT=8000                      # Kagenti default
```

### Removed from agent config

```text
# These move to the Kustomize overlay / AuthBridge sidecar config
SPIFFE_DEMO_SPIFFE_SOCKET_PATH    → spiffe-helper container
SPIFFE_DEMO_SPIFFE_TRUST_DOMAIN   → spiffe-helper container
SPIFFE_DEMO_SERVICE_MOCK_SPIFFE   → removed entirely
SPIFFE_DEMO_SERVICE_LISTEN_PLAIN_HTTP → removed (always plain HTTP)
```

## Demo flow

### Stage 1: No authentication

```text
┌──────┐     ┌───────────┐  GET /documents/DOC-001  ┌──────────────────┐
│ User │────▶│ Summarizer│─────────────────────────▶│ Document Service │
│      │◀────│ Agent     │◀─────────────────────────│ (open mode)      │
└──────┘     └───────────┘   200 OK + content       └──────────────────┘
                  │
                  │ LLM API call
                  ▼
              ┌───────┐
              │  LLM  │
              └───────┘
```

All documents are accessible. No sidecars, no tokens, no policies.

### Stage 2: With authentication harness

```text
┌──────┐     ┌───────────┐  GET /documents/DOC-002  ┌───────┐  + Bearer token  ┌──────────────────┐
│ User │────▶│ Summarizer│─────────────────────────▶│  Auth │─────────────────▶│ Document Service │
│      │◀────│ Agent     │◀─────────────────────────│Bridge │◀─────────────────│ (auth mode)      │
└──────┘     └───────────┘                          └───────┘                  └──────────────────┘
                  │              transparent                     JWT validated
                  │              token exchange                  OPA policy checked
                  ▼
              ┌───────┐
              │  LLM  │
              └───────┘
```

Same agent binary. AuthBridge sidecar added via Kustomize overlay.
Document service validates JWT and enforces OPA policies. Restricted
documents now accessible (if policy allows).

## Migration checklist

- [x] Remove SPIFFE imports and initialization from agent `cmd/serve.go`
- [x] Simplify service structs (remove auth fields)
- [x] Replace `fetchDocumentWithDelegation()` with `fetchDocument()`
- [x] Remove `fetchDocumentForA2A()` adapter
- [x] Simplify request structs (remove identity fields)
- [x] Remove identity middleware from HTTP handler chain
- [x] Replace mTLS server with plain HTTP server
- [x] Change default port to 8000
- [x] Update root command descriptions
- [x] Refactor `pkg/a2abridge/executor.go` (rename to `AgentExecutor`)
- [x] Refactor `pkg/a2abridge/message.go` (replace with `ExtractDocumentID`)
- [x] Simplify `pkg/a2abridge/client.go` (remove identity from requests)
- [x] Update `agent-service` A2A invocation callsite
- [x] Apply same refactoring to reviewer-service
- [ ] Remove `MockSPIFFE`, collapse into `ListenPlainHTTP` (Phase 3)
- [ ] Create standalone config struct (drop `CommonConfig` embedding)
- [ ] Update Dockerfile if port changes
- [ ] Update document-service to support unauthenticated GET endpoint
- [x] Create Kustomize overlay that adds AuthBridge sidecar to agents
- [x] Test both deployment modes end to end (12/12 AuthBridge tests pass)
- [ ] Extract standalone module for `kagenti/agent-examples` contribution
- [x] Ext-proc: delegation header forwarding (Phase 6)
- [x] Revert interim delegation code (Phase 5a → Phase 6)
- [ ] Ext-proc: `act` claim chain of custody (Phase 7)
