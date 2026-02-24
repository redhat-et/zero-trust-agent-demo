# Kagenti integration refactoring

## Goal

Refactor the summarizer-service so that the agent code contains **zero
authentication logic**. The SPIFFE/mTLS/token-exchange concerns move entirely
to the deployment layer (Envoy sidecar, SPIRE, Kustomize overlays). This
enables a two-stage demo:

1. **Without auth harness**: Agent calls document-service over plain HTTP.
   Only open documents are accessible.
2. **With auth harness**: Same agent binary, but Envoy sidecar intercepts
   traffic, injects identity tokens, and document-service enforces OPA
   policies. Restricted documents become accessible.

The agent binary is identical in both deployments.

## Current state

### What's embedded in the agent today

The summarizer-service currently contains these auth-related concerns:

| Concern             | Location               | What it does                                |
| ------------------- | ---------------------- | ------------------------------------------- |
| SPIFFE client init  | `cmd/serve.go:130-151` | Creates `WorkloadClient`, fetches X509-SVID |
| mTLS HTTP client    | `cmd/serve.go:154`     | `workloadClient.CreateMTLSClient()`         |
| Agent SPIFFE ID     | `cmd/serve.go:138,148` | Builds/stores `agentSPIFFEID` string        |
| Identity middleware | `cmd/serve.go:213`     | `spiffe.IdentityMiddleware()` wraps mux     |
| mTLS server config  | `cmd/serve.go:215`     | `workloadClient.CreateHTTPServer()`         |
| TLS listener        | `cmd/serve.go:271-275` | Conditional `ListenAndServeTLS`             |
| SPIFFE client close | `cmd/serve.go:233-234` | Shutdown cleanup                            |
| Delegation context  | `cmd/serve.go:389-395` | Builds `user_spiffe_id`, `agent_spiffe_id`  |
| X-SPIFFE-ID header  | `cmd/serve.go:413`     | Sets agent identity on outgoing requests    |

### What's in shared packages

| Package         | Files                       | Auth-related content                          |
| --------------- | --------------------------- | --------------------------------------------- |
| `pkg/spiffe`    | `workload.go`               | Full SPIFFE client, mTLS, identity middleware |
| `pkg/a2abridge` | `executor.go`, `message.go` | `DelegationContext` struct, extraction logic  |
| `pkg/config`    | `config.go`                 | `SPIFFEConfig`, `MockSPIFFE` flag             |

## Target state

### Agent code (auth-free)

After refactoring, `cmd/serve.go` should:

- Create a plain `http.Client` (no mTLS)
- Start a plain HTTP server (no TLS)
- Fetch documents via a simple `GET /documents/{id}` (no delegation context)
- Have no imports from `pkg/spiffe`
- Have no SPIFFE-related config fields
- Have no `MockSPIFFE` flag (there's nothing to mock)

### Sidecar handles auth transparently

The Envoy sidecar (deployed via Kustomize overlay) handles:

- Outbound: intercepts HTTP to document-service, performs token exchange,
  injects `Authorization: Bearer <token>`
- Inbound: validates caller identity (optional, for service-to-service trust)
- The agent never sees tokens, certificates, or SPIFFE IDs

### Document-service handles policy

The document-service operates in two modes:

- **No auth**: serves all documents without access checks
- **With auth**: validates JWT from request, evaluates OPA policies using
  claims (agent identity, user identity, departments)

## Refactoring changes

### Phase 1: Clean up the agent binary

#### `cmd/serve.go` — rewrite service struct

Remove all SPIFFE fields. The service only needs an HTTP client, document
service URL, logger, and LLM provider.

```go
// BEFORE
type SummarizerService struct {
    httpClient         *http.Client
    documentServiceURL string
    log                *logger.Logger
    trustDomain        string
    workloadClient     *spiffe.WorkloadClient
    llmProvider        llm.Provider
    agentSPIFFEID      string
}

// AFTER
type SummarizerService struct {
    httpClient         *http.Client
    documentServiceURL string
    log                *logger.Logger
    llmProvider        llm.Provider
}
```

#### `cmd/serve.go` — simplify `runServe()`

Remove the entire SPIFFE initialization block (lines 129-154). Replace with:

```go
httpClient := &http.Client{Timeout: 30 * time.Second}
```

Remove the identity middleware wrapping (line 213). Use the mux directly:

```go
// BEFORE
handler := spiffe.IdentityMiddleware(cfg.Service.MockSPIFFE)(mux)
server := workloadClient.CreateHTTPServer(cfg.Service.Addr(), handler)

// AFTER
server := &http.Server{
    Addr:    cfg.Service.Addr(),
    Handler: mux,
}
```

Remove conditional TLS listening (lines 270-275). Always use plain HTTP:

```go
// BEFORE
if !cfg.Service.MockSPIFFE && server.TLSConfig != nil {
    serverErr = server.ListenAndServeTLS("", "")
} else {
    serverErr = server.ListenAndServe()
}

// AFTER
serverErr = server.ListenAndServe()
```

Remove SPIFFE client close from shutdown (lines 233-234).

Remove SPIFFE-related log lines (lines 243, 245).

#### `cmd/serve.go` — simplify `SummarizeRequest`

Remove user identity fields. The agent only needs the document ID.

```go
// BEFORE
type SummarizeRequest struct {
    DocumentID      string   `json:"document_id"`
    UserSPIFFEID    string   `json:"user_spiffe_id"`
    UserDepartments []string `json:"user_departments,omitempty"`
}

// AFTER
type SummarizeRequest struct {
    DocumentID string `json:"document_id"`
}
```

#### `cmd/serve.go` — simplify `fetchDocumentWithDelegation()`

Rename to `fetchDocument()`. Replace the POST-with-delegation-context with a
simple GET.

```go
// BEFORE: POST /access with delegation body and X-SPIFFE-ID header

// AFTER
func (s *SummarizerService) fetchDocument(
    ctx context.Context, documentID string,
) (map[string]any, error) {
    url := fmt.Sprintf("%s/documents/%s", s.documentServiceURL, documentID)
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }
    req.Header.Set("Accept", "application/json")

    resp, err := s.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("document service request failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusForbidden {
        return nil, fmt.Errorf("access denied")
    }
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("document service returned status %d",
            resp.StatusCode)
    }

    var result map[string]any
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }

    if doc, ok := result["document"].(map[string]any); ok {
        return doc, nil
    }
    return result, nil
}
```

#### `cmd/serve.go` — simplify `handleSummarize()`

Remove the `UserSPIFFEID` validation. Update the `fetchDocument` call:

```go
// BEFORE
if req.DocumentID == "" || req.UserSPIFFEID == "" {

// AFTER
if req.DocumentID == "" {
```

```go
// BEFORE
doc, err := s.fetchDocumentWithDelegation(r.Context(), req)

// AFTER
doc, err := s.fetchDocument(r.Context(), req.DocumentID)
```

Remove delegation-related metrics labels (change `"delegated"` to
`"direct"`).

#### `cmd/serve.go` — remove `fetchDocumentForA2A()`

This adapter function exists only to convert between `DelegationContext` and
`SummarizeRequest`. It goes away entirely.

#### `cmd/serve.go` — simplify CLI flags

Remove all flags from `init()` that relate to SPIFFE. Keep only:

- `--document-service-url`
- `--llm-provider`, `--llm-api-key`, `--llm-base-url`, `--llm-model`
- `--llm-max-tokens`, `--llm-timeout`

#### `cmd/serve.go` — update imports

Remove:

```go
"github.com/redhat-et/zero-trust-agent-demo/pkg/spiffe"
```

#### `cmd/root.go` — update description

```go
// BEFORE
Short: "Summarizer Agent Service for SPIFFE/SPIRE Zero Trust Demo",
Long:  `...using Claude AI with SPIFFE workload identity and delegated access.`,

// AFTER
Short: "Summarizer Agent Service",
Long:  `Summarizer Agent Service provides document summarization using AI.`,
```

#### `cmd/serve.go` — change default port

```go
// BEFORE
if cfg.Service.Port == 0 {
    cfg.Service.Port = 8086
}

// AFTER
if cfg.Service.Port == 0 {
    cfg.Service.Port = 8000  // Kagenti default
}
```

### Phase 2: Refactor `pkg/a2abridge`

#### `message.go` — remove `DelegationContext`

Replace with a simple message extractor that pulls document ID from the A2A
message text.

```go
// BEFORE: DelegationContext with document_id, user_spiffe_id,
//         user_departments, review_type
// ExtractDelegationContext() parses DataPart

// AFTER: extract document ID from user message text
// e.g., "Summarize DOC-002" → document_id = "DOC-002"
```

The A2A message should carry the user's natural language request. The agent
parses the document ID from the text (or accepts it as a structured parameter
if using DataPart — but without identity fields).

#### `executor.go` — remove delegation types

```go
// BEFORE
type DocumentFetcher func(
    ctx context.Context, dc *DelegationContext,
) (map[string]any, error)

type LLMProcessor func(
    ctx context.Context, dc *DelegationContext,
    title, content string,
) (string, error)

// AFTER
type DocumentFetcher func(
    ctx context.Context, documentID string,
) (map[string]any, error)

type LLMProcessor func(
    ctx context.Context, title, content string,
) (string, error)
```

Update `DelegatedExecutor.Execute()` to use the simplified types. Rename to
`SummarizerExecutor` since it's no longer about delegation.

#### `client.go` — simplify `InvokeRequest`

Remove `UserSPIFFEID` and `UserDepartments` from `InvokeRequest`. The client
sends only the document ID and the task description.

#### `discovery.go` — no changes needed

Agent discovery via Kubernetes labels is orthogonal to auth.

### Phase 3: Config cleanup

#### `pkg/config/config.go`

The `CommonConfig` struct is shared across services. Don't remove
`SPIFFEConfig` from it — other services (document-service, web-dashboard)
still use it. Instead, the summarizer's `Config` struct in `cmd/serve.go`
should stop embedding `CommonConfig` and define only what it needs:

```go
type Config struct {
    Service            ServiceConfig `mapstructure:"service"`
    DocumentServiceURL string        `mapstructure:"document_service_url"`
    LLM                llm.Config    `mapstructure:"llm"`
}

type ServiceConfig struct {
    Host       string `mapstructure:"host"`
    Port       int    `mapstructure:"port"`
    HealthPort int    `mapstructure:"health_port"`
    LogLevel   string `mapstructure:"log_level"`
}
```

No `MockSPIFFE`, no `ListenPlainHTTP`, no `SPIFFEConfig`.

### Phase 4: Standalone module (for kagenti contribution)

When contributing to `kagenti/agent-examples`, the summarizer needs its own
`go.mod` — it can't depend on the monorepo's shared packages. Extract what's
needed:

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

| Monorepo package | Destination        | What to keep                                   |
| ---------------- | ------------------ | ---------------------------------------------- |
| `pkg/a2abridge`  | `internal/agent`   | `BuildAgentCard`, simplified executor          |
| `pkg/llm`        | `internal/llm`     | `Provider` interface, implementations, prompts |
| `pkg/logger`     | remove             | Use `log/slog` directly                        |
| `pkg/config`     | remove             | Use Viper directly in `cmd/`                   |
| `pkg/metrics`    | remove or simplify | Optional Prometheus metrics                    |
| `pkg/spiffe`     | **do not copy**    | Not needed in the agent                        |

### Phase 5: Document-service changes

The document-service needs to support both modes. This is outside the
summarizer refactoring but required for the demo.

**Without auth (default)**:

- `GET /documents/{id}` returns any document, no auth check
- OPA evaluation skipped or runs with a permissive default policy

**With auth (overlay-enabled)**:

- Envoy sidecar injects `Authorization: Bearer <token>` on incoming requests
- Document-service validates JWT, extracts claims
- OPA evaluates policy using token claims (agent identity, user identity,
  departments)
- Returns 403 if policy denies access

The key point: the document-service API path stays the same (`GET
/documents/{id}`). The difference is whether an auth token is present in the
request headers. When no token is present, the service either allows open
access or denies restricted documents — depending on the document's
classification.

## Environment variables

### Summarizer agent (simplified)

```text
# Required
LLM_API_KEY=sk-...            # or ANTHROPIC_API_KEY
LLM_PROVIDER=anthropic        # anthropic | openai | litellm

# Optional
LLM_MODEL=claude-sonnet-4-20250514
LLM_BASE_URL=                  # for OpenAI-compatible endpoints
LLM_MAX_TOKENS=4096
LLM_TIMEOUT=45
DOCUMENT_SERVICE_URL=http://document-service:8084
PORT=8000                      # Kagenti default
```

### Removed from agent config

```text
# These move to the Kustomize overlay / sidecar config
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
│ User │────▶│ Summarizer│─────────────────────────▶│ Envoy │─────────────────▶│ Document Service │
│      │◀────│ Agent     │◀─────────────────────────│Sidecar│◀─────────────────│ (auth mode)      │
└──────┘     └───────────┘                          └───────┘                  └──────────────────┘
                  │              transparent                     JWT validated
                  │              token injection                 OPA policy checked
                  ▼
              ┌───────┐
              │  LLM  │
              └───────┘
```

Same agent binary. Envoy sidecar added via Kustomize overlay. Document
service validates JWT and enforces OPA policies. Restricted documents now
accessible (if policy allows).

## Migration checklist

- [ ] Remove SPIFFE imports and initialization from `cmd/serve.go`
- [ ] Simplify `SummarizerService` struct (remove auth fields)
- [ ] Replace `fetchDocumentWithDelegation()` with `fetchDocument()`
- [ ] Remove `fetchDocumentForA2A()` adapter
- [ ] Simplify `SummarizeRequest` (remove identity fields)
- [ ] Remove identity middleware from HTTP handler chain
- [ ] Replace mTLS server with plain HTTP server
- [ ] Change default port to 8000
- [ ] Update root command description
- [ ] Refactor `pkg/a2abridge/executor.go` (remove `DelegationContext`)
- [ ] Refactor `pkg/a2abridge/message.go` (simplify message extraction)
- [ ] Simplify `pkg/a2abridge/client.go` (remove identity from requests)
- [ ] Create standalone config struct (drop `CommonConfig` embedding)
- [ ] Update Dockerfile if port changes
- [ ] Update document-service to support unauthenticated GET endpoint
- [ ] Create Kustomize overlay that adds Envoy sidecar to summarizer
- [ ] Test both deployment modes end to end
- [ ] Extract standalone module for `kagenti/agent-examples` contribution
