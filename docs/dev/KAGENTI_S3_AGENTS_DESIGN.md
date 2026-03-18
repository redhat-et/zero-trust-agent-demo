# Kagenti S3 agents design

**Status**: Approved
**Date**: 2026-03-17
**Context**: Bring-your-own-agent integration with Kagenti using S3-backed
documents and AuthBridge for transparent access control.

## Problem statement

We want to demonstrate the "bring your own agent" pattern with Kagenti:
a Python-based agent that knows nothing about authentication or access
control, yet is transparently restricted by zero-trust policies when
deployed in a Kagenti-managed cluster.

The agent accepts any document URL (S3 or web), fetches it via plain
HTTP, and summarizes or reviews it. When deployed in Kagenti, AuthBridge
intercepts outbound S3 requests and enforces the permission intersection
(`User Departments ∩ Agent Capabilities`) without any agent code changes.

## Architecture overview

```text
┌────────────┐    ┌───────────────────────────────────────────────┐
│    Web      │    │  Agent Pod (Kagenti-managed)                  │
│  Dashboard  │    │                                               │
│            │───▶│  ┌─────────────┐     ┌──────────────────────┐ │
│  (user picks│    │  │  Python     │────▶│  AuthBridge sidecar   │ │
│   doc +     │    │  │  Agent      │     │                      │ │
│   agent)    │    │  │  (auth-     │     │  1. Intercept GET    │ │
│            │    │  │   unaware)  │     │  2. Token exchange   │ │
└────────────┘    │  └─────────────┘     │  3. Route to cred-gw │ │
                  │                      └──────────┬───────────┘ │
                  └─────────────────────────────────┼─────────────┘
                                                    │
                         ┌──────────────────────────┼──────────┐
                         │                          ▼          │
                         │  ┌──────────────┐  ┌──────────┐    │
                         │  │  Credential  │  │   OPA    │    │
                         │  │  Gateway     │──│ (policy) │    │
                         │  │  (S3 proxy)  │  └──────────┘    │
                         │  └──────┬───────┘                   │
                         │         │                           │
                         │         ▼                           │
                         │  ┌──────────┐                       │
                         │  │   AWS S3  │                       │
                         │  └──────────┘                       │
                         │          Cluster services            │
                         └─────────────────────────────────────┘
```

## Components

### Python agents

Two self-contained Python agents in separate directories, each
independently deployable via Kagenti.

**kagenti-summarizer**: Fetches a document from any URL and produces
an AI summary. OPA capabilities: `["finance"]` (restricted).

**kagenti-reviewer**: Fetches a document from any URL and produces
a review (general, compliance, or security). OPA capabilities:
`["engineering", "finance", "admin", "hr"]` (broad access).

Both agents share the same structure but are fully independent with
no shared code imports, making them easy to extract to separate
repositories later.

#### Directory layout

```text
kagenti-summarizer/
├── pyproject.toml          # uv-managed dependencies
├── Dockerfile
├── agent.py                # A2A agent (Google a2a-python SDK v1.0)
├── summarizer.py           # URL fetch + LLM summarization
├── llm.py                  # Multi-provider LLM abstraction
└── agent-card.json         # Static agent card

kagenti-reviewer/
├── pyproject.toml
├── Dockerfile
├── agent.py                # A2A agent (url-review skill)
├── reviewer.py             # URL fetch + LLM review
├── llm.py                  # Multi-provider LLM abstraction
└── agent-card.json
```

#### Agent behavior

1. Receive A2A `tasks/send` with a URL in the message text
1. Extract URL via regex (`s3://...` or `https://...`)
1. If `s3://bucket/path`, convert to `https://bucket.s3.amazonaws.com/path`
1. Make a plain `GET` request via `httpx` to fetch content
1. Send content to configured LLM with system prompt
1. Return result as A2A task artifact

The reviewer additionally accepts an optional `review_type` parameter
(`general`, `compliance`, `security`) with different system prompts.

#### Configuration

| Env var | Default | Purpose |
| ------- | ------- | ------- |
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `8000` | Listen port |
| `LLM_PROVIDER` | `anthropic` | `anthropic`, `openai`, `litellm`, `mock` |
| `LLM_API_KEY` | — | API key for chosen provider |
| `LLM_BASE_URL` | — | Custom endpoint (LiteLLM/vLLM) |
| `LLM_MODEL` | per-provider | Model override |

When `LLM_API_KEY` is not set, the agent falls back to mock mode:
returns a canned response with document metadata (URL, content length,
first 200 chars).

#### A2A and Kagenti integration

Both agents use Google's `a2a-python` SDK v1.0 GA and expose:

- `/.well-known/agent-card.json` — static agent card
- `/a2a` — JSON-RPC endpoint for A2A messages
- `/health` — health check

Kagenti discovery labels on the Deployment:

```yaml
labels:
  kagenti.io/type: agent
  protocol.kagenti.io/a2a: ""
```

#### Agent card (summarizer example)

```json
{
  "name": "S3 Document Summarizer",
  "url": "http://kagenti-summarizer:8000",
  "version": "1.0.0",
  "defaultInputModes": ["application/json"],
  "defaultOutputModes": ["text/plain"],
  "skills": [{
    "id": "url-summarization",
    "name": "URL Document Summarization",
    "description": "Fetches a document from any URL and summarizes it",
    "tags": ["summarization", "s3"]
  }]
}
```

### AuthBridge sidecar (no code changes)

AuthBridge already intercepts outbound HTTP requests via iptables and
performs RFC 8693 token exchange per route. For S3 access, we add a
route entry — no AuthBridge code changes required.

#### Outbound flow

1. Agent sends `GET https://bucket.s3.amazonaws.com/path`
1. Envoy outbound listener captures the request (iptables redirect)
1. Ext-proc sees the host matches `*.s3.amazonaws.com`
1. Ext-proc performs token exchange → JWT with `act` claims
1. Envoy routes the request to credential gateway (host rewrite)
1. Credential gateway receives GET + JWT, proxies from S3

#### Route configuration

Add to AuthBridge `routes.yaml`:

```yaml
- host: "*.s3.amazonaws.com"
  target_audience: "credential-gateway"
  token_scopes: "openid"
- host: "*.s3.*.amazonaws.com"
  target_audience: "credential-gateway"
  token_scopes: "openid"
```

#### Envoy route addition

The Envoy outbound listener needs a route rule that rewrites
`*.s3.amazonaws.com` destinations to the credential gateway service,
prepending `/s3-proxy/` to the path. For example,
`GET /finance/q4-report.md` to `zt-demo-documents.s3.amazonaws.com`
becomes `GET /s3-proxy/finance/q4-report.md` to the credential
gateway. This is an Envoy config change in the sidecar deployment,
applied via Kustomize patch or Kagenti operator config.

### Credential gateway S3 proxy endpoint

Extend the existing credential gateway with a proxy mode that fetches
S3 objects on behalf of the caller. The existing `POST /credentials`
endpoint remains unchanged — the proxy is an additional handler.

#### Endpoint

`GET /s3-proxy/{key...}` — proxies S3 object fetches. The S3 bucket
is configured via the existing `--s3-bucket` / `AWS_S3_BUCKET` flag
(already present in the gateway). The `{key...}` is the S3 object key
(e.g., `finance/q4-report.md`).

#### Request example

```text
GET /s3-proxy/finance/q4-report.md
Authorization: Bearer <JWT-with-act-claims>
```

#### Processing steps

1. Strip `/s3-proxy/` prefix to get S3 key (`finance/q4-report.md`)
1. Validate JWT using existing validation logic (JWKS or dev mode)
1. Extract delegation chain from `sub` + `act` claims (existing code)
1. Query OPA at `/v1/data/demo/credential_gateway/proxy_decision`
   with extended input (see OPA input schema below)
1. If denied: return HTTP 403 with JSON error body
1. If allowed: call `s3:GetObject` using scoped STS credentials
   (existing `AssumeRole` + session policy logic), return object
   body with `Content-Type: text/markdown`

#### OPA input schema (extended)

The existing `OPAIntersectionInput` Go struct gains an optional
`S3Key` field. The proxy endpoint populates it; the existing
`POST /credentials` endpoint leaves it empty.

```go
type OPAIntersectionInput struct {
    User    string `json:"user"`
    Agent   string `json:"agent"`
    Target  string `json:"target_service"`
    Action  string `json:"action"`
    S3Key   string `json:"s3_key,omitempty"`
}
```

#### Error responses

| Condition | HTTP status | Body |
| --------- | ----------- | ---- |
| Missing/invalid JWT | 401 | `{"error": "unauthorized"}` |
| OPA denies access | 403 | `{"error": "forbidden", "reason": "..."}` |
| S3 object not found | 404 | `{"error": "not found"}` |
| S3/STS failure | 502 | `{"error": "upstream error"}` |

### OPA policy extension

#### Manifest-based document lookup

The existing `scripts/seed-s3.sh` already produces a `manifest.json`
at the S3 bucket root, mapping each S3 key to its departments (parsed
from YAML front matter in `sample-documents/`). This manifest data
is loaded into OPA as `data.demo.s3_documents` via a ConfigMap
(generated from the manifest JSON, mounted alongside existing policy
files under `/policies/`).

Example manifest entry:

```json
{
  "id": "DOC-005",
  "title": "Budget Projections",
  "key": "engineering/budget.md",
  "departments": ["finance", "engineering"]
}
```

This handles multi-department documents correctly. DOC-005 lives under
`engineering/` but belongs to both `finance` and `engineering`.

#### Policy logic

New rule in `credential_gateway.rego`, queried at
`/v1/data/demo/credential_gateway/proxy_decision`. Uses the existing
`permission_intersection` computation and adds S3 key lookup.

```rego
s3_doc_departments(key) := depts if {
    some doc in data.demo.s3_documents
    doc.key == key
    depts := doc.departments
}

proxy_decision := {"allow": true, "reason": reason} if {
    depts := s3_doc_departments(input.s3_key)
    some dept in depts
    dept in permission_intersection
    reason := sprintf("allowed: %s", [input.s3_key])
}
```

When `input.s3_key` is absent (existing `POST /credentials` flow),
this rule does not fire and the existing `decision` rule applies.

#### New agent capability entries

These use the `kagenti-` prefix to avoid collision with the existing
Go-based `summarizer` and `reviewer` agents. The agent name in OPA
must match the `azp` (authorized party) or `act.sub` claim in the JWT
that AuthBridge produces during token exchange. The Keycloak client ID
for each agent determines this value.

```rego
agent_capabilities["kagenti-summarizer"] := ["finance"]
agent_capabilities["kagenti-reviewer"] := ["engineering", "finance", "admin", "hr"]
```

### Dashboard and document metadata

#### Document store extension

Add `s3_url` field to each document in
`document-service/internal/store/documents.go`:

```go
S3URL: "s3://zt-demo-documents/engineering/roadmap.md"
```

The `GET /documents` response includes the new field:

```json
{
  "id": "DOC-001",
  "title": "Engineering Roadmap",
  "department": "engineering",
  "s3_url": "s3://zt-demo-documents/engineering/roadmap.md"
}
```

#### Dashboard behavior

When the user selects a document and targets a kagenti agent, the
dashboard sends the `s3_url` in the A2A message instead of
`document_id`. Existing Go agents continue to use `document_id` —
no breaking changes.

## Test matrix

| User | Agent | Document | S3 key | Expected |
| ---- | ----- | -------- | ------ | -------- |
| Alice | kagenti-summarizer | Q4 Report | `finance/q4-report.md` | Allowed |
| Alice | kagenti-summarizer | Roadmap | `engineering/roadmap.md` | Denied |
| Alice | kagenti-summarizer | Budget | `engineering/budget.md` | Allowed |
| Alice | kagenti-reviewer | Roadmap | `engineering/roadmap.md` | Allowed |
| Carol | kagenti-summarizer | Q4 Report | `finance/q4-report.md` | Denied |
| Carol | kagenti-reviewer | HR Guide | `hr/guidelines.md` | Allowed |

**Alice + kagenti-summarizer**: intersection is `[finance]`. Q4 Report
(finance) allowed. Roadmap (engineering) denied. Budget
(finance + engineering) allowed because `finance` is in the
intersection.

**Carol + kagenti-summarizer**: intersection of `[hr]` and `[finance]`
is empty. All documents denied.

**Carol + kagenti-reviewer**: intersection is `[hr]`. HR Guidelines
(hr) allowed.

## Deployment

### Container images

| Image | Base | Notes |
| ----- | ---- | ----- |
| `kagenti-summarizer` | `python:3.12-slim` + `uv` | A2A agent |
| `kagenti-reviewer` | `python:3.12-slim` + `uv` | A2A agent |
| `credential-gateway` | existing alpine image | Add proxy handler |

### Kubernetes manifests

Each Python agent gets a Deployment (with Kagenti labels), Service,
and ConfigMap for the agent card. A Kustomize overlay
(`overlays/kagenti-s3-agents`) ties it together with the credential
gateway, OPA policy ConfigMap update, and Envoy route patches.

### Demo flow

1. Deploy to OpenShift with Kagenti operator
1. Kagenti discovers both agents via labels, attaches AuthBridge
1. User logs into dashboard, selects a document (sees S3 URL)
1. User picks kagenti-summarizer → agent receives S3 URL
1. Agent converts to HTTPS, makes plain GET
1. AuthBridge intercepts, does token exchange, routes to credential GW
1. Credential gateway validates JWT, checks OPA, fetches from S3
1. Content returns to agent → agent summarizes → result in dashboard
1. Repeat with kagenti-reviewer to show different access rights

## Implementation phases

| Phase | Description | Scope |
| ----- | ----------- | ----- |
| 1 | Python agents (summarizer + reviewer) | New code |
| 2 | Credential gateway S3 proxy endpoint | Extend existing |
| 3 | OPA policy with manifest-based lookup | Extend existing |
| 4 | Document store `s3_url` field + dashboard | Extend existing |
| 5 | Deployment manifests + Kagenti labels | New config |
| 6 | AuthBridge route config + Envoy routing | Config only |
| 7 | End-to-end testing | Integration test |

## Change summary

| Component | Change type | Scope |
| --------- | ----------- | ----- |
| `kagenti-summarizer/` | New | Self-contained Python agent |
| `kagenti-reviewer/` | New | Self-contained Python agent |
| `credential-gateway/` | Extend | Add S3 proxy endpoint |
| `opa-service/policies/` | Extend | Manifest lookup, new agents |
| `document-service/` | Extend | Add `s3_url` field |
| `web-dashboard/` | Extend | Send S3 URL for kagenti agents |
| `deploy/k8s/` | New overlay | Kagenti deployment config |
| AuthBridge | **No code changes** | Route config only |
