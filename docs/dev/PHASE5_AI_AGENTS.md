# Phase 5: AI agents implementation

## Status: COMPLETE

## Overview

Phase 5 adds two AI agent services (Summarizer and Reviewer) that demonstrate real-world AI agent use cases with Zero Trust principles. These agents:

- Fetch documents via document-service with delegation context
- Call LLM APIs for AI processing (supports multiple providers)
- Return markdown output for dashboard display
- Integrate with OPA for permission intersection

This phase validates the core Zero Trust principle: **agents can only access resources that both the delegating user AND the agent are authorized to access**.

## Architecture

```text
┌─────────────────┐     ┌────────────────────┐     ┌──────────────────┐
│   Dashboard     │────▶│ summarizer-service │────▶│ document-service │
│     :8080       │     │       :8086        │     │      :8084       │
│                 │     └────────────────────┘     └────────┬─────────┘
│                 │                                         │
│                 │     ┌────────────────────┐              │
│                 │────▶│  reviewer-service  │──────────────┘
│                 │     │       :8087        │
└─────────────────┘     └────────────────────┘
                                  │
                                  ▼
                        ┌────────────────────┐
                        │     LLM API        │
                        │ (Anthropic/OpenAI/ │
                        │  LiteLLM/vLLM)     │
                        └────────────────────┘
```

## Agent capabilities

| Agent | Departments | Use Case |
| ----- | ----------- | -------- |
| summarizer | finance | Summarize financial documents only |
| reviewer | engineering, finance, admin, hr | Review any document for compliance/issues |

## Service ports

| Service | Main Port | Health Port |
| ------- | --------- | ----------- |
| summarizer-service | 8086 | 8186 |
| reviewer-service | 8087 | 8187 |

## Implementation details

### Shared LLM package (pkg/llm)

The `pkg/llm` package provides a multi-provider LLM abstraction supporting Anthropic Claude,
OpenAI, LiteLLM, and other OpenAI-compatible APIs.

```text
pkg/llm/
├── provider.go          # Provider interface definition
├── config.go            # Configuration with provider defaults
├── anthropic.go         # Anthropic Claude implementation
├── openai_compat.go     # OpenAI-compatible implementation (OpenAI, LiteLLM, vLLM)
├── factory.go           # NewProvider() factory function
└── prompts.go           # System prompts for agents
```

#### Provider interface

```go
type Provider interface {
    Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error)
    Model() string
    ProviderName() string
}

func NewProvider(cfg Config) (Provider, error)
```

#### Configuration

```yaml
llm:
  provider: ""           # anthropic (default), openai, litellm
  api_key: ""            # Set via LLM_API_KEY or ANTHROPIC_API_KEY env var
  base_url: ""           # Required for litellm, optional for openai
  model: ""              # Provider-specific default if empty
  max_tokens: 4096
  timeout_seconds: 45
```

#### Environment variables

| Variable | Description |
| -------- | ----------- |
| `LLM_PROVIDER` | Provider selection: `anthropic`, `openai`, `litellm` |
| `LLM_API_KEY` | API key (fallback: `ANTHROPIC_API_KEY`) |
| `LLM_BASE_URL` | Base URL for OpenAI-compatible APIs |
| `LLM_MODEL` | Model name (provider-specific default if empty) |

#### Provider defaults

| Provider | Default Model | Default Base URL |
| -------- | ------------- | ---------------- |
| anthropic | claude-sonnet-4-20250514 | (SDK default) |
| openai | gpt-4o | https://api.openai.com/v1 |
| litellm | qwen3-14b | (must be set via LLM_BASE_URL) |

### Summarizer service

**Endpoint:** `POST /summarize`

Request:

```json
{
  "document_id": "DOC-001",
  "user_spiffe_id": "spiffe://demo.example.com/user/alice",
  "user_departments": ["engineering", "finance"]
}
```

Response:

```json
{
  "allowed": true,
  "document_id": "DOC-001",
  "summary": "## Summary\n\n...",
  "processing_time_ms": 1234
}
```

### Reviewer service

**Endpoint:** `POST /review`

Request:

```json
{
  "document_id": "DOC-001",
  "user_spiffe_id": "spiffe://demo.example.com/user/alice",
  "user_departments": ["engineering", "finance"],
  "review_type": "compliance"
}
```

Response:

```json
{
  "allowed": true,
  "document_id": "DOC-001",
  "review": "## Compliance Review\n\n...",
  "issues_found": 2,
  "severity": "medium",
  "processing_time_ms": 2345
}
```

Review types: `general`, `compliance`, `security`

## Document access flow

```text
1. Dashboard calls /summarize or /review with user context
         │
         ▼
2. AI Agent service calls document-service /access with:
   - document_id
   - delegation.user_spiffe_id (e.g., spiffe://demo.example.com/user/alice)
   - delegation.agent_spiffe_id (e.g., spiffe://demo.example.com/agent/summarizer)
   - delegation.user_departments (from JWT claims if OIDC enabled)
         │
         ▼
3. Document-service queries OPA for authorization
         │
         ▼
4. OPA computes permission intersection:
   effective = user_departments ∩ agent_capabilities
         │
         ▼
5. If allowed, document content returned to AI agent
         │
         ▼
6. AI agent sends content to Claude API
         │
         ▼
7. Returns markdown response to dashboard
```

## Permission tests

| User | Agent | Document | Result | Reason |
| ---- | ----- | -------- | ------ | ------ |
| Alice (eng, fin) | Summarizer (fin) | DOC-002 (finance) | ALLOWED | fin ∩ fin = fin |
| Alice (eng, fin) | Summarizer (fin) | DOC-001 (engineering) | DENIED | fin ∩ eng = ∅ |
| Alice (eng, fin) | Reviewer (all) | DOC-001 (engineering) | ALLOWED | eng ∩ eng = eng |
| Carol (hr) | Reviewer (all) | DOC-001 (engineering) | DENIED | hr ∩ eng = ∅ |
| Bob (fin, admin) | Summarizer (fin) | DOC-006 (admin + fin) | ALLOWED | fin ∩ (admin + fin) = fin |

## Files changed

### New files

```text
pkg/llm/
├── provider.go                  # Provider interface definition
├── config.go                    # Configuration with provider defaults
├── anthropic.go                 # Anthropic Claude implementation
├── openai_compat.go             # OpenAI-compatible implementation
├── factory.go                   # NewProvider() factory function
└── prompts.go                   # System prompts for agents

summarizer-service/
├── main.go
├── cmd/
│   ├── root.go
│   └── serve.go                 # /summarize endpoint
└── Dockerfile

reviewer-service/
├── main.go
├── cmd/
│   ├── root.go
│   └── serve.go                 # /review endpoint
└── Dockerfile
```

### Modified files

```text
pkg/config/config.go            # Port defaults for new services
pkg/logger/logger.go            # ComponentSummarizer, ComponentReviewer

agent-service/internal/store/agents.go
                                # Added reviewer agent

opa-service/policies/agent_permissions.rego
                                # Added reviewer capabilities

web-dashboard/cmd/serve.go      # Service URLs, /api/summarize, /api/review
web-dashboard/internal/assets/templates/index.html
                                # Summarize/Review buttons
web-dashboard/internal/assets/static/js/app.js
                                # Button handlers, markdown rendering

Makefile                        # New services, podman targets, OpenShift deploy
scripts/run-local.sh            # Start new services

deploy/k8s/base/opa-policies-configmap.yaml
                                # Added reviewer agent capabilities
```

### New Kubernetes overlays

```text
deploy/k8s/overlays/
├── ai-agents/
│   ├── kustomization.yaml      # Base AI agent overlay
│   ├── deployments.yaml        # summarizer-service, reviewer-service
│   ├── services.yaml           # ClusterIP services
│   ├── llm-configmap.yaml      # Default LLM config (mock mode)
│   └── llm-secret.yaml.template # API key template
├── local-ai-agents/
│   └── kustomization.yaml      # Extends local + ai-agents
└── openshift-ai-agents/
    ├── kustomization.yaml      # Extends openshift-oidc + ai-agents
    └── llm-secret.yaml.template # API key template
```

## Running locally

### With Anthropic (default provider)

```bash
export LLM_API_KEY=your-anthropic-key
# or: export ANTHROPIC_API_KEY=your-anthropic-key

make run-local
open http://localhost:8080
```

### With LiteLLM (Red Hat MaaS)

```bash
export LLM_PROVIDER=litellm
export LLM_BASE_URL=https://litellm-prod.apps.maas.redhatworkshops.io/v1
export LLM_API_KEY=your-litellm-key
export LLM_MODEL=qwen3-14b  # optional, this is the default

make run-local
open http://localhost:8080
```

### With OpenAI

```bash
export LLM_PROVIDER=openai
export LLM_API_KEY=your-openai-key
export LLM_MODEL=gpt-4o  # optional, this is the default

make run-local
open http://localhost:8080
```

### Mock mode (no LLM)

Without an API key, the services run in mock mode and return placeholder responses.

```bash
make run-local
open http://localhost:8080
```

## Testing

### Manual testing via curl

```bash
# Test summarizer (should be allowed - alice has finance)
curl -X POST http://localhost:8086/summarize \
  -H "Content-Type: application/json" \
  -d '{
    "document_id": "DOC-002",
    "user_spiffe_id": "spiffe://demo.example.com/user/alice",
    "user_departments": ["engineering", "finance"]
  }'

# Test summarizer (should be denied - summarizer lacks engineering)
curl -X POST http://localhost:8086/summarize \
  -H "Content-Type: application/json" \
  -d '{
    "document_id": "DOC-001",
    "user_spiffe_id": "spiffe://demo.example.com/user/alice",
    "user_departments": ["engineering", "finance"]
  }'

# Test reviewer (should be allowed - reviewer has all departments)
curl -X POST http://localhost:8087/review \
  -H "Content-Type: application/json" \
  -d '{
    "document_id": "DOC-001",
    "user_spiffe_id": "spiffe://demo.example.com/user/alice",
    "user_departments": ["engineering"],
    "review_type": "compliance"
  }'
```

### Dashboard testing

1. Open http://localhost:8080
1. Select a user (e.g., Alice)
1. Select a document (e.g., DOC-002 - Q4 Financial Report)
1. Click "Summarize" - should show summary (alice + summarizer both have finance)
1. Select DOC-001 (Engineering Roadmap)
1. Click "Summarize" - should show access denied (summarizer lacks engineering)
1. Click "Review" - should show review (reviewer has all departments)

## Deployment options

### Local development (no OIDC)

By default, the dashboard runs without OIDC and shows a user dropdown for selecting demo users:

```bash
make run-local
```

This is ideal for quick iteration and testing permission intersection logic.

### Local development with OIDC

To test the full authentication flow locally, run Keycloak and enable OIDC:

```bash
# Start Keycloak (see Phase 4 docs)
# Then run dashboard with OIDC enabled
./bin/web-dashboard serve \
  --oidc-enabled \
  --oidc-issuer-url "http://localhost:8180/realms/spiffe-demo" \
  --oidc-client-id "spiffe-demo-dashboard" \
  --oidc-redirect-url "http://localhost:8080/auth/callback"
```

### Hybrid deployment (Kind + OpenShift Keycloak)

For a production-like setup, run the demo services in Kind while authenticating against
a Keycloak instance on OpenShift. This provides:

- **Local iteration speed** - Fast rebuilds and testing in Kind
- **Real identity provider** - Production-like OAuth2/OIDC flow
- **Consistent user/group data** - Same Keycloak realm across environments

Configuration via CLI flags:

```bash
./bin/web-dashboard serve \
  --oidc-enabled \
  --oidc-issuer-url "https://keycloak.apps.your-cluster.example.com/realms/spiffe-demo" \
  --oidc-client-id "spiffe-demo-dashboard" \
  --oidc-redirect-url "http://localhost:8080/auth/callback"
```

Or via environment variables in Kind deployment manifests:

```yaml
env:
  - name: SPIFFE_DEMO_OIDC_ENABLED
    value: "true"
  - name: SPIFFE_DEMO_OIDC_ISSUER_URL
    value: "https://keycloak.apps.your-cluster.example.com/realms/spiffe-demo"
  - name: SPIFFE_DEMO_OIDC_CLIENT_ID
    value: "spiffe-demo-dashboard"
  - name: SPIFFE_DEMO_OIDC_REDIRECT_URL
    value: "http://localhost:8080/auth/callback"
```

**Important**: Ensure the Keycloak client configuration includes `http://localhost:8080/*`
in its valid redirect URIs when testing this hybrid setup.

### Full Kubernetes/OpenShift deployment

For production or demo environments, deploy all services to the cluster.

#### Kubernetes overlay structure

AI agent services are optional and deployed via separate overlays:

```text
deploy/k8s/overlays/
├── ai-agents/              # Base AI agent resources (deployments, services, config)
├── local-ai-agents/        # Extends local + ai-agents with mock SPIFFE
├── openshift-ai-agents/    # Extends openshift-oidc + ai-agents with LiteLLM
└── ...
```

| Overlay | Base | AI Agents | LLM Provider | Use case |
| ------- | ---- | --------- | ------------ | -------- |
| `local` | base | No | - | Local development without AI |
| `local-ai-agents` | local + ai-agents | Yes | Anthropic (env) | Local development with AI |
| `openshift-oidc` | openshift | No | - | OpenShift with Keycloak |
| `openshift-ai-agents` | openshift-oidc + ai-agents | Yes | LiteLLM | Full OpenShift demo |

#### Kind cluster

```bash
./scripts/deploy-app.sh
```

#### OpenShift (without AI agents)

```bash
oc apply -k deploy/k8s/overlays/openshift-oidc
```

#### OpenShift (with AI agents)

```bash
# Generate OIDC config files
CLUSTER_DOMAIN=$(oc get ingresses.config/cluster -o jsonpath='{.spec.domain}')
cd deploy/k8s/overlays/openshift-oidc
sed "s/CLUSTER_DOMAIN/$CLUSTER_DOMAIN/g" oidc-urls-configmap.yaml.template > oidc-urls-configmap.yaml
sed "s/CLUSTER_DOMAIN/$CLUSTER_DOMAIN/g" keycloak-realm-patch.yaml.template > keycloak-realm-patch.yaml
cd -

# Create LLM secret
cp deploy/k8s/overlays/openshift-ai-agents/llm-secret.yaml.template \
   deploy/k8s/overlays/openshift-ai-agents/llm-secret.yaml
# Edit with your API key

# Deploy
oc apply -f deploy/k8s/overlays/openshift-ai-agents/llm-secret.yaml -n spiffe-demo
oc apply -k deploy/k8s/overlays/openshift-ai-agents
```

#### Development workflow with git SHA tags

For iterative development on OpenShift:

```bash
# Build, push, and deploy with git SHA tag
make deploy-openshift

# Quick deploy (no rebuild)
make deploy-openshift-quick

# Restart deployments
make restart-openshift

# Clean up old images
make ghcr-cleanup
```

See [OpenShift deployment guide](../deployment/openshift.md) for full details.

## Future enhancements

### Configuration-driven agents

The current implementation hardcodes agent definitions. Future phases could:

1. Load agents from YAML configuration
1. Generate OPA policies from configuration
1. Support hot-reload of agent definitions
1. Single generic `ai-agent-service` with dynamic routing

### Additional review types

- Security review
- Legal compliance review
- Technical debt analysis
- Code review (for code documents)

### Streaming responses

For long documents, stream the LLM response back to the dashboard using SSE.

## Zero Trust principles demonstrated

1. **Permission Intersection**: Agents cannot exceed user permissions
1. **Delegation Required**: Agents cannot act without user context
1. **Least Privilege**: Summarizer limited to finance documents only
1. **Audit Trail**: All access attempts logged with delegation context
1. **Policy Enforcement**: OPA evaluates every request consistently
