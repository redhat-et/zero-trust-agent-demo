# Agent gateway with dynamic AgentCard discovery

## Problem

The agent-service uses hardcoded fake agents (gpt4, claude, summarizer,
reviewer) and the dashboard talks directly to summarizer/reviewer
services via separate URL flags. With real agents deployed under the
Kagenti operator (which creates `AgentCard` CRs automatically), we
need to:

1. Discover agents dynamically from AgentCard CRs
2. Route all agent invocations through agent-service (gateway pattern)
3. Remove hardcoded agents and direct service URL flags

## Design decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Discovery source | AgentCard CRs via K8s API | Kagenti-native; provides signed card, SPIFFE binding, URL |
| Invocation routing | All through agent-service | Zero-trust: delegation context, SPIFFE identity, OPA checks in one place |
| Agent capabilities display | Name + description only | OPA is the authority for permissions; AgentCard describes what an agent *can do*, not what it's *allowed to do* |
| Document format for A2A agents | Agent-service constructs `s3_url` message | Dashboard sends `document_id`; gateway resolves format |
| Deny reason in API response | Not exposed | Security: deny reasons leak policy structure; audit trail in logs only |

## Architecture

### Before

```text
Dashboard ──→ agent-service (hardcoded agents, access checks)
Dashboard ──→ summarizer-service (direct, separate URL flag)
Dashboard ──→ reviewer-service (direct, separate URL flag)
```

### After

```text
Dashboard ──→ agent-service ──→ AgentCard CRs (discovery)
                  │
                  ├──→ document-service (metadata + OPA authz)
                  │
                  └──→ A2A agent (invoke via URL from AgentCard)
```

The dashboard only needs one backend URL for all agent operations.

## Component changes

### 1. Agent discovery — AgentCard CR watcher

**File:** `pkg/a2abridge/discovery.go` (replace existing)

Replace the Deployment-label polling with AgentCard CR list/watch:

- Use `k8s.io/client-go` dynamic client to list/watch
  `agent.kagenti.dev/v1alpha1/AgentCard` resources in the configured
  namespace
- For each AgentCard, extract from `status.card`:
  - `name` — agent display name
  - `description` — agent description
  - `url` — in-cluster A2A endpoint
  - `version` — agent version
- Extract from `status.bindingStatus`:
  - `bound` — whether SPIFFE identity is bound
  - SPIFFE ID (from `message` field)
- Register agents in the store with `source: "discovered"`
- On AgentCard deletion, remove agent from store
- Fallback: if watch is unavailable (e.g., local dev without K8s),
  support periodic list polling (existing `--discovery-interval`)

**RBAC requirement:** The agent-service service account must have
permission to list AgentCard CRs. Apply this Role and RoleBinding
in the target namespace:

```bash
oc apply -n spiffe-demo -f - <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: agentcard-reader
rules:
- apiGroups: ["agent.kagenti.dev"]
  resources: ["agentcards"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: agent-service-agentcard-reader
subjects:
- kind: ServiceAccount
  name: agent-service
roleRef:
  kind: Role
  name: agentcard-reader
  apiGroup: rbac.authorization.k8s.io
EOF
```

**Configuration flags** (replace existing discovery flags):

| Flag | Default | Description |
|------|---------|-------------|
| `--enable-discovery` | `false` | Enable AgentCard discovery |
| `--discovery-namespace` | `spiffe-demo` | Namespace to watch |
| `--discovery-interval` | `30s` | Poll interval (fallback) |

### 2. Agent store — remove hardcoded agents

**File:** `agent-service/internal/store/agents.go`

- Remove `loadSampleAgents()` and the four hardcoded agents
- Keep the `Agent` struct but remove `Capabilities` field (OPA
  handles this now)
- Keep `Register()`, `Remove()`, `Get()`, `List()` methods
- The store starts empty; agents are populated by discovery

Updated `Agent` struct:

```go
type Agent struct {
    ID          string          `json:"id"`
    Name        string          `json:"name"`
    Description string          `json:"description"`
    SPIFFEID    string          `json:"spiffe_id,omitempty"`
    Source      AgentSource     `json:"source"`
    A2AURL      string          `json:"a2a_url,omitempty"`
    Version     string          `json:"version,omitempty"`
    AgentCard   *a2a.AgentCard  `json:"-"`
}
```

### 3. Agent-service gateway — unified invoke endpoint

**File:** `agent-service/cmd/serve.go`

The existing `/agents/{id}/invoke` endpoint becomes the single entry
point for all agent operations. Flow:

```text
POST /agents/{id}/invoke
{
  "document_id": "DOC-002",
  "user_spiffe_id": "spiffe://...user/alice",
  "action": "summarize" | "review",
  "review_type": "general" | "compliance" | "security"
}
```

The `action` field is passed through to the A2A message text. The
agent-service does not validate whether an action matches the target
agent — the agent itself decides how to handle the message. This
keeps the gateway generic: any A2A agent can be invoked with any
action string.

Handler steps:

1. Look up agent from store (404 if not found)
2. Validate `user_spiffe_id` is present (deny autonomous access)
3. Call document-service `/access` with delegation context (existing
   `accessDocumentDelegated` flow)
4. If denied, return 403 with generic "Access denied"
5. If allowed, get document metadata (including `s3_url`) from the
   response
6. Construct A2A message: `"{action} {s3_url}"` (e.g.,
   `"Summarize s3://zt-demo-documents/finance/q4-report.md"`)
7. Invoke agent via A2A using `a2abridge.InvokeA2A()` with the
   agent's URL from the discovered card
8. Return result to caller

**Endpoints summary:**

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Health check |
| `/agents` | GET | List discovered agents |
| `/agents/{id}` | GET | Get agent details |
| `/agents/{id}/access` | POST | Check delegated access (keep for backward compat) |
| `/agents/{id}/invoke` | POST | Invoke agent via A2A (primary path) |

### 4. Dashboard changes

**File:** `web-dashboard/cmd/serve.go`

Remove:
- `--summarizer-service-url` flag
- `--reviewer-service-url` flag
- `handleSummarize()` handler (direct summarizer call)
- `handleReview()` handler (direct reviewer call)

Add/modify:
- `/api/invoke` → proxies to agent-service `/agents/{id}/invoke`
- Agent dropdown: show `{name} — {description}` from agent list
- Keep document dropdown as-is (document-service already returns
  `s3_url` in metadata)

**File:** `web-dashboard/internal/assets/static/js/app.js`

- Summarize button → POST `/api/invoke` with
  `{agent_id, document_id, action: "summarize"}`
- Review button → POST `/api/invoke` with
  `{agent_id, document_id, action: "review", review_type}`
- Update `populateSelect()` for agents: show name and description
  instead of name and capabilities

**File:** `web-dashboard/internal/assets/templates/index.html`

- Update agent dropdown helper text
- Remove capability badges from agent options (if any)

### 5. What stays the same

- OPA policies — no changes
- Document-service — already has `s3_url`, no changes
- Credential gateway — no changes
- SSE event stream — no changes
- Direct access flow (user → document without agent)
- Delegated access flow logic (permission intersection model)
- Permission Matrix display

### 6. What gets removed

| Item | Location |
|------|----------|
| Hardcoded agents (gpt4, claude, summarizer, reviewer) | `agent-service/internal/store/agents.go` |
| Deployment-label discovery | `pkg/a2abridge/discovery.go` |
| `--summarizer-service-url` flag | `web-dashboard/cmd/serve.go` |
| `--reviewer-service-url` flag | `web-dashboard/cmd/serve.go` |
| `handleSummarize()` | `web-dashboard/cmd/serve.go` |
| `handleReview()` | `web-dashboard/cmd/serve.go` |
| `/api/summarize` route | `web-dashboard/cmd/serve.go` |
| `/api/review` route | `web-dashboard/cmd/serve.go` |
| Direct health checks for summarizer/reviewer | `web-dashboard/cmd/serve.go` (`handleStatus`) |

## Local development

Without a K8s cluster, agents can still be registered manually via
the existing `Register()` method. Add a `--static-agents` flag that
loads agents from a JSON file for local testing:

```bash
./bin/agent-service serve --static-agents agents.json
```

This replaces the hardcoded agents with a configurable file that
mirrors the AgentCard CR structure.

## Verified test results (2026-03-24, spiffe-demo namespace)

**Agent-service deployed:** image `:4f5cfa6` on OpenShift.

| Test | Result | Notes |
|------|--------|-------|
| AgentCard CR discovery | Pass | 3 agents found: kagenti-summarizer, reviewer-service, summarizer-service |
| RBAC for agentcards | Pass | Required Role `agentcard-reader` with get/list/watch |
| `/agents` endpoint | Pass | Returns all 3 discovered agents with metadata |
| `/agents/{id}/invoke` routing | Pass | Correctly routes through document-service to OPA |
| OPA policy evaluation | Pass | Denies mismatched trust domain (expected) |
| Kubeconfig fallback (local dev) | Pass | Discovers agents from workstation via `~/.kube/config` |

Full E2E invoke (authorization + A2A forwarding) requires dashboard
with OIDC — the JWT `user_departments` claim bypasses SPIFFE-based
user lookup in OPA.

## Roadmap (out of scope)

- Expose deny reasons in API response (security trade-off: leaks
  policy structure; keep in audit logs only)
- Pass department information from OPA to dashboard for richer UI
  (Permission Matrix already covers this)
- Kustomize overlay for kagenti-s3-agents (Task 12 from previous
  branch)
- AuthBridge outbound route config (blocked on Kagenti team)
