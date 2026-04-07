# zt-agent: unified agent runtime (phase 1)

**Date:** 2026-04-06
**Status:** Draft
**Author:** Pavel Anni

## Goal

Replace all five agent deployments (summarizer-hr, summarizer-tech,
reviewer-ops, reviewer-general, summarizer-tech-klaviger) with a
single Go binary (`zt-agent`) whose personality and agent card are
loaded from a ConfigMap-mounted directory at startup.

## Background

The project currently has two Go agents (`summarizer-service`,
`reviewer-service`) and two Python agents (`kagenti-summarizer`,
`kagenti-reviewer`) deployed as five agent instances via Kagenti.
The Go agents' `serve.go` files are nearly identical — same HTTP
server scaffolding, same health server, same config loading, same
`fetchDocument` function. The only differences are the system
prompt and the `ProcessLLM` callback.

The Python agents are simpler (A2A-only, no delegation transport)
but functionally equivalent: fetch a document, call an LLM with a
system prompt, return the result.

## Approach

**Approach B (chosen):** Create a new `zt-agent/` directory with a
clean implementation. Old agents stay untouched as fallback. Remove
them once `zt-agent` is validated on the cluster.

Alternatives considered:

- **A (shared package):** Extract scaffolding into `pkg/agentserver`,
  keep separate binaries. Too many moving parts, doesn't achieve
  one-image goal directly.
- **C (rename in place):** Rename `summarizer-service/` to
  `zt-agent/`, delete `reviewer-service/`. Breaks existing
  deployments immediately, no fallback.

## Architecture

### Directory structure

```text
zt-agent/
├── main.go              # Entry point
├── cmd/
│   ├── root.go          # Cobra root command, Viper init
│   └── serve.go         # Service logic
└── Dockerfile           # Multi-stage Alpine build
```

Reuses existing shared packages unchanged:

- `pkg/a2abridge/` — `AgentExecutor`, `DelegationTransport`,
  `BuildAgentCard`, `SignedCardHandler`
- `pkg/llm/` — `Provider` interface, `NewProvider()` factory
- `pkg/config/` — `CommonConfig`, `InitViper`, `Load`
- `pkg/logger/` — structured logging
- `pkg/metrics/` — Prometheus counters

### Config directory

The agent reads its personality from a directory specified by
`--config-dir` (default: `/config/agent`):

```text
/config/agent/
├── system-prompt.txt     # Required: system prompt for LLM
├── agent-card.json       # Required: A2A agent card
├── prompts.json          # Optional: prompt variants by keyword
└── skills/               # Reserved for phase 2 (ignored)
```

**`system-prompt.txt`** — plain text, becomes the system prompt
passed to `llm.Provider.Complete()`. If missing, the agent refuses
to start.

**`agent-card.json`** — JSON, parsed into `a2a.AgentCard` and
served at `GET /.well-known/agent-card.json`. If a signed card
exists at `AGENT_CARD_SIGNED_PATH` (set by Kagenti), it takes
precedence. If `agent-card.json` is missing, the agent starts with
a minimal fallback card (for local dev convenience).

**`prompts.json`** — optional JSON map of `type -> prompt string`.
When present, the agent extracts a keyword from the incoming
message to select a prompt variant, falling back to
`system-prompt.txt`. This covers the reviewer's
general/compliance/security modes.

### Configuration

The `Config` struct extends `CommonConfig`:

```go
type Config struct {
    config.CommonConfig `mapstructure:",squash"`
    DocumentServiceURL  string     `mapstructure:"document_service_url"`
    LLM                 llm.Config `mapstructure:"llm"`
    ConfigDir           string     `mapstructure:"config_dir"`
}
```

LLM access is configured the same way as existing agents:

| Source | Variables |
| ------ | --------- |
| CLI flags | `--llm-provider`, `--llm-api-key`, `--llm-base-url`, `--llm-model` |
| Env vars | `LLM_PROVIDER`, `LLM_API_KEY` (or `ANTHROPIC_API_KEY`), `LLM_BASE_URL`, `LLM_MODEL` |
| Config file | `llm.provider`, `llm.api_key`, `llm.base_url`, `llm.model` |

On the cluster, the API key comes from a Kubernetes Secret mounted
as an env var. The agent personality (prompts, agent card) comes
from a ConfigMap.

### HTTP endpoints

| Endpoint | Method | Server | Description |
| -------- | ------ | ------ | ----------- |
| `/.well-known/agent-card.json` | GET | Main | Agent card (signed if available) |
| `/a2a` | POST | Main | A2A JSON-RPC 2.0 |
| `/` | POST | Main | A2A JSON-RPC (Kagenti root path) |
| `/health` | GET | Main | Health check |
| `/health` | GET | Health | Health check (plain HTTP) |
| `/ready` | GET | Health | Readiness probe |
| `/metrics` | GET | Health | Prometheus metrics |

Main server listens on port 8000 (Kagenti convention for AI agents).
Health server on port 8100 (plain HTTP for K8s probes).

### Request handling

Reuses `pkg/a2abridge.AgentExecutor` unchanged:

```go
executor := &a2abridge.AgentExecutor{
    Log:           log,
    FetchDocument: fetchDocument,  // same as existing agents
    ProcessLLM:    processLLM,     // uses loaded prompt
}
```

The `processLLM` callback:

1. If `prompts.json` was loaded and the A2A message text contains a
   matching keyword (case-insensitive scan), uses the variant prompt
2. Otherwise uses the content of `system-prompt.txt`
3. Calls `llm.Provider.Complete(ctx, systemPrompt, userPrompt)`

**Note on prompt variant triggering:** The web dashboard currently
sends only a document ID with no user message, so keyword matching
never triggers there — the default prompt is always used. This is
acceptable: summarizers don't need variants, and reviewers default
to "general" review (matching current behavior). Prompt variants
can be triggered via Kagenti's Chat tab, which supports free-text
messages. Adding a text input to the dashboard is a separate
follow-up enhancement.

The `fetchDocument` callback is identical to the existing agents:
HTTP GET to document-service with `DelegationTransport` injecting
`X-Delegation-*` headers automatically.

## Kubernetes deployment

### ConfigMap (one per agent)

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: summarizer-hr-config
data:
  system-prompt.txt: |
    You are a document summarizer agent specialized in
    analyzing and summarizing documents.
    ...
  agent-card.json: |
    {
      "name": "summarizer-hr",
      "description": "HR document summarizer",
      "version": "1.0.0",
      "protocolVersion": "0.3.0",
      "skills": [{
        "id": "document-summarization",
        "name": "Document Summarization",
        "description": "Summarizes documents with AI",
        "tags": ["hr"]
      }],
      "capabilities": {},
      "defaultInputModes": ["application/json"],
      "defaultOutputModes": ["text/plain"]
    }
```

### Deployment (same image, different ConfigMap)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: summarizer-hr
spec:
  template:
    spec:
      containers:
      - name: zt-agent
        image: ghcr.io/redhat-et/zero-trust-agent-demo/zt-agent:dev
        args: ["serve", "--config-dir", "/config/agent"]
        env:
        - name: LLM_API_KEY
          valueFrom:
            secretKeyRef:
              name: llm-credentials
              key: api-key
        volumeMounts:
        - name: agent-config
          mountPath: /config/agent
          readOnly: true
      volumes:
      - name: agent-config
        configMap:
          name: summarizer-hr-config
```

### Reviewer with prompt variants

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: reviewer-ops-config
data:
  system-prompt.txt: |
    You are a document reviewer agent specialized in
    analyzing documents for compliance, security, and
    general quality.
    ...
  prompts.json: |
    {
      "compliance": "You are a compliance review agent...",
      "security": "You are a security review agent..."
    }
  agent-card.json: |
    {
      "name": "reviewer-ops",
      "description": "Operations document reviewer",
      ...
    }
```

Five ConfigMaps, five Deployments, one image. OPA policies must
include the deployment name as a key in `agent_capabilities` (e.g.,
`"zt-agent-summarizer-hr": ["hr", "engineering"]`). The deployment
name is the agent ID used everywhere — OPA, SPIFFE, dashboard.

## Migration path

The agent-service gateway discovers agents via AgentCard CRs and
proxies A2A requests. It doesn't care what's behind the endpoint.

1. Build and push the `zt-agent` image
2. Create ConfigMaps for all five agents
3. Deploy `zt-agent` Deployments alongside existing agents
4. Create AgentCard CRs pointing to the new Deployments
5. Test with existing demo scenarios (Alice -> summarizer-tech ->
   DOC-001, etc.)
6. Once validated, remove old agent Deployments and AgentCard CRs
7. Remove old agent directories from the repo (separate cleanup PR)

No downtime required. Old and new agents coexist during migration.

## Out of scope (phase 1)

- Agentic tool-use loop (phase 2)
- SKILL.md loading from `skills/` subdirectory (phase 2)
- ClawHub skill integration (phase 3)
- Changes to shared packages (`pkg/llm`, `pkg/a2abridge`, etc.)
- Removal of old agent directories
- Makefile/CI changes beyond adding `zt-agent` build targets
- New Go dependencies

## Success criteria

1. `zt-agent serve --config-dir ./testdata/summarizer-hr` runs
   locally and responds to A2A requests with summarization
2. The same binary with `--config-dir ./testdata/reviewer-ops`
   acts as a reviewer with prompt variant support
3. All five existing demo scenarios pass with `zt-agent` Deployments
   on the cluster
4. Image size is comparable to current Go agent images (~15-20MB)
