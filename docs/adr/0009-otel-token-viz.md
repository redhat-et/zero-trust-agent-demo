# ADR-0009: OpenTelemetry instrumentation and token exchange visibility

## Status

Accepted (Subphases A-D implemented)

## Date

2026-02-10

## Context

Phase 8 added the AuthBridge overlay, which performs RFC 8693 token
exchange via an Envoy ext\_proc sidecar. The flow works end-to-end:
a SPIFFE JWT SVID is exchanged for a Keycloak access token, scoped
to the correct audience, before reaching the document-service.

The problem is that **none of this is visible**. The web dashboard
looks identical before and after AuthBridge is deployed. For demos to
Red Hat coworkers and customers, we need to show:

1. That token exchange is happening
1. What tokens are involved (audiences, subjects, grants)
1. How the permission intersection works across identity boundaries
1. That this architecture is production-grade, not a toy

This is important because the demo should not only show "what we can
do" but, more importantly, show customers "how this SHOULD be done."
Eventually this demo should become either a Reference Architecture or
part of Red Hat's product line.

### Current observability

The project already has:

- **Prometheus metrics** (`pkg/metrics/`) — request counts, latencies,
  authorization decisions, delegation attempts, SVID rotation
- **Structured logging** (`pkg/logger/`) — color-coded component logs
  with flow indicators (`log.Flow`, `log.Allow`, `log.Deny`)
- **Health endpoints** on separate ports (ADR-0005)

What is missing is **distributed tracing** — the ability to follow a
single request across all services and see the token exchange happen
in context.

## Decision

We will add **OpenTelemetry distributed tracing** to all Go services
and the AuthBridge ext-proc, with **Jaeger** as the trace visualization
backend. The original plan included a bubbletea TUI (Subphase D), but
this was replaced with **Bearer token propagation** to enable the
ext-proc to perform token exchange on the delegation path.

### Why OpenTelemetry

- Industry-standard, vendor-neutral observability framework
- Native integration with Jaeger, Grafana Tempo, and other backends
- Go SDK provides HTTP middleware and outbound client instrumentation
- Trace context propagation via W3C `traceparent` header works through
  Envoy without extra configuration
- Positions this demo as a reference architecture, not a one-off hack

### Why Jaeger (not a TUI)

The original plan called for a bubbletea-based TUI binary. During
implementation, Jaeger proved sufficient for trace visualization:

- Jaeger is already deployed as part of the OTel Collector pipeline
- It provides trace search, filtering, and detail views out of the box
- No custom binary to build, test, and maintain
- Familiar to operators who use it in production
- Subphase D effort was better spent on Bearer token propagation,
  which was required for the ext-proc token exchange spans to fire

## Architecture overview

```text
┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│ user-svc │   │agent-svc │   │ doc-svc  │   │ opa-svc  │
│  :8082   │   │  :8083   │   │  :8084   │   │  :8085   │
└────┬─────┘   └──┬───┬───┘   └────┬─────┘   └────┬─────┘
     │            │   │            │              │
     │     ┌──────┘   │            │              │
     │     │ ext-proc │            │              │
     │     │(sidecar) │            │              │
     │     └──────┬───┘            │              │
     │  OTLP/gRPC │                │              │
     └───────┬────┴────────┬───────┴──────┬───────┘
             ▼             ▼              ▼
       ┌─────────────────────────────────────┐
       │       OpenTelemetry Collector       │
       │         (otel-collector)            │
       └──────┬──────────────────────┬───────┘
              │                      │
              ▼                      ▼
         ┌────────┐            ┌────────┐
         │ Jaeger │            │ Tempo  │
         │  (dev) │            │ (prod) │
         └────────┘            └────────┘
```

### Trace structure

A single delegated access request produces one trace with spans across
services. Token exchange happens **only** on the agent-service's
outbound path (agent-service → document-service), via the Envoy
sidecar on agent-service:

```text
[web-dashboard] POST /api/access-delegated
  └─ [user-service] POST /delegate
       ├─ [user-service] user.delegate
       └─ [user-service] → agent-service POST /agents/gpt4/access
            ├─ [agent-service] agent.delegated_access
            └─ [agent-service] → document-service POST /access
                 ├─ [authbridge-ext-proc] ext_proc.outbound
                 │     span attrs: authbridge.action (token_exchanged)
                 │     └─ [authbridge-ext-proc] token_exchange
                 │           span attrs: token.subject, token.aud.before,
                 │             token.aud.after, exchange.grant_type
                 ├─ [document-service] doc.access
                 │     ├─ [document-service] jwt_validation
                 │     │     span attrs: jwt.issuer, jwt.azp, jwt.groups
                 │     └─ [document-service] → opa-service POST /v1/data/...
                 │          └─ [opa-service] policy.evaluate
                 │                span attrs: decision, reason, caller_type
                 └─ response
```

Key architectural decision: the Envoy sidecar with ext-proc is
deployed **only on agent-service**, not on user-service. The
user-service communicates with agent-service via mTLS and passes the
Bearer token in the HTTP header. The Envoy sidecar on agent-service
intercepts the outbound request to document-service and exchanges the
user's OIDC token for a document-service-scoped token. See the
"Single-sidecar vs dual-sidecar" section below for rationale.

### Custom span attributes

Security-relevant moments get dedicated span events and attributes
rather than just generic HTTP spans:

| Span | Key attributes |
| ---- | -------------- |
| `token_exchange` | `token.subject`, `token.aud.before`, `token.aud.after`, `exchange.grant_type` |
| `jwt_validation` | `jwt.issuer`, `jwt.azp`, `jwt.groups`, `jwt.exp` |
| `policy_evaluation` | `opa.decision`, `opa.reason`, `opa.caller_type`, `opa.effective_departments` |
| `permission_intersection` | `user.departments`, `agent.capabilities`, `effective.departments` |

### Bearer token propagation (replaces TUI)

Instead of building a TUI, Subphase D implements Bearer token
propagation so that the ext-proc can perform RFC 8693 token exchange.
Without this, the ext-proc always saw `passthrough_no_token` because
no service forwarded the OIDC access token.

**Token flow on the delegation path:**

```text
Browser (Keycloak OIDC token in session)
  → web-dashboard (extracts token, sets Authorization header)
    → user-service (passes token through to agent-service)
      → agent-service (passes token through)
        → [Envoy sidecar intercepts outbound request]
          → ext-proc exchanges token (RFC 8693)
            → document-service (receives exchanged token, validates JWT)
```

**Changes:**

1. `pkg/auth/session.go` — store `AccessToken` in session
1. `web-dashboard/cmd/serve.go` — save token at OIDC callback,
   add `getAccessToken()` helper, convert 5 POST calls to set
   `Authorization: Bearer` header
1. `user-service/cmd/serve.go` — extract and forward Bearer token
   on the delegation path (not on direct access)
1. `agent-service/cmd/serve.go` — extract and forward Bearer token
   on delegated document access

**Mock mode:** when OIDC is disabled, no token is present. Services
skip forwarding. The ext-proc logs `passthrough_no_token` as before.

## Scope of changes

### This repository (zero-trust-agent-demo)

1. **`pkg/telemetry/`** — shared OTel initialization package
   - Tracer provider setup with OTLP exporter
   - Common span attribute helpers for security events
   - HTTP middleware for inbound request tracing
   - HTTP client transport wrapper for outbound tracing
   - W3C trace context propagation

1. **Service instrumentation** (all four services)
   - Import `pkg/telemetry/` and initialize tracer on startup
   - Wrap HTTP handlers with tracing middleware
   - Wrap outbound HTTP clients with tracing transport
   - Add custom spans at security decision points:
     - user-service: delegation validation
     - agent-service: delegation context, access forwarding
     - document-service: JWT validation, OPA query
     - opa-service: policy evaluation, permission intersection

1. **Bearer token propagation** (Subphase D, replaces TUI)
   - `pkg/auth/session.go` — `AccessToken` field in session
   - `web-dashboard/cmd/serve.go` — store token, propagate on
     outbound requests
   - `user-service/cmd/serve.go` — forward token on delegation path
   - `agent-service/cmd/serve.go` — forward token on document access

1. **`deploy/k8s/`** — OTel Collector deployment
   - Collector ConfigMap (receivers, processors, exporters)
   - Collector Deployment and Service
   - Jaeger Deployment and Service
   - Overlay patches for OpenShift

### kagenti-extensions (separate repository)

1. **`AuthBridge/AuthProxy/go-processor/`** — ext-proc service
   - Add OTel span around token exchange call
   - Emit span attributes: `token.subject`, `token.aud.before`,
     `token.aud.after`, `exchange.grant_type`
   - Accept incoming trace context from Envoy headers
   - This is positioned as "proper instrumentation" valuable to all
     kagenti users, not demo-specific

1. Changes will be developed in a fork first, then proposed as a PR
   to the kagenti-extensions repository

## Bring your own agent

A key goal of this architecture is to let customers **plug in their own
AI agents** without modifying the infrastructure services. The pitch is:
"Here is the secure infrastructure to run your agents. Bring your own
agents, add them with minimal configuration, and you get controlled
access, policy enforcement, and full observability for free."

### How the architecture enables this

The agent-service is an **authorization harness and metadata registry**,
not a proxy. It stores agent capabilities and SPIFFE IDs, and enforces
the permission intersection during delegation. The actual AI agents
(like the existing summarizer and reviewer services) are independent
microservices that:

1. Receive delegation context from the dashboard or user-service
1. Call document-service directly with that delegation context
1. Get transparent token exchange via the AuthBridge sidecar
1. Get traced automatically via OTel instrumentation

This means a customer-provided agent only needs to:

1. **Run as a pod** in the namespace
1. **Receive the AuthBridge sidecar** (injected via Kustomize overlay
   or, eventually, a mutating webhook)
1. **Be registered** in agent-service with its capabilities and
   SPIFFE ID (or OIDC client identity)
1. **Call document-service** with the standard delegation JSON
   (`user_spiffe_id` + `agent_spiffe_id` + `document_id`)

The agent does not need to know about SPIFFE, token exchange, or OPA.
All of that happens transparently in the infrastructure layer.

### What OTel adds for third-party agents

With the instrumentation from this ADR, a customer's agent
automatically gets:

- **Trace context propagation** — the W3C `traceparent` header flows
  through the AuthBridge sidecar, so the agent's requests appear in
  the same trace as the rest of the chain
- **Token exchange visibility** — the ext-proc span shows the token
  swap even though the agent's code never touches tokens
- **Policy decision audit** — the OPA span records what was allowed
  or denied and why
- **TUI rendering** — the agent appears in the sequence diagram
  alongside the infrastructure services

If the agent itself is instrumented with OTel (any language — Go,
Python, Java), its internal spans merge into the same trace, giving
end-to-end visibility from user delegation through agent processing
to document access.

### Integration path

| Step | What | Who |
| ---- | ---- | --- |
| Register agent metadata | Add ID, capabilities, SPIFFE ID to agent-service | Platform admin |
| Deploy agent pod | Standard Deployment with AuthBridge overlay | Platform admin |
| Configure OPA policy | Add agent capabilities to `agent_permissions.rego` | Platform admin |
| Call document-service | HTTP POST with delegation context | Agent developer |

Today, registration is done by editing Go source and Rego policy files.
A future improvement (outside this ADR's scope) is to add a dynamic
registration API:

```text
POST /agents
{
  "id": "customer-llm",
  "name": "Customer LLM Service",
  "capabilities": ["engineering", "finance"],
  "spiffe_id": "spiffe://demo.example.com/agent/customer-llm"
}
```

This would update agent-service's store and push a policy update to
OPA, eliminating the need for code changes entirely.

### Convergence with Kagenti

The Kagenti platform already supports adding custom agents via its
webhook and agent registration mechanisms. The long-term vision is to
deploy this security infrastructure (AuthBridge, OPA, OTel) **as part
of the Kagenti platform** so that:

- Kagenti handles agent lifecycle (registration, deployment, scaling)
- AuthBridge handles identity and token exchange
- OPA handles policy enforcement
- OTel provides unified observability

This ADR's OTel instrumentation is a step toward that convergence —
the ext-proc tracing work in kagenti-extensions benefits all Kagenti
users, not just this demo.

## Phased implementation plan

### Subphase A: OTel SDK integration (done)

- Added `go.opentelemetry.io/otel` dependencies
- Created `pkg/telemetry/` with tracer provider (`provider.go`),
  HTTP middleware (`middleware.go`), and custom span helpers
  (`spans.go`)
- Instrumented all five Go services (HTTP handlers + outbound clients)
- Added custom security span attributes (`AttrUserID`, `AttrAgentID`,
  `AttrDocumentID`, `AttrAccessGranted`, etc.)
- Verified traces appear with OTLP exporter

### Subphase B: collector and Jaeger (done)

- Deployed OTel Collector as a standalone Deployment in `spiffe-demo`
  namespace
- Configured OTLP/gRPC receiver on port 4317 and Jaeger exporter
- Deployed Jaeger all-in-one for trace visualization (port 16686)
- Added manifests to `deploy/k8s/base/` (`otel-collector.yaml`,
  `jaeger.yaml`)
- Verified full trace propagation across all services including
  through Envoy (W3C `traceparent` header preserved)

### Subphase C: ext-proc instrumentation (done)

- Forked kagenti-extensions
- Added OTel tracing to the Go ext-proc: `ext_proc.outbound` parent
  span with `token_exchange` and `jwt_validation` child spans
- Trace context propagation from Envoy to ext-proc via
  `grpc-trace-bin` header
- Token exchange span emits `token.subject`, `token.aud.before`,
  `token.aud.after`, `exchange.grant_type` attributes
- Discovered and fixed Envoy config bug: `request_headers_to_add`
  at `virtual_hosts` level is invisible to ext-proc (see
  `docs/bugs/envoy-ext-proc-direction-header-bug.md`)
- Fix: Lua HTTP filter before ext-proc injects
  `x-authbridge-direction: inbound` header

### Subphase D: Bearer token propagation (done, replaces TUI)

The original plan for a bubbletea TUI was dropped in favor of Bearer
token propagation — without it, the ext-proc never saw an
`Authorization` header and always logged `passthrough_no_token`.

- Added `AccessToken` field to `pkg/auth/session.go`
- Dashboard stores OIDC access token in session at callback
- Dashboard sets `Authorization: Bearer` header on all outbound
  requests
- user-service forwards Bearer token on the delegation path
  (not on direct access — direct access uses mTLS only)
- agent-service forwards Bearer token on outbound document access
- Envoy sidecar on agent-service intercepts the outbound request,
  ext-proc performs RFC 8693 token exchange

**Architectural decision — single-sidecar (agent-service only):**

During implementation we briefly added an Envoy sidecar to
user-service as well. This caused a double token exchange bug on
the delegation path: user-service's ext-proc exchanged the token on
outbound, then agent-service's ext-proc tried to exchange the
already-exchanged token, and Keycloak rejected it (`client is not
within the token audience`).

Analysis showed that the user-service sidecar was unnecessary:

- **Direct access** (user-service → document-service): authenticated
  via mTLS + OPA policy. No OIDC token needed.
- **Delegated access** (user-service → agent-service →
  document-service): only the last hop (agent → document) needs
  token exchange. user-service just passes the Bearer token through.

The sidecar was reverted. The Envoy + ext-proc is deployed only on
agent-service, where it intercepts the critical outbound hop to
document-service.

### Subphase E: OpenShift deployment (not started)

- Create OTel Collector overlay for OpenShift
- Configure Tempo or cluster-logging as trace backend
- Test full flow on OpenShift with AuthBridge
- Document deployment and usage

## Deployment considerations

### OpenShift-first

- The final version must work on OpenShift — this is the target platform
- Kind is used only for quick local development iteration
- If supporting both Kind and OpenShift requires significant effort,
  focus on **OpenShift only**
- OpenShift provides built-in observability (cluster-logging, Tempo
  operator) that should be leveraged

### OTel Collector deployment options

| Option | Pros | Cons |
| ------ | ---- | ---- |
| Standalone Deployment | Simple, single instance | Extra pod |
| DaemonSet | Automatic on every node | Overkill for demo |
| Sidecar | Per-service, no extra Deployment | Config duplication |

Recommendation: **Standalone Deployment** in the `spiffe-demo` namespace.
One collector instance is sufficient for demo scale.

### Trace sampling

For demo purposes, sample 100% of traces. In production, configure
tail-based sampling in the collector to capture interesting traces
(denied access, high latency, token exchange failures).

## Consequences

### Positive

- **Visibility**: Token exchange flow is observable in Jaeger — traces
  show `token_exchange` and `jwt_validation` spans with decoded
  attributes
- **Reference architecture**: Shows how OTel should be used in agentic
  security workflows
- **Ecosystem integration**: Jaeger works out of the box; Tempo
  available for production
- **Reusable instrumentation**: `pkg/telemetry/` provides standard
  helpers for any Go service
- **kagenti benefit**: ext-proc tracing is valuable to the broader
  kagenti community (PR submitted with bug fix)
- **Bug discovery**: Found and documented Envoy `request_headers_to_add`
  visibility bug — useful for anyone using ext-proc with direction
  headers

### Negative

- **Dependency increase**: OTel SDK adds several Go module dependencies
- **Complexity**: Trace context propagation through Envoy and ext-proc
  requires careful attention to HTTP filter chain ordering
- **Performance overhead**: Tracing adds small latency to every request
  (mitigated by sampling in production)

### Neutral

- Existing Prometheus metrics remain unchanged
- Structured logging continues to work alongside tracing
- Web dashboard is not modified (only backend token propagation added)

## Alternatives considered

### Separate "Token Flow" page in the web dashboard

- **Pros**: No new binary, reuses existing SSE infrastructure
- **Cons**: Dashboard should stay simple; not OTel-native; doesn't
  serve as a reference architecture

### Structured log tailing with a viewer

- **Pros**: No new dependencies, works with existing logging
- **Cons**: Fragile log parsing, not OTel-compatible, doesn't integrate
  with observability ecosystem

### SSE event endpoints per service

- **Pros**: Real-time, no OTel dependency
- **Cons**: Custom protocol, doesn't integrate with Jaeger/Grafana,
  not a pattern customers should adopt

### Keycloak event listener

- **Pros**: Direct access to token exchange events
- **Cons**: Only shows Keycloak's perspective, misses the full
  request chain across services

### Envoy access logs with a viewer

- **Pros**: Captures traffic without code changes
- **Cons**: Requires Envoy config changes, only shows HTTP-level info,
  no semantic security attributes

## References

- [OpenTelemetry Go SDK](https://opentelemetry.io/docs/languages/go/)
- [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [Jaeger](https://www.jaegertracing.io/)
- [Envoy ext-proc direction header bug](../bugs/envoy-ext-proc-direction-header-bug.md)
- [OpenShift distributed tracing](https://docs.openshift.com/container-platform/latest/observability/distr_tracing/distr_tracing_arch/distr-tracing-architecture.html)
