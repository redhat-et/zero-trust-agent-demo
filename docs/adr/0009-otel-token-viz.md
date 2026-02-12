# ADR-0009: OpenTelemetry instrumentation and token exchange TUI

## Status

Proposed

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
and build a **bubbletea-based terminal UI** that renders token exchange
flows as live sequence diagrams.

### Why OpenTelemetry

- Industry-standard, vendor-neutral observability framework
- Native integration with Jaeger, Grafana Tempo, and other backends
- Go SDK provides HTTP middleware and outbound client instrumentation
- Trace context propagation via W3C `traceparent` header works through
  Envoy without extra configuration
- Positions this demo as a reference architecture, not a one-off hack

### Why a TUI (not extending the web dashboard)

- The web dashboard is intentionally simple and should stay that way
- A terminal UI impresses technical audiences — previous experience
  with bubbletea/lipgloss TUIs at demos has shown strong impact
- The TUI is a separate binary that can be used independently
- It naturally complements `kubectl logs` and terminal workflows
- It can be shipped as a single static Go binary

### Why bubbletea

- Pure Go, compiles to a single binary
- Elm architecture is well-suited for streaming trace data
- lipgloss provides rich terminal styling without ncurses
- Large ecosystem of community components (bubbles)
- Aligns with the project's Go-first approach

## Architecture overview

```text
┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│ user-svc │   │agent-svc │   │ doc-svc  │   │ opa-svc  │
│  :8082   │   │  :8083   │   │  :8084   │   │  :8085   │
└────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘
     │  OTLP/gRPC   │              │              │
     └───────┬──────┴──────┬───────┴──────┬───────┘
             ▼             ▼              ▼
       ┌─────────────────────────────────────┐
       │       OpenTelemetry Collector       │
       │         (otel-collector)            │
       └──────┬──────────┬──────────┬───────┘
              │          │          │
              ▼          ▼          ▼
         ┌────────┐ ┌────────┐ ┌────────┐
         │ Jaeger │ │ Tempo  │ │  TUI   │
         │  (dev) │ │ (prod) │ │(OTLP)  │
         └────────┘ └────────┘ └────────┘
```

### Trace structure

A single delegated access request produces one trace with spans across
services:

```text
[user-service] POST /delegate
  ├─ [user-service] validate_user (alice)
  ├─ [user-service] → agent-service POST /agents/gpt4/access
  │   ├─ [envoy/ext-proc] token_exchange
  │   │     span attrs: token.subject, token.aud.before, token.aud.after,
  │   │                 exchange.grant_type (urn:ietf:params:oauth:grant-type:token-exchange)
  │   ├─ [agent-service] validate_delegation
  │   ├─ [agent-service] → document-service POST /access
  │   │   ├─ [envoy/ext-proc] token_exchange
  │   │   ├─ [document-service] jwt_validation
  │   │   │     span attrs: jwt.issuer, jwt.azp, jwt.groups
  │   │   ├─ [document-service] → opa-service POST /v1/data/...
  │   │   │   └─ [opa-service] policy_evaluation
  │   │   │         span attrs: decision, reason, caller_type
  │   │   └─ [document-service] access_result
  │   │         span attrs: document_id, allowed
  │   └─ [agent-service] delegation_result
  └─ [user-service] response
```

### Custom span attributes

Security-relevant moments get dedicated span events and attributes
rather than just generic HTTP spans:

| Span | Key attributes |
| ---- | -------------- |
| `token_exchange` | `token.subject`, `token.aud.before`, `token.aud.after`, `exchange.grant_type` |
| `jwt_validation` | `jwt.issuer`, `jwt.azp`, `jwt.groups`, `jwt.exp` |
| `policy_evaluation` | `opa.decision`, `opa.reason`, `opa.caller_type`, `opa.effective_departments` |
| `permission_intersection` | `user.departments`, `agent.capabilities`, `effective.departments` |

### TUI design

The TUI has two main views:

**Trace list view** — streams incoming traces in real time:

```text
 ┌─ Token Exchange Monitor ─────────────────────────────────┐
 │                                                          │
 │  TRACE  alice → gpt4 → DOC-001    ✓ ALLOWED   120ms     │
 │  TRACE  bob → summarizer → DOC-002  ✓ ALLOWED   89ms    │
 │  TRACE  alice → gpt4 → DOC-004    ✗ DENIED    45ms      │
 │                                                          │
 │  ↑/↓ navigate   enter detail   q quit                    │
 └──────────────────────────────────────────────────────────┘
```

**Trace detail view** — sequence diagram with decoded tokens:

```text
 ┌─ alice → gpt4 → DOC-001 ──────────────────────────────────┐
 │                                                            │
 │  user-svc    agent-svc    ext-proc    doc-svc    opa-svc   │
 │     │            │            │          │          │       │
 │     │──delegate──▶            │          │          │       │
 │     │            │──access───▶│          │          │       │
 │     │            │            │──token───▶          │       │
 │     │            │            │  exchange │          │      │
 │     │            │            │  aud: agent-svc     │      │
 │     │            │            │  → aud: doc-svc     │      │
 │     │            │            │          │──eval────▶│     │
 │     │            │            │          │  ALLOW   ◀│     │
 │     │            │            │          ◀───────────│     │
 │     │            ◀────────────│          │          │      │
 │     ◀────────────│            │          │          │      │
 │                                                            │
 │  Token details:                                            │
 │  ┌─ Before exchange ──────┐  ┌─ After exchange ─────────┐ │
 │  │ sub: agent/gpt4        │  │ sub: agent/gpt4          │ │
 │  │ aud: agent-service     │  │ aud: document-service    │ │
 │  │ iss: spire-server      │  │ iss: keycloak            │ │
 │  │ groups: [eng, finance] │  │ groups: [eng, finance]   │ │
 │  └────────────────────────┘  └──────────────────────────┘ │
 │                                                            │
 │  esc back   q quit                                         │
 └────────────────────────────────────────────────────────────┘
```

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

1. **`cmd/token-viz/`** — new bubbletea TUI binary
   - OTLP receiver (listens for traces from collector)
   - Trace aggregation and filtering
   - Sequence diagram renderer
   - JWT decoder for token detail view

1. **`deploy/k8s/`** — OTel Collector deployment
   - Collector ConfigMap (receivers, processors, exporters)
   - Collector Deployment and Service
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

### Subphase A: OTel SDK integration

- Add `go.opentelemetry.io/otel` dependencies
- Create `pkg/telemetry/` with tracer provider, middleware, and helpers
- Instrument all four Go services (HTTP handlers + outbound clients)
- Add custom security span attributes
- Verify traces appear in stdout exporter

### Subphase B: collector and Jaeger

- Deploy OTel Collector as a sidecar or standalone pod
- Configure OTLP receiver and Jaeger exporter
- Deploy Jaeger for visual trace inspection during development
- Verify full trace propagation across all services including through
  Envoy (W3C `traceparent` header)

### Subphase C: ext-proc instrumentation

- Fork kagenti-extensions
- Add OTel tracing to the Go ext-proc token exchange handler
- Ensure trace context propagation from Envoy to ext-proc and back
- Verify token exchange spans appear in Jaeger traces
- Open PR against kagenti-extensions

### Subphase D: bubbletea TUI

- Build `cmd/token-viz/` binary
- Implement OTLP receiver (gRPC server that accepts trace exports)
- Build trace list view with real-time streaming
- Build trace detail view with sequence diagram rendering
- Add JWT decoding for token before/after comparison
- Add lipgloss styling for terminal rendering

### Subphase E: OpenShift deployment

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

- **Visibility**: Token exchange flow becomes observable and demonstrable
- **Reference architecture**: Shows how OTel should be used in agentic
  security workflows
- **Ecosystem integration**: Jaeger, Grafana, Tempo work out of the box
- **Reusable instrumentation**: `pkg/telemetry/` is useful beyond the TUI
- **kagenti benefit**: ext-proc tracing is valuable to the broader
  kagenti community
- **Demo impact**: TUI provides a compelling visual for technical audiences

### Negative

- **Dependency increase**: OTel SDK adds several Go module dependencies
- **Complexity**: Trace context propagation through Envoy and ext-proc
  requires careful configuration
- **Maintenance**: TUI is a new binary to build, test, and ship
- **Performance overhead**: Tracing adds small latency to every request
  (mitigated by sampling in production)

### Neutral

- Existing Prometheus metrics remain unchanged
- Structured logging continues to work alongside tracing
- Web dashboard is not modified

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
- [bubbletea](https://github.com/charmbracelet/bubbletea)
- [lipgloss](https://github.com/charmbracelet/lipgloss)
- [Jaeger](https://www.jaegertracing.io/)
- [OpenShift distributed tracing](https://docs.openshift.com/container-platform/latest/observability/distr_tracing/distr_tracing_arch/distr-tracing-architecture.html)
