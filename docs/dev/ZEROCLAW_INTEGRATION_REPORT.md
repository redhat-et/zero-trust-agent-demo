# ZeroClaw integration report

**Date:** 2026-04-06
**Author:** Pavel Anni
**Status:** Draft for team discussion

## Context

The OpenClaw AI agent framework has become the dominant open-source
agent platform (247K+ GitHub stars in 60 days, Jensen Huang called it
"probably the single most important release of software ever"). This
report analyzes how our zero-trust agent demo should position itself
relative to OpenClaw and evaluates lightweight alternatives for
enterprise deployment.

## The OpenClaw problem for enterprises

OpenClaw is a **personal assistant** — single-user, single-process,
designed to run on a laptop and control a user's digital life. It
connects to everything (email, Slack, files, browser, calendar) through
100+ skills and operates autonomously via a heartbeat daemon.

This architecture creates fundamental problems for enterprise
deployment:

### Security concerns (documented by industry)

| Source | Finding |
| ------ | ------- |
| Cisco | Third-party skills performing data exfiltration without user awareness |
| CrowdStrike | Published detailed risk analysis of OpenClaw as "AI super agent" |
| Microsoft | Recommended treating OpenClaw as "untrusted code execution with persistent credentials" |
| Bitsight/SecurityScorecard | 135,000+ instances exposed on public internet, 15,000+ vulnerable to RCE |
| Koi Security | 820+ malicious skills found on ClawHub marketplace |
| Gartner | "Agentic Productivity Comes With Unacceptable Cybersecurity Risk" |
| China (state policy) | Restricted OpenClaw use for state agencies and SOEs |

Key CVEs: CVE-2026-25253 (CVSS 8.8, gateway compromise),
CVE-2026-24763 and CVE-2026-25157 (command injection).

### Shadow AI risk

OpenClaw is "shadow AI with elevated privileges." Unlike shadow SaaS
(which creates isolated data silos), an OpenClaw agent connects to
*everything* the employee has access to. It runs continuously, builds
persistent memory across sessions, and accumulates organizational
knowledge. A compromised agent inherits all of it.

Enterprise security teams fought shadow IT for a decade. OpenClaw is
shadow IT on steroids.

### Why our project is the answer, not the competitor

Our zero-trust demo solves exactly the problems OpenClaw exposes:

| OpenClaw problem | Our approach |
| ---------------- | ------------ |
| One agent has access to everything | Permission intersection limits each agent's scope |
| No delegation chain — single identity | Nested `act` claims trace every hop |
| Skills run with full user privileges | Agents are auth-unaware; OPA enforces least privilege |
| No audit trail for agent actions | Every delegation is traceable through JWTs |
| Shadow AI with elevated privileges | Agents deployed and authorized by the platform |

**Positioning:** We are not anti-OpenClaw. OpenClaw proved that
autonomous AI agents are useful. The enterprise question is: how do you
deploy and govern hundreds of them? Our project demonstrates the answer.

## The resource problem

Running OpenClaw instances as individually scoped agents is
impractical at scale:

| Runtime | RAM per instance | 100 agents | 200 agents |
| ------- | ---------------- | ---------- | ---------- |
| OpenClaw | ~1GB+ | 100-200GB | 200-400GB |
| OpenFang (Rust) | ~40MB | 4GB | 8GB |
| PicoClaw (Go) | <10MB | 1GB | 2GB |
| ZeroClaw (Rust) | <5MB | 500MB | 1GB |

## Lightweight alternatives evaluated

### PicoClaw

- **Language:** Go
- **Origin:** Sipeed (electronics manufacturer, China)
- **Size:** <10MB RAM, single binary
- **License:** MIT
- **Status:** Pre-v1.0, rapid development
- **Notes:** Designed for edge/IoT ($10 hardware). 12K GitHub stars.
  Go-based, which aligns with our team's primary language. However,
  the organizational relationship is less favorable for Red Hat
  collaboration.

### OpenFang

- **Language:** Rust (137K LOC, 14 crates)
- **Origin:** RightNow AI (Saudi Arabia)
- **Size:** ~40MB idle, 32MB binary
- **License:** Open source
- **Status:** Targeting v1.0 mid-2026
- **Notes:** Heavier than PicoClaw/ZeroClaw. Self-describes as an
  "Agent Operating System" rather than a lightweight runtime. 180ms
  cold start. Built-in WASM sandbox and extensive security features.
  More complex than needed for our use case.

### ZeroClaw (recommended)

- **Language:** Rust
- **Origin:** Harvard/MIT researchers, Massachusetts
- **Size:** <5MB RAM, 8.8MB binary, sub-10ms cold start
- **License:** MIT + Apache 2.0
- **Status:** Pre-v1.0, 24K GitHub stars
- **Notes:** Security-first design with explicit scope boundaries,
  allowlisted operations, and least-privilege principles. Trait-driven
  architecture for provider/channel/memory extensibility.

### Why ZeroClaw

1. **Resource efficiency** — smallest footprint of all alternatives
   (5MB RAM, sub-10ms cold start)
2. **Security-first design** — least-privilege principles are built
   into the architecture, aligning directly with our zero-trust model
3. **Red Hat relationship** — main developers are at Harvard and MIT
   in Massachusetts. Red Hat has long-standing relationships with
   these universities and significant presence in the state.
   A team member already has a contact with the ZeroClaw developers.
4. **Architectural fit** — trait-driven design makes it adaptable
   without forking

## ZeroClaw architecture analysis

### Codebase structure

ZeroClaw is a monolithic Rust binary with a Cargo workspace:

| Member | Purpose |
| ------ | ------- |
| Root binary (`zeroclawlabs`) | Main executable, all agent logic |
| `crates/robot-kit` | Hardware robotics toolkit (not relevant) |
| `crates/aardvark-sys` | Hardware peripheral bindings (not relevant) |
| `apps/tauri` | Desktop app wrapper (not relevant) |

Core functionality lives in `src/` as 38 modules: `agent`, `gateway`,
`channels`, `tools`, `skills`, `hands`, `providers`, `memory`,
`config`, `sop`, `runtime`, `security`, and others.

### Run modes

1. **`zeroclaw daemon`** — full stack: gateway (Axum HTTP/WS/SSE on
   port 42617), all configured channel adapters, cron scheduler
   ("Hands"), and agent loop. This is the "personal assistant" mode.

2. **`zeroclaw agent`** — agent-only: interactive REPL, no gateway,
   no channels, no scheduler. Just the core agent loop.

### Agent runtime core

The `Agent` struct exposes a clean API:

- `Agent::turn(message)` — single synchronous turn with tool loop
- `Agent::turn_streamed(message, event_tx)` — streaming variant
- `Agent::run_single(message)` — one-shot wrapper
- `Agent::from_config(config)` — factory from TOML config
- `Agent::builder()` — fluent builder

The agent has **no built-in HTTP listener**. It makes outbound calls
to LLM providers only. External systems drive it via `turn()`.

### Webhook channel — the integration point

ZeroClaw includes a `WebhookChannel` that provides HTTP-driven agent
operation:

- Listens on configurable port (default 8080) and path (`/webhook`)
- Accepts `POST` with `{sender, content, thread_id}` JSON payload
- POSTs results to a configured callback URL
- Supports HMAC-SHA256 signature verification

**This is the key for Kubernetes deployment.** Configure ZeroClaw with
only the webhook channel, and it becomes an HTTP-driven agent with no
Telegram, Slack, or gateway UI.

### What ZeroClaw does NOT have

- **No A2A protocol** — no `.well-known/agent-card.json`, no Google
  A2A compliance
- **No SPIFFE/workload identity** — auth is bearer token or HMAC only
- **No agent card discovery** — nothing for Kagenti to discover
- **Not decomposable at compile time** — binary includes all code,
  but at 8.8MB this is acceptable

## Integration architecture

### Recommended approach: ZeroClaw + A2A sidecar

```text
                    Kagenti discovers
                    AgentCard CR
                         |
+------------------+  +--+--------------------------------------+
| agent-service    |  | Pod: summarizer-hr                      |
|   (gateway)      +->|  +-----------+    +-------------------+ |
|                  |  |  | A2A       +--->| ZeroClaw          | |
|                  |  |  | sidecar   |    | (webhook channel) | |
|                  |  |  | (thin Go) |    |                   | |
|                  |  |  +-----------+    +-------------------+ |
+------------------+  +-----------------------------------------+
```

1. **ZeroClaw runs with webhook channel only** — `config.toml`
   restricts tools, sets a single LLM provider, defines the agent's
   purpose via system prompt
2. **A thin Go sidecar bridges A2A to webhook** — receives A2A
   protocol requests, translates to ZeroClaw's JSON format,
   translates responses back. Estimated ~200 lines of Go.
3. **SPIFFE identity** handled by Envoy sidecar or SPIRE CSI
   (existing infrastructure)
4. **AgentCard CR** created by Kagenti deployment, pointing to the
   A2A sidecar endpoint
5. **OPA policies** scope the agent's effective permissions via
   permission intersection (unchanged from current architecture)

### Per-agent configuration

Each ZeroClaw deployment gets a different `config.toml` via ConfigMap:

```toml
default_provider = "anthropic"
api_key_env = "ZEROCLAW_API_KEY"

[webhook]
enabled = true
port = 8080
path = "/webhook"
hmac_secret_env = "WEBHOOK_SECRET"

[agent]
allowed_tools = ["web_fetch", "summarize"]
system_prompt = "You are a document summarizer focused on HR content."
```

Same binary, different config, different OPA scope — the pattern we
already use with our Python A2A agents, now with a
production-grade runtime.

### What stays the same

The entire zero-trust infrastructure is unchanged:

- Agent-service gateway discovers agents via Kagenti AgentCard CRs
- SPIFFE provides workload identity at the transport layer
- AuthBridge performs RFC 8693 token exchange for delegation context
- OPA evaluates permission intersection on every request
- Nested `act` claims trace the full delegation chain
- Credential gateway translates Zero Trust tokens to
  service-specific credentials

ZeroClaw replaces only the innermost component — the agent runtime
that receives work and produces results.

## Integration options considered

### Option A: OpenShift as orchestrator (recommended)

Each ZeroClaw instance is a Kubernetes Deployment with its own
ServiceAccount, SPIFFE identity, and OPA policy. Kagenti manages
lifecycle. OpenShift handles scheduling, scaling, and resource
isolation.

**Advantages:**

- Matches existing architecture — no changes to gateway, discovery,
  or policy infrastructure
- Each agent gets real Kubernetes identity (ServiceAccount,
  NetworkPolicy, resource limits)
- Aligns with how OpenShift operators already think and work
- No fork of ZeroClaw required

### Option B: Modify ZeroClaw orchestrator to be OpenShift-aware

Fork ZeroClaw's gateway to create Kubernetes Deployments instead of
local processes.

**Disadvantages:**

- Fork maintenance burden on a fast-moving pre-v1.0 project
- Split-brain problem: who owns agent lifecycle — ZeroClaw or Kagenti?
- Duplicates what Kubernetes already does well
- Requires deep Rust expertise to maintain

**Not recommended** unless ZeroClaw upstream adopts Kubernetes-native
orchestration.

## Upstream collaboration opportunities

The ZeroClaw team at Harvard/MIT may be receptive to contributions
that benefit both projects:

1. **A2A protocol support** — native `.well-known/agent-card.json`
   endpoint, eliminating the sidecar. Clean contribution that makes
   ZeroClaw interoperable with Google's agent protocol.
2. **Kubernetes health endpoints** — liveness/readiness probes for
   the webhook channel mode. PicoClaw already added these.
3. **SPIFFE identity integration** — optional mTLS via SPIRE CSI.
   Aligns with ZeroClaw's security-first philosophy.
4. **Agent scoping improvements** — finer-grained tool restrictions,
   per-deployment capability declarations.

Contributing upstream avoids fork maintenance and gives Red Hat
visibility in the Claw ecosystem.

## Positioning summary

**For teammates:** OpenClaw proved the demand for autonomous AI
agents. The enterprise question is not *whether* to deploy agents but
*how* to govern them at scale. Our project provides the governance
layer (identity, policy, delegation chains). ZeroClaw provides a
lightweight runtime that makes many-small-agents physically feasible
on OpenShift. Together they demonstrate enterprise-grade agent
deployment.

**For customers:** You don't give one mega-agent access to everything.
You deploy many small, scoped agents — each with its own identity and
policy-controlled permissions. ZeroClaw makes this feasible at 5MB per
agent. OpenShift provides orchestration and resource isolation. SPIFFE
provides workload identity. OPA enforces permission intersection.
This project shows how these pieces compose.

**Not the message:** "OpenClaw is wrong" or "don't use OpenClaw."

**The message:** "OpenClaw is step one — here's step two."

## Next steps

1. Set up a ZeroClaw dev environment and validate the webhook channel
   integration
2. Build a proof-of-concept A2A sidecar in Go
3. Deploy a ZeroClaw-based summarizer-hr alongside the existing Python
   agent to compare behavior
4. Reach out to ZeroClaw team about A2A protocol contribution
5. Draft a blog post or conference talk: "From personal agents to
   governed fleets"
