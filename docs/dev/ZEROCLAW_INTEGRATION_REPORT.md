# ZeroClaw integration report

**Date:** 2026-04-06</br>
**Author:** Pavel Anni</br>
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

| Source                     | Finding                                                                                 |
| -------------------------- | --------------------------------------------------------------------------------------- |
| Cisco                      | Third-party skills performing data exfiltration without user awareness                  |
| CrowdStrike                | Published detailed risk analysis of OpenClaw as "AI super agent"                        |
| Microsoft                  | Recommended treating OpenClaw as "untrusted code execution with persistent credentials" |
| Bitsight/SecurityScorecard | 135,000+ instances exposed on public internet, 15,000+ vulnerable to RCE                |
| Koi Security               | 820+ malicious skills found on ClawHub marketplace                                      |
| Gartner                    | "Agentic Productivity Comes With Unacceptable Cybersecurity Risk"                       |
| China (state policy)       | Restricted OpenClaw use for state agencies and SOEs                                     |

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

| OpenClaw problem                      | Our approach                                          |
| ------------------------------------- | ----------------------------------------------------- |
| One agent has access to everything    | Permission intersection limits each agent's scope     |
| No delegation chain — single identity | Nested `act` claims trace every hop                   |
| Skills run with full user privileges  | Agents are auth-unaware; OPA enforces least privilege |
| No audit trail for agent actions      | Every delegation is traceable through JWTs            |
| Shadow AI with elevated privileges    | Agents deployed and authorized by the platform        |

**Positioning:** We are not anti-OpenClaw. OpenClaw proved that
autonomous AI agents are useful. The enterprise question is: how do you
deploy and govern hundreds of them? Our project demonstrates the answer.

## The resource problem

Running OpenClaw instances as individually scoped agents is
impractical at scale:

| Runtime         | RAM per instance | 100 agents | 200 agents |
| --------------- | ---------------- | ---------- | ---------- |
| OpenClaw        | ~1GB+            | 100-200GB  | 200-400GB  |
| OpenFang (Rust) | ~40MB            | 4GB        | 8GB        |
| PicoClaw (Go)   | <10MB            | 1GB        | 2GB        |
| ZeroClaw (Rust) | <5MB             | 500MB      | 1GB        |

## Lightweight alternatives evaluated

### PicoClaw (best reference for Go patterns)

- **Language:** Go (go 1.25.8)
- **Origin:** Sipeed (electronics manufacturer, China)
- **Size:** <10MB RAM, single binary, sub-second startup
- **License:** MIT
- **Stars:** 26K+ GitHub stars
- **Status:** Pre-v1.0, rapid development
- **Dependencies:** ~40 direct, ~60 indirect Go modules
- **Notes:** Well-structured Go codebase with clean, extractable
  patterns. The tool-use loop, tool interface, and hook system are
  directly applicable to our Go agents. Not recommended as a
  dependency (too many channel libraries, no A2A), but excellent as a
  reference implementation. See detailed analysis below.

### OpenFang

- **Language:** Rust (137K LOC, 14 crates)
- **Origin:** RightNow (Jordan)
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

| Member                       | Purpose                                     |
| ---------------------------- | ------------------------------------------- |
| Root binary (`zeroclawlabs`) | Main executable, all agent logic            |
| `crates/robot-kit`           | Hardware robotics toolkit (not relevant)    |
| `crates/aardvark-sys`        | Hardware peripheral bindings (not relevant) |
| `apps/tauri`                 | Desktop app wrapper (not relevant)          |

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

## PicoClaw architecture analysis

PicoClaw follows standard Go layout with a large `pkg/` tree
containing modular, well-separated packages. Despite being designed
for edge/IoT devices, the code quality and patterns are
production-grade.

### Agentic tool-use loop

The core loop (`pkg/tools/toolloop.go`, ~100 lines) implements the
standard agentic pattern:

1. Construct tool definitions from registry
2. Call LLM with messages + tool definitions
3. If LLM returns tool calls → execute all tools **in parallel** →
   append results → loop back to step 3
4. If no tool calls (or max iterations hit) → return final response

The full agent loop (`pkg/agent/loop.go`) adds steering (mid-turn
message injection), context budget management, model routing (switch
between heavy/light models based on complexity), and SubTurn spawning
(hierarchical agent delegation with configurable depth).

### Tool interface

Clean Go interface suitable for direct adoption:

```go
type Tool interface {
    Name() string
    Description() string
    Parameters() map[string]any  // OpenAPI-style JSON Schema
    Execute(ctx context.Context, args map[string]any) *ToolResult
}
```

The `ToolRegistry` is thread-safe with two tiers:

- **Core tools** — always visible to the LLM
- **Hidden tools** — promoted with a TTL (time-to-live in iterations),
  implementing dynamic tool discovery. The LLM can search for tools,
  which promotes them temporarily.

Built-in tools include `exec` (shell), `read_file`, `write_file`,
`edit_file`, `web_fetch`, `web_search`, `cron`, `spawn` (subagent),
and hardware I/O (`i2c`, `spi`).

### Hook system

Before/after hooks on LLM calls and tool execution with four actions:
approve, deny, modify, abort. This maps directly to OPA integration:
a `ToolApprover` hook could check permission intersection *before each
tool execution* in the agentic loop, bringing zero-trust enforcement
inside the agent rather than only at the API gateway.

### Shell execution security

35+ production-tested deny patterns blocking dangerous commands:
`rm -rf`, `sudo`, `dd`, `docker run`, `git push`, `ssh`, `eval`, fork
bombs, etc. Workspace sandboxing with symlink resolution and path
traversal prevention. Configurable allow/deny lists per deployment.

### Memory

Two layers:

- **Session memory** — JSONL append-only files with sharded mutexes
  (64 shards). Crash-safe by design — partial writes lose at most one
  message, never corrupt existing data. Uses skip offsets for O(1)
  truncation.
- **Agent memory** — `MEMORY.md` for long-term facts,
  `memory/YYYYMM/YYYYMMDD.md` for daily notes. Combined and injected
  into system prompt each session.

### What PicoClaw lacks

Same gaps as ZeroClaw:

- No A2A protocol (multi-agent is internal SubTurns only)
- No SPIFFE/workload identity
- No OPA integration
- No AgentCard discovery
- 17+ channel adapters designed for personal chatbot use, not
  headless K8s agents

### Extractable patterns for our Go agents

PicoClaw's value is as a **reference implementation**, not a
dependency. The most valuable patterns to study and adapt:

| Package | Est. lines | What we'd use it for |
| ------- | ---------- | -------------------- |
| `pkg/tools/toolloop.go` | ~100 | Agentic loop for Go agents |
| `pkg/tools/base.go` | ~50 | Tool interface definition |
| `pkg/tools/registry.go` | ~150 | Tool registration and discovery |
| `pkg/agent/hooks.go` | ~100 | OPA tool approval hooks |
| `pkg/tools/shell.go` (deny patterns) | ~50 | Security hardening for exec tool |
| `pkg/memory/jsonl.go` | ~200 | Lightweight session persistence |
| **Total reference code** | **~650** | Core agentic capabilities |

Why extract patterns rather than adopt PicoClaw:

1. PicoClaw is a personal assistant, not a headless K8s agent
2. Same sidecar problem as ZeroClaw (no A2A, no SPIFFE, no Kagenti)
3. 40+ Go dependencies including channel libraries we don't need
4. The valuable parts are small enough to reimplement (~650 lines)
5. Our agents already have the infrastructure integration PicoClaw
   lacks

## One image, many agents: the ConfigMap pattern

### Current state: nearly identical agents

Analysis of `kagenti-summarizer` and `kagenti-reviewer` reveals they
are almost the same code:

- `agent.py` — identical A2A server boilerplate, differs only in which
  handler function is called (`fetch_and_summarize` vs `fetch_and_review`)
- `llm.py` — identical LLM client, differs only in the system prompt
  strings at the top
- `summarizer.py` / `reviewer.py` — identical document fetch logic,
  differs only in prompt selection

The only functional difference is the system prompt. The reviewer adds
a minor prompt-routing feature (general/compliance/security based on
keywords), but the core flow is the same: extract URL, fetch document,
call `provider.complete(system_prompt, content)`, return result.

### Target architecture: one image + ConfigMaps

```text
One container image: "zero-trust-agent"
    ├── A2A server (generic)
    ├── LLM client (generic)
    └── Document handler (generic: fetch URL, call LLM, return result)

ConfigMap: agent-config
    └── system-prompt.txt    ← the only thing that changes per agent

ConfigMap: agent-card
    └── agent-card.json      ← name, description, capabilities
```

Different Deployments, same image:

| Deployment       | system-prompt.txt          | agent-card.json                   | OPA scope                    |
| ---------------- | -------------------------- | --------------------------------- | ---------------------------- |
| summarizer-hr    | "Summarize documents..."   | `{name: "summarizer-hr", ...}`    | `["hr"]`                     |
| summarizer-tech  | "Summarize documents..."   | `{name: "summarizer-tech", ...}`  | `["finance", "engineering"]` |
| reviewer-ops     | "Review documents for..."  | `{name: "reviewer-ops", ...}`     | `["engineering", "admin"]`   |
| reviewer-general | "Review for compliance..." | `{name: "reviewer-general", ...}` | `["all"]`                    |

For agents with multiple prompt variants (like the reviewer's
general/compliance/security modes), a `prompts.json` ConfigMap entry
can hold the variants:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: reviewer-ops-config
data:
  default-prompt: |
    You are a document reviewer...
  prompts.json: |
    {
      "compliance": "You are a compliance review agent...",
      "security": "You are a security review agent..."
    }
```

The generic agent reads `prompts.json` if it exists, falls back to
`default-prompt`. This covers both simple agents (one prompt) and
multi-mode agents (keyword-routed prompts) without separate images.

### Industry validation

This is **the dominant emerging pattern** for multi-agent Kubernetes
deployment. Research across the industry (2025-2026) identifies six
main patterns:

| Pattern                      | Description                                                   | Relevance                                           |
| ---------------------------- | ------------------------------------------------------------- | --------------------------------------------------- |
| One image + config           | Same image, different ConfigMaps/env vars per Deployment      | **Our next step**                                   |
| CRD-managed agents           | Agents declared as CRDs, operator handles lifecycle           | **Already using** (Kagenti)                         |
| Agent Sandbox (K8s SIG)      | `Sandbox`/`SandboxTemplate` CRDs for untrusted code execution | Less relevant (our agents don't run arbitrary code) |
| Virtual actors (Dapr)        | Thousands of agents per process via actor model               | Alternative density model, weaker isolation         |
| Gateway/proxy (agentgateway) | Rust-based proxy for A2A/MCP/LLM traffic (Linux Foundation)   | **Worth watching** (Red Hat is a contributor)       |
| Framework-specific           | CrewAI/LangGraph as standard K8s Deployments                  | Reference implementations                           |

Key projects in this space:

- **[kagent](https://kagent.dev/)** (CNCF Sandbox, Solo.io) — agents
  as CRs with system prompt and tool references. Tools are also CRs
  shared across agents.
- **[Agent Sandbox](https://github.com/kubernetes-sigs/agent-sandbox)**
  (K8s SIG Apps) — `Sandbox`, `SandboxTemplate`, `SandboxWarmPool`
  CRDs for isolated agent execution.
- **[Dapr Agents](https://www.cncf.io/blog/2025/03/12/announcing-dapr-ai-agents/)**
  — virtual actor model, thousands of agents on a single core,
  `DurableAgent` with crash recovery. GA at KubeCon Europe 2026.
- **[agentgateway](https://agentgateway.dev/)** (Linux Foundation,
  v1.0 March 2026) — A2A/MCP/LLM proxy, Kubernetes Gateway API
  extensions. Contributors: AWS, Cisco, IBM, Microsoft, Red Hat.

### Identity: the unsolved problem

An important finding from the research: per-agent identity remains an
open problem. SPIFFE today maps to ServiceAccounts — all replicas of a
Deployment share the same SPIFFE ID. For autonomous agents that need
individual accountability, this is insufficient. Our approach (separate
Deployment per agent with its own ServiceAccount and SPIFFE ID) is the
practical workaround the industry uses today.

Active discussion on this topic at [Solo.io](https://blog.christianposta.com/agent-identity-and-access-management-can-spiffe-work/)
and [nhimg.org](https://nhimg.org/community/agentic-ai-and-nhis/exploring-spiffe-for-agent-identity-and-access-management/).

## ClawHub skills: what they actually are

### The SKILL.md format

An OpenClaw skill is **not a container, not a binary, not executable
code**. It is a `SKILL.md` file — a markdown document with YAML
frontmatter that gets injected into the LLM's system prompt:

```yaml
---
name: my-skill
description: One-line description for the agent
metadata:
  openclaw:
    requires:
      bins: ["jq"]          # Required binaries on host
      env: ["API_KEY"]      # Required env vars
    os: ["darwin", "linux"]
---

Natural language instructions telling the LLM when and how to use
tools. This is a prompt fragment, not code.
```

### Execution model

Skills do not execute directly. The chain is:

1. Skill's markdown body is injected into the LLM system prompt
2. LLM interprets the instructions and decides which tools to call
3. Tools (`exec`, `browser`, `apply_patch`) run as subprocesses
4. Results feed back to the LLM for the next turn

This means "pulling a skill from ClawHub" maps naturally to a
ConfigMap — it's just text. But *running* it requires an agentic
tool-use loop.

### Implications for our project

Most ClawHub skills assume desktop-oriented capabilities (local
filesystem, CLI tools, interactive PTY, browser automation). Many
won't work in a headless Kubernetes pod. But the format itself is
sound and could be adopted for Kubernetes-native skills.

## Option C: Extend existing Go agents (recommended)

After analyzing ZeroClaw's architecture and the ClawHub skill format,
a third option emerges as the strongest path.

### The case for building on what we have

Our current Python agents already have the hard parts that ZeroClaw
lacks:

| Capability                    | Our agents               | ZeroClaw |
| ----------------------------- | ------------------------ | -------- |
| A2A protocol                  | Yes                      | No       |
| AgentCard discovery (Kagenti) | Yes                      | No       |
| SPIFFE identity               | Yes (via infrastructure) | No       |
| OPA policy integration        | Yes (via infrastructure) | No       |
| LLM client                    | Yes                      | Yes      |
| Agentic tool-use loop         | No                       | Yes      |
| Skill loading (SKILL.md)      | No                       | Yes      |

What we would need to add (using PicoClaw as reference):

1. **Agentic tool-use loop** — adapt PicoClaw's `RunToolLoop` pattern
   (call LLM with tool-use enabled, execute tool calls in parallel,
   feed results back, repeat). Estimated ~100-150 lines of Go.
2. **Tool interface and registry** — adapt PicoClaw's `Tool` interface
   and thread-safe registry. Estimated ~200 lines of Go.
3. **Tool implementations** — `exec` (with PicoClaw's deny patterns)
   and `web_fetch`. Estimated ~200 lines of Go.
4. **Hook system for OPA** — adapt PicoClaw's before/after hooks to
   wire OPA policy checks as a `ToolApprover`. Estimated ~100 lines.
5. **Skill loading** — parse `SKILL.md` from ConfigMap (YAML
   frontmatter + markdown). Estimated ~50 lines of Go.

Total estimated effort: ~650-700 lines of Go on top of existing
agents, closely following PicoClaw's proven patterns.

### Advantages over ZeroClaw integration

- **No Rust dependency** — team's primary language is Go
- **No sidecar needed** — A2A is native, not bridged
- **No monolithic binary** — only the code we need
- **Full control** — no upstream dependency on a pre-v1.0 project
- **Smaller footprint** — a Go binary with just the agent loop will be
  comparable to ZeroClaw's 5MB
- **Proven patterns** — PicoClaw's tool loop, registry, and hooks are
  production-tested reference code in Go, derrisking implementation
- **"OpenClaw compatible" claim** — if we can load and execute
  `SKILL.md` skills, we can credibly claim compatibility with the
  ClawHub ecosystem

### What "OpenClaw compatible" means for us

A minimal, defensible claim: "can load and execute `SKILL.md` skills
from ClawHub." This requires:

1. Parse YAML frontmatter from `SKILL.md`
2. Evaluate gating requirements (binaries, env vars)
3. Inject markdown body into LLM system prompt
4. Provide core tools that skills reference (`exec`, `web_fetch`)
5. Run the agentic tool-use loop

We do NOT need to implement: the gateway, channel adapters, Hands
(cron-scheduled agents), memory system, PTY support, or browser
automation. These are OpenClaw daemon features, not skill requirements.

### Deployment model

```text
One container image: "zero-trust-agent" (Go binary, ~10-15MB)

ConfigMap: agent-config
    ├── skill.md           ← SKILL.md from ClawHub or custom
    ├── agent-card.json    ← A2A agent card
    └── prompts.json       ← optional prompt variants

Secret: agent-secrets
    └── LLM_API_KEY        ← LLM provider credentials

OPA policy: agent-permissions.rego
    └── agent_capabilities["summarizer-hr"] := ["hr"]
```

Same image for all agents. Different ConfigMaps create different
agent personalities and capabilities. OPA controls what each agent
can access. Kagenti manages lifecycle and discovery.

## Integration options considered

### Option A: ZeroClaw instances, OpenShift as orchestrator

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

### Option C: Extend existing Go agents with tool-use loop (recommended)

Rewrite the current Python agents as a single Go binary with an
agentic tool-use loop and SKILL.md loading. Keep all existing
infrastructure (A2A, Kagenti, SPIFFE, OPA) unchanged.

**Advantages:**

- Go is the team's primary language — no Rust dependency
- A2A protocol is native, no sidecar bridge needed
- Full control over the codebase, no upstream dependency
- Estimated ~500-800 lines of Go on top of existing code
- Credible "OpenClaw compatible" claim via SKILL.md support
- Smallest possible footprint (~10-15MB Go binary)

**Risks:**

- Must implement agentic tool-use loop (LLM tool calling is well
  documented but needs careful implementation)
- ClawHub skills that assume desktop features (browser, PTY) won't
  work without adaptation
- "OpenClaw compatible" is a self-declared claim, not a certification

**This is the recommended path.** ZeroClaw remains valuable as a
reference implementation and potential collaboration partner, but
building on our existing A2A agents avoids the sidecar complexity
and Rust dependency while achieving the same goal.

## ClawHub skill compatibility validator

Not all ClawHub skills will run in a headless Kubernetes pod. A
validator tool can assess compatibility before deployment, catching
issues early rather than at runtime.

### Two-level analysis

**Static analysis (deterministic, no LLM cost):**

| Check                                  | What it catches                                      |
| -------------------------------------- | ---------------------------------------------------- |
| `requires.os` includes `linux`         | macOS/Windows-only skills                            |
| `requires.bins` available in container | Missing CLI dependencies                             |
| Tool references in markdown body       | Desktop-only tools (`browser`, `pty`, `applescript`) |
| File path patterns                     | Host-specific paths (`~/`, `~/.openclaw/`)           |
| Network assumptions                    | Skills expecting `localhost` services                |

**Semantic analysis (LLM-based, for subtle cases):**

| Check                         | What it catches                                       |
| ----------------------------- | ----------------------------------------------------- |
| Interactive input assumptions | Skills expecting mid-execution user prompts           |
| GUI output expectations       | Screenshots, browser rendering, desktop notifications |
| Persistent filesystem state   | Skills assuming state across sessions                 |
| Shell command feasibility     | Commands that won't work in a minimal container       |

The static checks catch ~80% of incompatibilities. The LLM-based
checks handle the rest.

### Implementation options

1. **CLI tool (Go)** — pulls a skill from ClawHub, parses frontmatter,
   scans markdown for known patterns, outputs a compatibility report.
   Suitable for CI/CD pipelines as an automated gate before deploying
   a skill to OpenShift.

2. **Claude Code skill** — interactive analysis where you provide a
   ClawHub skill URL, it fetches the SKILL.md, runs static checks,
   then uses LLM judgment for semantic analysis. Quick to build,
   useful for exploration.

3. **Both** — CLI for automation, Claude skill for interactive use.

### Output format

The validator would produce a structured report:

```text
Skill: clawhub.ai/skills/jira-ticket-creator
Compatibility: COMPATIBLE (with notes)

Static checks:
  ✓ OS: linux supported
  ✓ Required bins: curl, jq (available in base image)
  ✓ No desktop-only tools referenced
  ✗ References ~/.openclaw/config — needs ConfigMap mapping

Semantic checks:
  ✓ No interactive input required
  ✓ No GUI output expected
  ⚠ Assumes access to Jira API — needs NetworkPolicy allowlist

Recommendation: Deploy with ConfigMap for config path override.
Add Jira API host to NetworkPolicy egress rules.
```

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

## Agent memory systems

### OpenClaw vs ZeroClaw memory

Both are local-first and self-contained, but differ significantly
in sophistication:

| Aspect | OpenClaw | ZeroClaw |
| ------ | -------- | -------- |
| Storage | Markdown files + SQLite index | SQLite only (bundled `rusqlite`) |
| Search | Hybrid (BM25 + vector similarity) | Keyword (SQLite FTS) |
| Memory types | Long-term, daily notes, dreams, soul | Store/recall/forget |
| Human-readable | Yes (Markdown files are source of truth) | No (SQLite rows) |
| Git-friendly | Yes (text files) | No |
| Consolidation | "Dream" background process promotes short-term to long-term | None documented |
| External deps | None required (embeddings optional) | None required |

**OpenClaw** uses a dual-layer approach: `MEMORY.md` for long-term
facts (loaded every session), `memory/YYYY-MM-DD.md` for daily notes,
and `DREAMS.md` for experimental background consolidation. These
Markdown files are indexed into a per-agent SQLite database with
~400-token chunks. Hybrid search combines BM25 keyword matching with
vector similarity (auto-detects embedding providers).

**ZeroClaw** stores everything in bundled SQLite with in-memory LRU
caching. Memory tools support recall, store, forget, knowledge, and
project intel operations. Search is keyword-based (SQLite FTS) — no
vector/semantic search. Per-client isolation via ClientId keys.

**Kubernetes problem**: Both use SQLite per agent, which means
StatefulSet + PVC per agent instance. This doesn't scale well for
fleets of 100+ agents on OpenShift.

### Dedicated memory solutions for Kubernetes

Several purpose-built memory systems are better suited for
multi-agent Kubernetes deployment:

**[Letta](https://github.com/letta-ai/letta)** (formerly MemGPT) —
best OpenShift fit. Uses PostgreSQL + pgvector as backend. Three
memory types:

- **Core blocks** — working memory pinned to the context window,
  editable by the agent at runtime
- **Archival** — long-term vector-indexed storage for facts that
  don't fit in the context window
- **Recall** — full conversation history persisted in the database

Server is stateless (Deployment), PG is the only stateful component.
Works with CrunchyData PostgreSQL Operator on OpenShift. Multi-agent
support via shared memory blocks — multiple agents can read/write
the same block. Apache 2.0 license.

**[Mem0](https://github.com/mem0ai/mem0)** — universal memory
*layer* (library, not framework). Supports 20 vector DB backends
including PGVector, Qdrant, Milvus, Redis, and Elasticsearch. Three
scopes: user, session, agent. Optional graph memory for
entity-relationship tracking. Stateless SDK — you bring your own
vector store. Most flexible for integrating into existing agents.
Apache 2.0 license.

**[Graphiti](https://github.com/getzep/graphiti)** (from Zep) —
temporal knowledge graph. Stores facts as graph edges with
`valid_at`/`invalid_at` timestamps — old facts are invalidated, not
deleted. Unique for compliance and audit use cases where you need to
know what was true at a specific point in time. Requires Neo4j or
FalkorDB. Heaviest infrastructure footprint but strongest temporal
reasoning. Apache 2.0 license.

### Comparison for OpenShift deployment

| Solution | Backend | K8s readiness | Multi-agent | Temporal tracking | External deps |
| -------- | ------- | ------------- | ----------- | ----------------- | ------------- |
| OpenClaw built-in | Markdown + SQLite | Low (PVC per agent) | Via Honcho backend | Implicit (daily files) | None |
| ZeroClaw built-in | SQLite | Low (PVC per agent) | Per-client isolation | None | None |
| Letta | PostgreSQL + pgvector | **High** (operator-managed PG) | Shared memory blocks | Full history in DB | PostgreSQL + LLM |
| Mem0 | Configurable (20 backends) | Medium (needs vector DB) | Agent-scoped | None | LLM + vector DB |
| Graphiti | Neo4j / FalkorDB | Medium-High (graph DB) | Shared knowledge graph | **First-class** (valid_at/invalid_at) | Graph DB + LLM + embeddings |

### Relevance to our project

Our current agents (summarizer, reviewer) are **stateless** — they
receive a document, call an LLM, return a result. No memory is
needed, and this is an advantage for Kubernetes deployment (pure
Deployments, no PVCs, no StatefulSets).

If we add agents that need persistent memory (e.g., a research agent
that builds knowledge over time, or a compliance reviewer that tracks
findings across documents), the ranking for OpenShift is:

1. **Letta** — PG-backed, operator-managed, stateless server, shared
   memory blocks map to our permission intersection model
2. **Mem0 + PGVector** — library approach, reuses existing PG
   infrastructure on OpenShift
3. **Graphiti** — if temporal fact tracking is required for
   compliance/audit scenarios
4. **OpenClaw Markdown model** — simplest and human-auditable, viable
   for small-scale deployments via ConfigMap/PVC

Letta's shared memory blocks are particularly interesting: they enable
multiple scoped agents to share *some* knowledge (e.g., a user's
preferences or organizational context) while keeping their own working
memory isolated. This maps naturally to the permission intersection
model — an agent's memory access could be scoped the same way its
document access is scoped.

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

1. Merge current Python summarizer and reviewer into a single generic
   Go-based A2A agent with ConfigMap-driven prompts
2. Add an agentic tool-use loop (LLM tool calling with `exec` and
   `web_fetch` tools)
3. Implement SKILL.md loading from ConfigMap
4. Deploy multiple agent instances (summarizer-hr, summarizer-tech,
   reviewer-ops) from the single image to validate the pattern
5. Pull a simple ClawHub skill and test it in the Kubernetes
   environment
6. Build a ClawHub skill compatibility validator (CLI + Claude Code
   skill) to assess OpenShift readiness before deployment
7. Evaluate Letta as the memory backend for stateful agents — test
   shared memory blocks with permission intersection scoping
8. Reach out to ZeroClaw team at Harvard/MIT about collaboration
   (A2A protocol, Kubernetes health endpoints)
9. Draft a blog post or conference talk: "From personal agents to
   governed fleets"
