# SPIFFE/SPIRE Zero Trust Demo Guide

## Quick Overview

This demo shows how to implement **Zero Trust security** for AI agents using:

- **SPIFFE/SPIRE** for cryptographic workload identity
- **OPA (Open Policy Agent)** for policy-based access control
- **Permission Intersection** to limit AI agent access

### The Core Principle

When a user delegates to an AI agent:

```text
Effective Permissions = User Permissions ∩ Agent Capabilities
```

**Agents can never exceed the permissions of either the user OR the agent's own capabilities.**

## Architecture

```text
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Dashboard  │────▶│User Service │────▶│Agent Service│
│   :8080     │     │   :8082     │     │   :8083     │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                    ┌─────────────┐     ┌──────▼──────┐
                    │ OPA Service │◀────│Doc Service  │
                    │   :8085     │     │   :8084     │
                    └─────────────┘     └─────────────┘
```

## Running the Demo

### Option A: Build and Run Locally

```bash
# Build everything
make build

# Start all services
./scripts/run-local.sh
```

### Option B: Deploy with Pre-built Images

No local builds required! Images are automatically built and pushed to GitHub Container Registry.

```bash
# Quick deploy to Kind
./scripts/setup-kind.sh
kubectl apply -f deploy/k8s/
./scripts/port-forward.sh

# Open the dashboard
open http://localhost:8080
```

### Open Dashboard

Navigate to: **http://localhost:8080**

### Watch Logs (Optional)

In a separate terminal:

```bash
tail -f tmp/logs/*.log
```

## Demo Scenarios to Try

### Scenario 1: Direct User Access

| User  | Document            | Result | Why                        |
| ----- | ------------------- | ------ | -------------------------- |
| Alice | Engineering Roadmap | ✅      | Alice has engineering dept |
| Alice | HR Guidelines       | ❌      | Alice lacks hr dept        |
| Bob   | Admin Policies      | ✅      | Bob has admin dept         |
| Carol | HR Guidelines       | ✅      | Carol has hr dept          |

**Try it**: Select Alice, no agent, DOC-001 → Click "Direct Access"

### Scenario 2: Agent Without User (Always Denied)

| Agent  | Document | Result | Why                            |
| ------ | -------- | ------ | ------------------------------ |
| GPT-4  | Any      | ❌      | Agents require user delegation |
| Claude | Any      | ❌      | Agents require user delegation |

**Key Principle**: AI agents cannot act autonomously. They must have explicit user delegation.

### Scenario 3: Delegated Access (Permission Intersection)

| User + Agent       | Document        | Result | Why                          |
| ------------------ | --------------- | ------ | ---------------------------- |
| Alice + GPT-4      | DOC-001 (eng)   | ✅      | Both have engineering        |
| Alice + GPT-4      | DOC-004 (hr)    | ❌      | Neither has hr               |
| Alice + Summarizer | DOC-001 (eng)   | ❌      | Summarizer lacks engineering |
| Bob + Claude       | DOC-003 (admin) | ✅      | Both have admin              |

**Try it**: Select Alice, GPT-4, DOC-001 → Click "Delegate to Agent"

### Scenario 4: Agent as Capability Limiter

Bob has: `[finance, admin]` (2 departments)
Summarizer has: `[finance]` (1 department)

When Bob delegates to Summarizer:

- Effective permissions = `{finance, admin} ∩ {finance}` = `{finance}`
- Bob could access 3 document types alone
- With Summarizer, only 1 document type is accessible

**This demonstrates least privilege**: agents REDUCE effective permissions.

## Permission Reference

### Users

| User  | Departments          |
| ----- | -------------------- |
| Alice | engineering, finance |
| Bob   | finance, admin       |
| Carol | hr                   |

### Agents

| Agent      | Capabilities                    |
| ---------- | ------------------------------- |
| GPT-4      | engineering, finance            |
| Claude     | engineering, finance, admin, hr |
| Summarizer | finance                         |

### Documents

| ID      | Title               | Required Department   |
| ------- | ------------------- | --------------------- |
| DOC-001 | Engineering Roadmap | engineering           |
| DOC-002 | Q4 Financial Report | finance               |
| DOC-003 | Admin Policies      | admin                 |
| DOC-004 | HR Guidelines       | hr                    |
| DOC-005 | Budget Projections  | finance + engineering |
| DOC-006 | Compliance Audit    | admin + finance       |
| DOC-007 | All-Hands Summary   | (public)              |

## Zero Trust Principles Demonstrated

1. **Cryptographic Identity**: Each service has a SPIFFE ID (e.g., `spiffe://demo.example.com/user/alice`)

2. **Mutual TLS**: All service-to-service calls are mutually authenticated

3. **Policy-Based Control**: OPA evaluates every request against Rego policies

4. **Permission Intersection**: Delegated access = user ∩ agent permissions

5. **No Autonomous Agents**: Agents cannot access resources without user context

6. **Least Privilege**: Agents act as capability limiters, never privilege escalators

## Stopping the Demo

Press `Ctrl+C` in the terminal running `run-local.sh`.

## Troubleshooting

**Dashboard not responding?**

- Check if all services started: `curl http://localhost:8082/health`
- Restart services: Ctrl+C, then `./scripts/run-local.sh`

**Logs not updating?**

- Refresh the browser page
- Check `tmp/logs/` for service-specific logs

**OPA errors in logs?**

- Check `tmp/logs/opa-service.log` for policy evaluation errors
