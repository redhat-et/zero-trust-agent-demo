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

We use [Kustomize](https://kustomize.io/) to manage different deployment modes. Each overlay provides a different configuration optimized for specific use cases.

### Deployment Modes Overview

| Mode          | Images      | SPIFFE     | Use Case                         |
| ------------- | ----------- | ---------- | -------------------------------- |
| **mock**      | ghcr.io     | Mocked     | Quick demo, no SPIRE required    |
| **local**     | localhost/* | Real SPIRE | Local development with Kind      |
| **ghcr**      | ghcr.io     | Real SPIRE | Production-like with SPIRE       |
| **openshift** | ghcr.io     | Real SPIRE | OpenShift with SCC and SELinux   |

### Option A: Mock Mode (Quickest Demo)

No SPIRE installation required. Uses mocked SPIFFE identities for demonstration.

**Prerequisites:** [Kind](https://kind.sigs.k8s.io/) and [kubectl](https://kubernetes.io/docs/tasks/tools/)

```bash
# Clone the repository
git clone https://github.com/hardwaylabs/spiffe-spire-demo.git
cd spiffe-spire-demo

# Create Kind cluster
./scripts/setup-kind.sh

# Deploy with mock overlay (no SPIRE needed)
kubectl apply -k deploy/k8s/overlays/mock

# Wait for pods to be ready
kubectl -n spiffe-demo wait --for=condition=ready pod --all --timeout=120s

# Open dashboard
open http://localhost:8080
```

### Option B: Local Mode (Development with SPIRE)

Build from source and deploy with real SPIFFE/SPIRE integration.

**Prerequisites:** [Kind](https://kind.sigs.k8s.io/), [kubectl](https://kubernetes.io/docs/tasks/tools/), [Go 1.21+](https://golang.org/dl/)

```bash
# Clone and build
git clone https://github.com/hardwaylabs/spiffe-spire-demo.git
cd spiffe-spire-demo
make build

# Create Kind cluster with SPIRE
./scripts/setup-kind.sh
./scripts/setup-spire.sh

# Build and load Docker images into Kind
./scripts/build-images.sh
./scripts/load-images.sh

# Deploy with local overlay (uses localhost/* images)
kubectl apply -k deploy/k8s/overlays/local

# Wait for pods and open dashboard
kubectl -n spiffe-demo wait --for=condition=ready pod --all --timeout=120s
open http://localhost:8080
```

### Option C: GHCR Mode (Production-like)

Uses pre-built images from GitHub Container Registry with real SPIRE.

```bash
# Clone the repository
git clone https://github.com/hardwaylabs/spiffe-spire-demo.git
cd spiffe-spire-demo

# Create Kind cluster with SPIRE
./scripts/setup-kind.sh
./scripts/setup-spire.sh

# Deploy with ghcr overlay (pulls from ghcr.io)
kubectl apply -k deploy/k8s/overlays/ghcr

# Wait for pods and open dashboard
kubectl -n spiffe-demo wait --for=condition=ready pod --all --timeout=120s
open http://localhost:8080
```

### Option D: Local Development (No Kubernetes)

Run services directly on your machine for rapid iteration.

```bash
# Clone and build
git clone https://github.com/hardwaylabs/spiffe-spire-demo.git
cd spiffe-spire-demo
make build

# Run locally (without Kubernetes)
./scripts/run-local.sh

# Open dashboard
open http://localhost:8080
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

### Option E: OpenShift (Production with SCC/SELinux)

Deploy to OpenShift with real SPIRE and proper Security Context Constraints.

**Prerequisites:** [oc CLI](https://docs.openshift.com/container-platform/latest/cli_reference/openshift_cli/getting-started-cli.html), [Helm](https://helm.sh/docs/intro/install/), cluster-admin access

```bash
# Clone the repository
git clone https://github.com/hardwaylabs/spiffe-spire-demo.git
cd spiffe-spire-demo

# Setup SPIRE on OpenShift (handles SCC and SELinux)
./scripts/setup-spire-openshift.sh

# Deploy the demo application (applies SCC after namespace is created)
./scripts/deploy-openshift.sh

# Get the dashboard URL (Route is created automatically)
oc get route web-dashboard -n spiffe-demo -o jsonpath='https://{.spec.host}{"\n"}'
```

**OpenShift-specific features:**
- Creates an HTTPS Route for the web dashboard (edge TLS termination)
- Grants `privileged` SCC to SPIRE agent and CSI driver
- Grants `anyuid` SCC to SPIRE server
- Sets SELinux `spc_t` context on workloads to allow CSI socket access
- Sets `pod-security.kubernetes.io/enforce: privileged` on demo namespace

### Switching Between Modes

```bash
# Delete existing deployment
kubectl delete -k deploy/k8s/overlays/mock  # or local/ghcr

# Deploy with different overlay
kubectl apply -k deploy/k8s/overlays/local
```

### Watch Logs (Option D only)

In a separate terminal:

```bash
tail -f tmp/logs/*.log
```

### Kustomize Directory Structure

```text
deploy/k8s/
├── base/                    # Shared resources
│   ├── kustomization.yaml
│   ├── namespace.yaml
│   ├── services.yaml
│   ├── deployments.yaml
│   └── opa-policies-configmap.yaml
└── overlays/
    ├── mock/               # ghcr.io images, MOCK_SPIFFE=true
    ├── local/              # localhost/* images, MOCK_SPIFFE=false, SPIRE
    ├── ghcr/               # ghcr.io images, MOCK_SPIFFE=false, SPIRE
    └── openshift/          # ghcr.io images, SPIRE, SCC/SELinux fixes
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

## Observability

### Prometheus Metrics

All services expose Prometheus metrics on their health port:

| Service          | Metrics URL                      |
| ---------------- | -------------------------------- |
| user-service     | `http://localhost:8182/metrics`  |
| agent-service    | `http://localhost:8183/metrics`  |
| document-service | `http://localhost:8184/metrics`  |
| opa-service      | `http://localhost:8185/metrics`  |
| web-dashboard    | `http://localhost:8080/metrics`  |

**Available metrics:**
- `spiffe_demo_authorization_decisions_total` - Allow/deny counts by service
- `spiffe_demo_authorization_duration_seconds` - OPA policy evaluation latency
- `spiffe_demo_delegations_total` - Delegation attempts by user/agent

> **Note:** Metrics only appear after activity. Try some access requests first, then check metrics.

**Example:**
```bash
curl http://localhost:8184/metrics | grep spiffe_demo
```

### Structured JSON Logging

For production environments or log aggregation, enable JSON logging:

```bash
SPIFFE_DEMO_LOG_FORMAT=json ./scripts/run-local.sh
```

**JSON log format:**
```json
{
  "time": "2026-01-23T10:00:00Z",
  "level": "INFO",
  "msg": "Authorization decision",
  "component": "document-service",
  "spiffe_id": "spiffe://demo.example.com/user/alice",
  "document_id": "DOC-001"
}
```

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

**OpenShift pods stuck at ContainerCreating?**

- Check if SPIRE components are running: `oc get pods -n spire-system`
- Verify SCC grants: `oc get scc privileged -o yaml | grep spiffe-demo`
- Check for SELinux denials: `oc debug node/<node-name> -- chroot /host ausearch -m AVC`
- Redeploy with SELinux fix: `oc delete -k deploy/k8s/overlays/openshift && oc apply -k deploy/k8s/overlays/openshift`

**OpenShift socket permission denied?**

- This is usually SELinux blocking access to CSI-mounted sockets
- The OpenShift overlay sets SELinux `spc_t` context on workloads to allow CSI socket access
- Ensure the `privileged` SCC is granted to the default service account: `oc adm policy add-scc-to-user privileged -z default -n spiffe-demo`
- Re-run the setup script: `./scripts/setup-spire-openshift.sh`
