# SPIFFE/SPIRE Zero Trust Demo

An educational demonstration of **Zero Trust security principles** for AI agent systems using **SPIFFE/SPIRE** for workload identity and **Open Policy Agent (OPA)** for fine-grained access control.

## Overview

This demo showcases a document management system where:
- **Users** have department-based access rights (Engineering, Finance, Admin, HR)
- **AI Agents** have capability-based restrictions
- **Delegation** requires permission intersection (user AND agent must both have access)
- **Every request** is authenticated via mTLS and authorized via OPA policies

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Web Dashboard  │────▶│  User Service   │────▶│  Agent Service  │
│     :8080       │     │     :8082       │     │     :8083       │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                        ┌─────────────────┐              │
                        │  OPA Service    │◀─────────────┘
                        │     :8085       │              │
                        └────────┬────────┘              │
                                 │                       │
                        ┌────────▼────────┐              │
                        │ Document Service│◀─────────────┘
                        │     :8084       │
                        └─────────────────┘
```

## Quick Start

### Option A: Zero-Clone (Fastest)

No need to clone the repository. Just need [Kind](https://kind.sigs.k8s.io/) and [kubectl](https://kubernetes.io/docs/tasks/tools/).

```bash
# Create Kind cluster
curl -sL https://raw.githubusercontent.com/hardwaylabs/spiffe-spire-demo/main/deploy/kind/cluster.yaml | kind create cluster --config /dev/stdin

# Deploy the application
kubectl apply -f https://raw.githubusercontent.com/hardwaylabs/spiffe-spire-demo/main/deploy/k8s/namespace.yaml
kubectl apply -f https://raw.githubusercontent.com/hardwaylabs/spiffe-spire-demo/main/deploy/k8s/opa-policies-configmap.yaml
kubectl apply -f https://raw.githubusercontent.com/hardwaylabs/spiffe-spire-demo/main/deploy/k8s/deployments.yaml

# Wait for pods and open dashboard
kubectl -n spiffe-demo wait --for=condition=ready pod --all --timeout=120s
open http://localhost:8080
```

### Option B: Clone and Deploy

Clone the repo to explore the code, using pre-built images from GitHub Container Registry.

```bash
git clone https://github.com/hardwaylabs/spiffe-spire-demo.git
cd spiffe-spire-demo

./scripts/setup-kind.sh
kubectl apply -f deploy/k8s/
kubectl -n spiffe-demo wait --for=condition=ready pod --all --timeout=120s
open http://localhost:8080
```

## Demo Scenarios

### Users
| User  | Departments          | SPIFFE ID |
|-------|---------------------|-----------|
| Alice | Engineering, Finance | `spiffe://demo.example.com/user/alice` |
| Bob   | Finance, Admin       | `spiffe://demo.example.com/user/bob` |
| Carol | HR                   | `spiffe://demo.example.com/user/carol` |

### Agents
| Agent      | Capabilities                    | SPIFFE ID |
|------------|--------------------------------|-----------|
| GPT-4      | Engineering, Finance           | `spiffe://demo.example.com/agent/gpt4` |
| Claude     | All departments                | `spiffe://demo.example.com/agent/claude` |
| Summarizer | Finance only                   | `spiffe://demo.example.com/agent/summarizer` |

### Key Scenarios

1. **Direct User Access**: Alice accesses Engineering Roadmap → ✅ ALLOWED
2. **Agent Without Delegation**: GPT-4 accesses Finance Report → ❌ DENIED (no user context)
3. **Delegated Access**: Alice delegates to GPT-4 for Engineering doc → ✅ ALLOWED
4. **Permission Reduction**: Bob (Admin) delegates to Summarizer (Finance only) for Admin doc → ❌ DENIED

## Zero Trust Principles

1. **Cryptographic Workload Identity**: SPIFFE IDs backed by X.509 certificates
2. **Mutual TLS (mTLS)**: All service-to-service communication is mutually authenticated
3. **Policy-Based Access Control**: OPA evaluates Rego policies on every request
4. **Permission Intersection**: Agent access = User permissions ∩ Agent capabilities
5. **Agents Cannot Act Autonomously**: Agents MUST have user delegation context
6. **Short-Lived Credentials**: SVIDs have 1-hour TTLs and auto-rotate

## Development

Want to modify the code? See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Build from Source

```bash
git clone https://github.com/hardwaylabs/spiffe-spire-demo.git
cd spiffe-spire-demo

# Build all services
make build

# Run locally (without Kubernetes)
./scripts/run-local.sh

# Open dashboard
open http://localhost:8080
```

### Make Commands

```bash
make build          # Build all services
make run-local      # Run services locally
make test           # Run tests
make test-policies  # Run OPA policy tests
make setup-kind     # Create Kind cluster
make deploy-k8s     # Deploy to Kubernetes
make help           # Show all commands
```

### Project Structure

```
spiffe-spire-demo/
├── pkg/                    # Shared packages
│   ├── config/            # Viper configuration
│   ├── logger/            # slog-based colored logger
│   └── spiffe/            # SPIFFE workload client
├── opa-service/           # Policy evaluation service
├── document-service/      # Protected resource server
├── user-service/          # User workload simulation
├── agent-service/         # AI agent workload simulation
├── web-dashboard/         # Interactive demo UI
├── deploy/                # Kubernetes manifests
│   ├── kind/             # Kind cluster config
│   └── k8s/              # K8s deployments
├── scripts/              # Deployment scripts
└── Makefile              # Build and run commands
```

## Technology Stack

- **Language**: Go 1.25
- **CLI/Config**: Cobra + Viper
- **Logging**: `log/slog` with colored output
- **Policy Engine**: Open Policy Agent (OPA) with Rego
- **Identity**: SPIFFE/SPIRE (mock mode for local dev)
- **Deployment**: Kind (Kubernetes in Docker)
- **CI/CD**: GitHub Actions with multi-arch builds (amd64/arm64)
- **Styling**: Red Hat Design System

## License

[MIT](LICENSE)
