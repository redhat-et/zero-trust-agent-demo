# SPIFFE/SPIRE Zero Trust Demo

An educational demonstration of **Zero Trust security principles** for AI agent systems using **SPIFFE/SPIRE** for workload identity and **Open Policy Agent (OPA)** for fine-grained access control.

## Overview

This demo showcases a document management system where:
- **Users** have department-based access rights (Engineering, Finance, Admin, HR)
- **AI Agents** have capability-based restrictions
- **Delegation** requires permission intersection (user AND agent must both have access)
- **Every request** is authenticated via mTLS and authorized via OPA policies

## Architecture

```text
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

### Option A: Mock Mode (Fastest Demo)

No SPIRE required. Uses mocked identities to demonstrate the concepts.

```bash
git clone https://github.com/hardwaylabs/spiffe-spire-demo.git
cd spiffe-spire-demo

./scripts/setup-kind.sh
kubectl apply -k deploy/k8s/overlays/mock
kubectl -n spiffe-demo wait --for=condition=ready pod --all --timeout=120s
open http://localhost:8080
```

### Option B: Real SPIRE Integration

Full SPIFFE/SPIRE integration with real X.509 SVIDs and mTLS.

```bash
git clone https://github.com/hardwaylabs/spiffe-spire-demo.git
cd spiffe-spire-demo

./scripts/setup-kind.sh
./scripts/setup-spire.sh
kubectl apply -k deploy/k8s/overlays/ghcr
kubectl apply -f deploy/spire/clusterspiffeids.yaml
kubectl -n spiffe-demo wait --for=condition=ready pod --all --timeout=120s
open http://localhost:8080
```

See [docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md) for all deployment options including local development.

## Demo Scenarios

### Users

| User  | Departments          | SPIFFE ID                              |
| ----- | -------------------- | -------------------------------------- |
| Alice | Engineering, Finance | `spiffe://demo.example.com/user/alice` |
| Bob   | Finance, Admin       | `spiffe://demo.example.com/user/bob`   |
| Carol | HR                   | `spiffe://demo.example.com/user/carol` |

### Agents

| Agent      | Capabilities         | SPIFFE ID                                    |
| ---------- | -------------------- | -------------------------------------------- |
| GPT-4      | Engineering, Finance | `spiffe://demo.example.com/agent/gpt4`       |
| Claude     | All departments      | `spiffe://demo.example.com/agent/claude`     |
| Summarizer | Finance only         | `spiffe://demo.example.com/agent/summarizer` |

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

## Documentation

See [docs/README.md](docs/README.md) for the full documentation index.

### User Documentation

| Document                                 | Description                                            |
| ---------------------------------------- | ------------------------------------------------------ |
| [Demo Guide](docs/DEMO_GUIDE.md)         | Step-by-step instructions for running the demo         |
| [Learning Guide](docs/LEARNING_GUIDE.md) | Deep dive into Zero Trust, SPIFFE/SPIRE, mTLS, and OPA |
| [API Testing](docs/API_TESTING.md)       | API endpoints and curl commands for testing            |
| [Architecture](docs/ARCHITECTURE.md)     | System design and component overview                   |

### Security & Operations

| Document                           | Description                                      |
| ---------------------------------- | ------------------------------------------------ |
| [Security](docs/SECURITY.md)       | Threat model, trust boundaries, incident response |
| [Operations](docs/OPERATIONS.md)   | Deployment, monitoring, troubleshooting runbook  |

### Architecture Decision Records

| ADR | Title |
| --- | ----- |
| [ADR-0001](docs/adr/0001-spiffe-spire-workload-identity.md) | SPIFFE/SPIRE for Workload Identity |
| [ADR-0002](docs/adr/0002-permission-intersection-delegation.md) | Permission Intersection for AI Agent Delegation |
| [ADR-0003](docs/adr/0003-opa-policy-evaluation.md) | OPA for Policy Evaluation |
| [ADR-0004](docs/adr/0004-kustomize-deployment-variants.md) | Kustomize for Deployment Variants |
| [ADR-0005](docs/adr/0005-separate-health-ports-mtls.md) | Separate Health Ports for mTLS Services |

### Additional Resources

| Document | Description |
| -------- | ----------- |
| [Contributing](CONTRIBUTING.md) | Guidelines for contributors |
| [OpenShift vs Kubernetes](docs/deployment/OPENSHIFT_VS_KUBERNETES.md) | Platform comparison |

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

```text
spiffe-spire-demo/
├── pkg/                    # Shared packages
│   ├── config/            # Viper configuration
│   ├── logger/            # slog-based colored logger
│   ├── metrics/           # Prometheus metrics
│   └── spiffe/            # SPIFFE workload client
├── opa-service/           # Policy evaluation service
├── document-service/      # Protected resource server
├── user-service/          # User workload simulation
├── agent-service/         # AI agent workload simulation
├── web-dashboard/         # Interactive demo UI
├── deploy/                # Deployment configurations
│   ├── kind/             # Kind cluster config
│   ├── k8s/              # Kustomize base and overlays
│   │   ├── base/         # Shared K8s resources
│   │   └── overlays/     # mock, local, ghcr, openshift
│   └── spire/            # SPIRE Helm values and registrations
├── docs/                  # Documentation
│   ├── adr/              # Architecture Decision Records
│   ├── deployment/       # Platform-specific guides
│   ├── dev/              # Development process docs
│   ├── ARCHITECTURE.md   # System design
│   ├── SECURITY.md       # Security documentation
│   └── OPERATIONS.md     # Operations runbook
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
