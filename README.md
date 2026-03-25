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
│     :8080       │     │     :8080       │     │     :8080       │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                        ┌─────────────────┐              │
                        │  OPA Service    │◀─────────────┤
                        │     :8080       │              │
                        └────────┬────────┘              │
                                 │                       │
                        ┌────────▼────────┐              │
                        │ Document Service│◀─────────────┘
                        │     :8080       │
                        └─────────────────┘

┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Agent (JWT)    │────▶│  Credential     │────▶│  AWS STS        │
│                 │     │  Gateway :8080  │     │  (AssumeRole)   │
└─────────────────┘     └────────┬────────┘     └────────┬────────┘
                                 │                       │
                        ┌────────▼────────┐     ┌────────▼────────┐
                        │  OPA Service    │     │  S3 (scoped)    │
                        └─────────────────┘     └─────────────────┘
```

## Quick Start

### Option A: Mock Mode (Fastest Demo)

No SPIRE required. Uses mocked identities to demonstrate the concepts.

```bash
git clone https://github.com/redhat-et/zero-trust-agent-demo.git
cd zero-trust-agent-demo

./scripts/setup-kind.sh
kubectl apply -k deploy/k8s/overlays/mock
kubectl -n spiffe-demo wait --for=condition=ready pod --all --timeout=120s
open http://localhost:8080
```

### Option B: Real SPIRE Integration

Full SPIFFE/SPIRE integration with real X.509 SVIDs and mTLS.

```bash
git clone https://github.com/redhat-et/zero-trust-agent-demo.git
cd zero-trust-agent-demo

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

### Agents (dynamically discovered)

Agents are discovered from Kagenti AgentCard CRs. Same agent image
can be deployed multiple times with different names and OPA scopes.
Naming scheme: `{function}-{scope}`.

| Agent | Scope | Description |
| ----- | ----- | ----------- |
| summarizer-hr | hr | HR document summarizer |
| summarizer-tech | finance, engineering | Technical document summarizer |
| reviewer-ops | engineering, admin | Operations document reviewer |
| reviewer-general | all | General document reviewer |

See `docs/deployment/AGENT_DEPLOYER_GUIDE.md` for the full agent
deployment workflow.

### Key Scenarios

1. **Direct User Access**: Alice accesses Engineering Roadmap → ✅ ALLOWED
2. **Agent Without Delegation**: reviewer-general accesses Finance Report → ❌ DENIED (no user context)
3. **Delegated Access**: Alice delegates to summarizer-tech for Engineering doc → ✅ ALLOWED
4. **Permission Reduction**: Alice delegates to summarizer-hr for Engineering doc → ❌ DENIED (summarizer-hr lacks engineering)
5. **Cross-scope**: Carol delegates to summarizer-hr for HR doc → ✅ ALLOWED (both have hr)

### Credential Gateway (AWS S3)

The credential gateway extends the permission intersection model to external services.
It translates JWT delegation claims into scoped AWS STS credentials:

```text
Effective S3 Access = User Departments ∩ Agent Capabilities → STS Session Policy
```

| Scenario | Intersection | S3 Prefixes Accessible |
| -------- | ------------ | ---------------------- |
| Alice + summarizer-tech | {engineering, finance} | `engineering/*, finance/*` |
| Alice + summarizer-hr | {} (empty) | None (403 Denied) |
| Carol + summarizer-hr | {hr} | `hr/*` |
| Bob + reviewer-ops | {admin} | `admin/*` |

Run the interactive demo:

```bash
oc port-forward -n spiffe-demo svc/credential-gateway 8090:8080 &
./scripts/demo-credential-gateway.sh
```

## Zero Trust Principles

1. **Cryptographic Workload Identity**: SPIFFE IDs backed by X.509 certificates
2. **Verified Workload Identity**: Every service-to-service call carries cryptographic identity proof (mTLS or signed JWT)
3. **Policy-Based Access Control**: OPA evaluates Rego policies on every request
4. **Permission Intersection**: Agent access = User permissions ∩ Agent capabilities
5. **Agents Cannot Act Autonomously**: Agents MUST have user delegation context
6. **Short-Lived Credentials**: SVIDs have 1-hour TTLs and auto-rotate
7. **Scoped External Credentials**: AWS STS session policies enforce permission intersection natively

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

| Document                         | Description                                       |
| -------------------------------- | ------------------------------------------------- |
| [Security](docs/SECURITY.md)     | Threat model, trust boundaries, incident response |
| [Operations](docs/OPERATIONS.md) | Deployment, monitoring, troubleshooting runbook   |

### Architecture Decision Records

| ADR                                                             | Title                                           |
| --------------------------------------------------------------- | ----------------------------------------------- |
| [ADR-0001](docs/adr/0001-spiffe-spire-workload-identity.md)     | SPIFFE/SPIRE for Workload Identity              |
| [ADR-0002](docs/adr/0002-permission-intersection-delegation.md) | Permission Intersection for AI Agent Delegation |
| [ADR-0003](docs/adr/0003-opa-policy-evaluation.md)              | OPA for Policy Evaluation                       |
| [ADR-0004](docs/adr/0004-kustomize-deployment-variants.md)      | Kustomize for Deployment Variants               |
| [ADR-0005](docs/adr/0005-separate-health-ports-mtls.md)         | Separate Health Ports for mTLS Services         |
| [ADR-0006](docs/adr/0006-s3-document-storage.md)                | S3 Document Storage                             |
| [ADR-0009](docs/adr/0009-otel-token-viz.md)                     | OpenTelemetry Token Visualization               |
| [ADR-0010](docs/adr/0010-act-claim-chaining.md)                 | RFC 8693 Act Claim Chaining                     |

### Additional Resources

| Document                                                              | Description                 |
| --------------------------------------------------------------------- | --------------------------- |
| [Contributing](CONTRIBUTING.md)                                       | Guidelines for contributors |
| [OpenShift vs Kubernetes](docs/deployment/OPENSHIFT_VS_KUBERNETES.md) | Platform comparison         |

## Development

Want to modify the code? See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Build from Source

```bash
git clone https://github.com/redhat-et/zero-trust-agent-demo.git
cd zero-trust-agent-demo

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
zero-trust-agent-demo/
├── pkg/                    # Shared packages
│   ├── config/            # Viper configuration
│   ├── logger/            # slog-based colored logger
│   ├── metrics/           # Prometheus metrics
│   └── spiffe/            # SPIFFE workload client
├── opa-service/           # Policy evaluation service
├── document-service/      # Protected resource server
├── user-service/          # User workload simulation
├── agent-service/         # Agent gateway: discovery + A2A invoke
├── web-dashboard/         # Interactive demo UI
├── credential-gateway/    # JWT → scoped AWS credentials
├── kagenti-summarizer/    # Python A2A summarizer agent
├── kagenti-reviewer/      # Python A2A reviewer agent
├── sample-documents/      # Markdown docs with YAML front matter
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

- **Languages**: Go 1.25 (infrastructure services), Python 3.12 (A2A agents)
- **CLI/Config**: Cobra + Viper
- **Logging**: `log/slog` with colored output
- **Policy Engine**: Open Policy Agent (OPA) with Rego
- **Identity**: SPIFFE/SPIRE (mock mode for local dev)
- **Agent Protocol**: A2A (Google a2a-python SDK)
- **Agent Lifecycle**: Kagenti operator (AgentCard discovery, SPIFFE binding)
- **Deployment**: Kind (local), OpenShift (production)
- **CI/CD**: GitHub Actions with multi-arch builds (amd64/arm64)
- **Styling**: Red Hat Design System

## License

[Apache License 2.0](LICENSE)
