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

### Local Development

```bash
# Build all services
make build

# Run all services locally
make run-local

# Open dashboard
open http://localhost:8080
```

### Kubernetes (Kind)

```bash
# Create Kind cluster
make setup-kind

# Build and load Docker images
make docker-build
make docker-load

# Deploy to cluster
make deploy-k8s

# Access dashboard
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

## Project Structure

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

## Make Commands

```bash
make build          # Build all services
make run-local      # Run services locally
make test           # Run tests
make test-policies  # Run OPA policy tests
make setup-kind     # Create Kind cluster
make deploy-k8s     # Deploy to Kubernetes
make help           # Show all commands
```

## Technology Stack

- **Language**: Go 1.21+
- **CLI/Config**: Cobra + Viper
- **Logging**: `log/slog` with colored output
- **Policy Engine**: Open Policy Agent (OPA) with Rego
- **Identity**: SPIFFE/SPIRE (mock mode for local dev)
- **Deployment**: Kind (Kubernetes in Docker)
- **Styling**: Red Hat Design System

## License

MIT
