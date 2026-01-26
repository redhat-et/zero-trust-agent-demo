# CLAUDE.md - Project Guide for AI Assistants

## Project Overview

This is a **SPIFFE/SPIRE Zero Trust Demo** application that demonstrates workload identity and policy-based access control for AI agents. It showcases how to implement the principle of least privilege when AI agents act on behalf of users.

### Core Concept: Permission Intersection

When a user delegates access to an AI agent:
```
Effective Permissions = User Departments ∩ Agent Capabilities
```

This ensures agents can never exceed the permissions of either the user OR the agent's configured capabilities.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Web Dashboard  │────▶│  User Service   │────▶│ Agent Service   │
│    :8080        │     │    :8082        │     │    :8083        │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                        ┌─────────────────┐     ┌────────▼────────┐
                        │   OPA Service   │◀────│Document Service │
                        │    :8085        │     │    :8084        │
                        └─────────────────┘     └─────────────────┘
```

### Services

| Service | Port | Description |
|---------|------|-------------|
| web-dashboard | 8080 | Interactive UI for demo |
| user-service | 8082 | User management, direct access, delegation |
| agent-service | 8083 | AI agent management, delegated access |
| document-service | 8084 | Protected documents with OPA authorization |
| opa-service | 8085 | Policy evaluation engine (Rego policies) |

## Quick Start

```bash
# Build all services
make build

# Run locally (all services)
./scripts/run-local.sh

# Open dashboard
open http://localhost:8080

# Watch logs
tail -f tmp/logs/*.log
```

## Project Structure

```
spiffe-spire-demo/
├── pkg/                    # Shared packages
│   ├── config/            # Viper configuration
│   ├── logger/            # Colored slog wrapper
│   ├── metrics/           # Prometheus metrics
│   └── spiffe/            # SPIFFE workload client
├── web-dashboard/         # Dashboard service
│   ├── cmd/               # Cobra commands
│   └── internal/assets/   # Static files & templates
├── user-service/          # User service
│   ├── cmd/
│   └── internal/store/    # In-memory user store
├── agent-service/         # Agent service
│   ├── cmd/
│   └── internal/store/    # In-memory agent store
├── document-service/      # Document service
│   ├── cmd/
│   └── internal/store/    # In-memory document store
├── opa-service/           # OPA policy service
│   ├── cmd/
│   └── policies/          # Rego policy files
├── deploy/                # Deployment configs
│   ├── k8s/              # Kubernetes manifests
│   └── kind/             # Kind cluster config
├── docs/                  # Documentation
│   ├── adr/              # Architecture Decision Records
│   ├── deployment/       # Platform-specific guides
│   ├── dev/              # Development process docs
│   ├── ARCHITECTURE.md   # System design
│   ├── SECURITY.md       # Security documentation
│   └── OPERATIONS.md     # Operations runbook
├── scripts/               # Helper scripts
└── tmp/logs/             # Runtime logs (gitignored)
```

## Build Commands

```bash
make build          # Build all services to bin/
make clean          # Remove build artifacts
make run-local      # Build and run locally
make test           # Run tests
```

## Demo Scenario

### Users
- **Alice**: engineering, finance
- **Bob**: finance, admin
- **Carol**: hr

### AI Agents
- **GPT-4**: engineering, finance
- **Claude**: engineering, finance, admin, hr (unrestricted)
- **Summarizer**: finance (highly restricted)

### Documents
- DOC-001: Engineering Roadmap (engineering)
- DOC-002: Q4 Financial Report (finance)
- DOC-003: Admin Policies (admin)
- DOC-004: HR Guidelines (hr)
- DOC-005: Budget Projections (finance + engineering)
- DOC-006: Compliance Audit (admin + finance)
- DOC-007: All-Hands Summary (public)

### Example Flows

1. **Direct Access**: Alice → DOC-001 ✓ (Alice has engineering)
2. **Delegated Access**: Alice → GPT-4 → DOC-001 ✓ (both have engineering)
3. **Denied Delegation**: Alice → GPT-4 → DOC-004 ✗ (GPT-4 lacks hr)
4. **Agent Without User**: GPT-4 → DOC-001 ✗ (agents require delegation)

## OPA Policies

Policies are in `opa-service/policies/`:

- `user_permissions.rego` - User-to-department mappings
- `agent_permissions.rego` - Agent capability restrictions
- `delegation.rego` - Main authorization logic with permission intersection

### Policy Evaluation Endpoint

```bash
curl -X POST http://localhost:8085/v1/data/demo/authorization/decision \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "caller_spiffe_id": "spiffe://demo.example.com/agent/gpt4",
      "document_id": "DOC-001",
      "delegation": {
        "user_spiffe_id": "spiffe://demo.example.com/user/alice",
        "agent_spiffe_id": "spiffe://demo.example.com/agent/gpt4"
      }
    }
  }'
```

## Configuration

Services use Viper for configuration. Options can be set via:
1. Config file (e.g., `config.yaml`)
2. Environment variables (prefix: service name)
3. Command-line flags

Common flags:
- `--host` - Bind address (default: 0.0.0.0)
- `--port` - Port number (service-specific defaults)

## Key Technologies

- **Go 1.21+** - All services
- **Cobra/Viper** - CLI and configuration
- **log/slog** - Structured logging with colors
- **OPA (Open Policy Agent)** - Policy evaluation
- **SPIFFE/SPIRE** - Workload identity (mock mode for local dev)
- **SSE (Server-Sent Events)** - Real-time dashboard updates

## Development Notes

### Adding a New Document

Edit `document-service/internal/store/documents.go` and `opa-service/policies/delegation.rego` (documents map).

### Adding a New User/Agent

Edit respective files in `*-service/internal/store/` and corresponding Rego policy files.

### Modifying Policies

1. Edit `.rego` files in `opa-service/policies/`
2. Update `deploy/k8s/opa-policies-configmap.yaml` to match
3. Rebuild: `make build`

### Logging

All services use the shared logger from `pkg/logger/`. Components are color-coded:
- SPIRE-SERVER: Green
- USER-SERVICE: Blue
- AGENT-SERVICE: Magenta
- DOC-SERVICE: Yellow
- OPA-SERVICE: Cyan
- DASHBOARD: White

## Testing Endpoints

```bash
# Health checks
curl http://localhost:8082/health  # user-service
curl http://localhost:8083/health  # agent-service
curl http://localhost:8084/health  # document-service
curl http://localhost:8085/health  # opa-service

# List resources
curl http://localhost:8082/users
curl http://localhost:8083/agents
curl http://localhost:8084/documents

# Direct user access
curl -X POST http://localhost:8082/users/alice/access \
  -H "Content-Type: application/json" \
  -d '{"document_id": "DOC-001"}'

# Delegated agent access
curl -X POST http://localhost:8083/agents/gpt4/access \
  -H "Content-Type: application/json" \
  -d '{"document_id": "DOC-001", "user_spiffe_id": "spiffe://demo.example.com/user/alice"}'
```

## Kubernetes Deployment

```bash
# Create Kind cluster
./scripts/setup-kind.sh

# Deploy to Kind
./scripts/deploy-app.sh

# Port forward for local access
./scripts/port-forward.sh
```

## Zero Trust Principles Demonstrated

1. **Cryptographic Workload Identity** - SPIFFE IDs backed by X.509 certificates
2. **Mutual TLS** - All service-to-service communication authenticated
3. **Policy-Based Access Control** - OPA evaluates every request
4. **Permission Intersection** - Agents limited by both user AND agent permissions
5. **No Autonomous Agent Access** - Agents require user delegation context
6. **Short-Lived Credentials** - SVIDs with 1-hour TTL (in production)
