# Architecture

## Overview

This is a **SPIFFE/SPIRE Zero Trust Demo** that demonstrates workload
identity and policy-based access control for AI agents. It showcases
the principle of least privilege when AI agents act on behalf of users.

### Core concept: permission intersection

```text
Effective Permissions = User Departments ∩ Agent Capabilities
```

Agents can never exceed the permissions of either the user OR the
agent's configured OPA capabilities.

### Target audience

- Developers building AI agent systems with Zero Trust architecture
- Security engineers evaluating workload identity solutions
- Platform engineers implementing SPIFFE/SPIRE in Kubernetes

### Related documents

| Document | Description |
| -------- | ----------- |
| [Demo Scenarios](DEMO_SCENARIOS.md) | Users, agents, permission matrices, walkthrough scenarios |
| [Policy Reference](POLICY_REFERENCE.md) | OPA policy design, modules, examples, testing |
| [Agent Deployer Guide](deployment/AGENT_DEPLOYER_GUIDE.md) | How to deploy new agents with naming scheme |
| [Demo Guide](DEMO_GUIDE.md) | Step-by-step instructions for running the demo |
| [Security](SECURITY.md) | Threat model, trust boundaries |

## System architecture

```text
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Web Dashboard  │────▶│  User Service   │────▶│  Agent Service  │
│    :8080        │     │    :8080        │     │  (gateway)      │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                        ┌─────────────────┐     ┌────────▼────────┐
                        │   OPA Service   │◀────│Document Service │
                        │    :8080        │     │    :8080        │
                        └─────────────────┘     └─────────────────┘

Agent Service discovers A2A agents from Kagenti AgentCard CRs:

┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ Agent Service   │────▶│  AgentCard CRs  │     │  A2A Agents     │
│ (discovery)     │     │  (Kagenti)      │     │ (summarizer-*,  │
└────────┬────────┘     └─────────────────┘     │  reviewer-*)    │
         │                                      └─────────────────┘
         └──────────────────────────────────────────────▶│
                        /agents/{id}/invoke              │
```

### Infrastructure services (Go)

| Service | Port | Description |
| ------- | ---- | ----------- |
| web-dashboard | 8080 | Interactive UI, SSE events, OIDC login |
| user-service | 8080 | User management, direct access, delegation |
| agent-service | 8080 | Agent gateway: discovery, delegation, A2A invoke |
| document-service | 8080 | Protected documents with OPA authorization |
| opa-service | 8080 | Policy evaluation engine (Rego policies) |
| credential-gateway | 8080 | JWT to scoped AWS STS credentials, S3 proxy |

### A2A agents (Python, dynamically discovered)

Agents follow the `{function}-{scope}` naming scheme. Same agent
image can be deployed multiple times with different names and OPA
scopes. Agents are auth-unaware — OPA handles permissions.

| Agent | Scope | Description |
| ----- | ----- | ----------- |
| summarizer-hr | hr | HR document summarizer |
| summarizer-tech | finance, engineering | Technical document summarizer |
| reviewer-ops | engineering, admin | Operations document reviewer |
| reviewer-general | all | General document reviewer |

See [Agent Deployer Guide](deployment/AGENT_DEPLOYER_GUIDE.md) for
the deployment workflow.

## Component details

### Agent service (gateway)

The agent-service acts as a gateway for all agent operations:

1. **Discovery**: Lists AgentCard CRs via K8s API, registers agents
   in memory. Reads `zero-trust-demo/description` annotation for
   per-deployment descriptions.
2. **Delegation**: Validates user delegation context (no autonomous
   agent access), forwards to document-service for OPA authorization.
3. **Invoke**: After authorization, constructs A2A message with
   `s3_url` from document metadata and invokes agent via A2A protocol.

Endpoints:

| Endpoint | Method | Description |
| -------- | ------ | ----------- |
| `/agents` | GET | List discovered agents |
| `/agents/{id}` | GET | Get agent details |
| `/agents/{id}/access` | POST | Check delegated access |
| `/agents/{id}/invoke` | POST | Invoke agent via A2A |

### Document service

Serves document access requests. Verifies caller identity (mTLS or
JWT), queries OPA for authorization, returns document content or 403.

Documents include `s3_url` field pointing to S3 storage for
credential gateway integration.

### OPA service

Evaluates Rego policies. Three policy modules:

- `user_permissions.rego` — user-to-department mappings
- `agent_permissions.rego` — agent capability restrictions
- `delegation.rego` — permission intersection logic

See [Policy Reference](POLICY_REFERENCE.md) for details.

### Credential gateway

Extends the permission intersection model to AWS S3:

1. Receives JWT with delegation context
2. Queries OPA `proxy_decision` for per-object access control
3. Calls STS AssumeRole with session policy scoped to allowed
   departments
4. Proxies S3 GetObject with scoped credentials

### Web dashboard

Single-page UI that routes all operations through backend services:

- `/api/access-direct` → user-service (direct access)
- `/api/access-delegated` → user-service → agent-service (delegation)
- `/api/invoke` → agent-service (A2A agent invocation)
- `/events` → SSE stream for real-time console output

Supports OIDC login via Keycloak (AuthBridge overlay).

## Deployment modes

The project supports multiple deployment modes via Kustomize overlays.

| Mode | SPIFFE | OIDC | Agents | Use case |
| ---- | ------ | ---- | ------ | -------- |
| mock | Mocked | No | Static | Quick demo, no SPIRE required |
| local | Real | No | Static | Local dev with Kind + SPIRE |
| ghcr | Real | No | Static | Pre-built images + SPIRE |
| authbridge | Real | Yes | Static | OIDC with Keycloak |
| openshift-ai-agents | Real | Yes | Discovered | Full demo on OpenShift + Kagenti |

### AuthBridge (mTLS + OIDC + token exchange)

Adds Keycloak for user authentication, Envoy sidecar on
agent-service with ext-proc for RFC 8693 token exchange, and JWT
validation in document-service.

```text
Browser → Dashboard → User Service → Agent Service (Envoy + ext-proc)
                                            ↓ token exchange
                                      Document Service (JWT validation)
                                            ↓ mTLS
                                      OPA Service
```

## SPIFFE identity model

SPIRE issues one X.509-SVID per service (not per user/agent):

| Service | SPIFFE ID |
| ------- | --------- |
| web-dashboard | `spiffe://demo.example.com/service/web-dashboard` |
| user-service | `spiffe://demo.example.com/service/user-service` |
| agent-service | `spiffe://demo.example.com/service/agent-service` |
| document-service | `spiffe://demo.example.com/service/document-service` |
| opa-service | `spiffe://demo.example.com/service/opa-service` |

User and agent SPIFFE IDs (`spiffe://demo.example.com/user/alice`,
`spiffe://demo.example.com/agent/summarizer-tech`) are logical
identifiers carried in request bodies and headers, not X.509-backed
SVIDs. For Kagenti-deployed agents, the operator binds real SPIFFE
identities via the AgentCard CR.

## API endpoints

| Service | Endpoint | Description |
| ------- | -------- | ----------- |
| web-dashboard | `GET /` | Dashboard UI |
| web-dashboard | `GET /events` | SSE stream |
| web-dashboard | `POST /api/access-direct` | Direct user access |
| web-dashboard | `POST /api/access-delegated` | Delegated access |
| web-dashboard | `POST /api/invoke` | Invoke agent via gateway |
| user-service | `GET /users` | List users |
| user-service | `POST /access` | Direct document access |
| user-service | `POST /delegate` | Delegate to agent |
| agent-service | `GET /agents` | List discovered agents |
| agent-service | `POST /agents/{id}/invoke` | Invoke A2A agent |
| document-service | `GET /documents` | List documents |
| document-service | `POST /access` | Access document |
| opa-service | `POST /v1/data/demo/authorization/decision` | Policy eval |
| credential-gateway | `POST /credentials` | STS credentials |
| credential-gateway | `GET /s3-proxy/{key}` | S3 proxy with OPA |

## Security standards

The AuthBridge token exchange flow is built on these standards:

| RFC | Title | Used for |
| --- | ----- | -------- |
| RFC 7515 | JSON Web Signature | JWT signature verification via JWKS |
| RFC 7519 | JSON Web Token | Access token format |
| RFC 8693 | OAuth 2.0 Token Exchange | Ext-proc token swap |
| RFC 8705 | OAuth 2.0 Mutual-TLS | SPIFFE SVID client auth |
| RFC 9068 | JWT Profile for Access Tokens | Standardized JWT structure |

## Zero Trust principles demonstrated

1. **Cryptographic Workload Identity** — SPIFFE IDs backed by X.509
   certificates, not shared secrets
2. **Verified Workload Identity** — Every service-to-service call
   carries cryptographic identity proof (mTLS or signed JWT)
3. **Policy-Based Access Control** — OPA evaluates every request
   against Rego policies
4. **Permission Intersection** — Agents limited by both user AND
   agent permissions
5. **No Autonomous Agent Access** — Agents require user delegation
   context
6. **Short-Lived Credentials** — SVIDs with 1-hour TTL, auto-rotate
7. **Scoped External Credentials** — AWS STS session policies
   enforce permission intersection natively
