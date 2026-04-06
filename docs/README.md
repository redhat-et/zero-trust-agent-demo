# Documentation

This directory contains documentation for the SPIFFE/SPIRE Zero Trust
Demo — a reference implementation of workload identity and policy-based
access control for AI agents on OpenShift.

## Reading guide for the blog series

If you arrived here from the
[Zero Trust for AI agents][blog-series] blog series, start with the
documents mapped to each post.

### Part 1 — Why delegation beats impersonation

The permission intersection pattern and how OPA enforces it.

| Document | What you'll find |
| -------- | ---------------- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design and permission intersection model |
| [POLICY_REFERENCE.md](POLICY_REFERENCE.md) | OPA/Rego policy modules, examples, and testing |
| [ADR-0002](adr/0002-permission-intersection-delegation.md) | Decision record: why permission intersection |
| [ADR-0003](adr/0003-opa-policy-evaluation.md) | Decision record: why OPA for policy evaluation |
| [DEMO_SCENARIOS.md](DEMO_SCENARIOS.md) | Users, agents, documents, and worked examples |

### Part 2 — Wiring Zero Trust identity

SPIFFE workload identity, RFC 8693 token exchange, and Kagenti agent
discovery.

| Document | What you'll find |
| -------- | ---------------- |
| [SECURITY.md](SECURITY.md) | Trust boundaries, threat model, two-layer identity |
| [AUTHBRIDGE.md](AUTHBRIDGE.md) | AuthBridge architecture and JWT validation |
| [KEYCLOAK_TOKEN_EXCHANGE_SETUP.md](KEYCLOAK_TOKEN_EXCHANGE_SETUP.md) | Keycloak OAuth2 configuration for RFC 8693 |
| [DIAGRAMS.md](DIAGRAMS.md) | Token exchange and delegation flow diagrams |
| [ADR-0001](adr/0001-spiffe-spire-workload-identity.md) | Decision record: why SPIFFE/SPIRE |
| [ADR-0005](adr/0005-separate-health-ports-mtls.md) | Decision record: separate health ports for mTLS |
| [deployment/KAGENTI_ON_OPENSHIFT.md](deployment/KAGENTI_ON_OPENSHIFT.md) | Kagenti operator setup on OpenShift |

### Part 3 — The last mile

Credential gateway: translating Zero Trust tokens into real-world
credentials.

| Document | What you'll find |
| -------- | ---------------- |
| [ADR-0006](adr/0006-s3-document-storage.md) | Decision record: S3 for document storage |
| [deployment/AGENT_DEPLOYER_GUIDE.md](deployment/AGENT_DEPLOYER_GUIDE.md) | End-to-end agent deployment workflow |

## Full reference

### Architecture and design

- [ARCHITECTURE.md](ARCHITECTURE.md) — system design overview
- [SECURITY.md](SECURITY.md) — security model and threat analysis
- [POLICY_REFERENCE.md](POLICY_REFERENCE.md) — OPA policy design and
  examples
- [DEMO_SCENARIOS.md](DEMO_SCENARIOS.md) — user personas, permission
  matrices, walkthroughs
- [DIAGRAMS.md](DIAGRAMS.md) — architecture and flow diagrams

### Identity and authentication

- [AUTHBRIDGE.md](AUTHBRIDGE.md) — AuthBridge integration architecture
- [KEYCLOAK_TOKEN_EXCHANGE_SETUP.md](KEYCLOAK_TOKEN_EXCHANGE_SETUP.md) —
  Keycloak configuration
- [AUTHBRIDGE_INTEGRATION_LEARNING.md](AUTHBRIDGE_INTEGRATION_LEARNING.md) —
  deep dive into OAuth2 token exchange

### Operations

- [OPERATIONS.md](OPERATIONS.md) — runbook, monitoring, troubleshooting
- [API_TESTING.md](API_TESTING.md) — API reference and testing examples
- [LEARNING_GUIDE.md](LEARNING_GUIDE.md) — educational materials on
  Zero Trust and SPIFFE

### Deployment guides

- [deployment/AGENT_DEPLOYER_GUIDE.md](deployment/AGENT_DEPLOYER_GUIDE.md) —
  deploying new A2A agents
- [deployment/KAGENTI_ON_OPENSHIFT.md](deployment/KAGENTI_ON_OPENSHIFT.md) —
  Kagenti operator on OpenShift
- [deployment/ZERO_TRUST_OPENSHIFT.md](deployment/ZERO_TRUST_OPENSHIFT.md) —
  OpenShift-specific implementation
- [deployment/OPENSHIFT_VS_KUBERNETES.md][oks] — platform comparison
- [deployment/openshift.md](deployment/openshift.md) — cluster setup
  procedures

### Architecture decision records

See [adr/](adr/) for the full index. Key decisions:

- [ADR-0001](adr/0001-spiffe-spire-workload-identity.md) — SPIFFE/SPIRE
  for workload identity
- [ADR-0002](adr/0002-permission-intersection-delegation.md) —
  permission intersection for delegation
- [ADR-0003](adr/0003-opa-policy-evaluation.md) — OPA for policy
  evaluation
- [ADR-0006](adr/0006-s3-document-storage.md) — S3 for document storage

### Development internals

Internal planning documents, session logs, and design notes used during
development. These are working materials — not polished references.

- [dev/](dev/) — phase plans, design specs, session logs

## Quick links

- [Main README](../README.md) — project overview and quick start
- [OPA policies](../opa-service/policies/) — Rego source files

[oks]: deployment/OPENSHIFT_VS_KUBERNETES.md
[blog-series]: https://next.redhat.com/2026/XX/XX/placeholder
