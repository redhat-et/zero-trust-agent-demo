# Documentation Index

This directory contains documentation for the SPIFFE/SPIRE Zero Trust Demo.

## User Documentation

| Document | Description |
|----------|-------------|
| [DEMO_GUIDE.md](DEMO_GUIDE.md) | Step-by-step guide to running the demo |
| [LEARNING_GUIDE.md](LEARNING_GUIDE.md) | Educational materials on Zero Trust and SPIFFE |
| [API_TESTING.md](API_TESTING.md) | API reference and testing examples |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture and design |

## Security & Operations

| Document | Description |
|----------|-------------|
| [SECURITY.md](SECURITY.md) | Security model, threat analysis, trust boundaries |
| [OPERATIONS.md](OPERATIONS.md) | Operational runbook, monitoring, troubleshooting |

## Architecture Decision Records

See [adr/](adr/) for architectural decisions and their rationale:

- [ADR-0001](adr/0001-spiffe-spire-workload-identity.md) - SPIFFE/SPIRE for Workload Identity
- [ADR-0002](adr/0002-permission-intersection-delegation.md) - Permission Intersection for AI Agent Delegation
- [ADR-0003](adr/0003-opa-policy-evaluation.md) - OPA for Policy Evaluation
- [ADR-0004](adr/0004-kustomize-deployment-variants.md) - Kustomize for Deployment Variants
- [ADR-0005](adr/0005-separate-health-ports-mtls.md) - Separate Health Ports for mTLS Services

## Deployment Guides

| Document | Description |
|----------|-------------|
| [deployment/OPENSHIFT_VS_KUBERNETES.md](deployment/OPENSHIFT_VS_KUBERNETES.md) | Platform comparison and considerations |
| [deployment/ZERO_TRUST_OPENSHIFT.md](deployment/ZERO_TRUST_OPENSHIFT.md) | OpenShift-specific Zero Trust implementation |

## Development Documentation

Internal development process documentation:

| Document | Description |
|----------|-------------|
| [dev/PHASE2_SPIRE_INTEGRATION.md](dev/PHASE2_SPIRE_INTEGRATION.md) | Phase 2 implementation notes |
| [dev/PHASE3_PRODUCTION_READINESS.md](dev/PHASE3_PRODUCTION_READINESS.md) | Phase 3 implementation notes |
| [dev/SESSION_LOG_2026-01-22.md](dev/SESSION_LOG_2026-01-22.md) | Development session log |

## Quick Links

- [Main README](../README.md) - Project overview and quick start
- [CLAUDE.md](../CLAUDE.md) - AI assistant project guide
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Contribution guidelines
