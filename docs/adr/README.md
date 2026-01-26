# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for the SPIFFE/SPIRE Zero Trust Demo project.

## What is an ADR?

An Architecture Decision Record captures an important architectural decision made along with its context and consequences. ADRs help:

- Document why decisions were made
- Onboard new team members
- Avoid revisiting settled decisions
- Understand trade-offs that were considered

## ADR Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [0001](0001-spiffe-spire-workload-identity.md) | Use SPIFFE/SPIRE for Workload Identity | Accepted | 2026-01-20 |
| [0002](0002-permission-intersection-delegation.md) | Permission Intersection for AI Agent Delegation | Accepted | 2026-01-20 |
| [0003](0003-opa-policy-evaluation.md) | Use OPA for Policy Evaluation | Accepted | 2026-01-20 |
| [0004](0004-kustomize-deployment-variants.md) | Use Kustomize for Deployment Variants | Accepted | 2026-01-21 |
| [0005](0005-separate-health-ports-mtls.md) | Separate Health Ports for mTLS Services | Accepted | 2026-01-22 |

## ADR Template

When adding a new ADR, use this template:

```markdown
# ADR-NNNN: Title

## Status

Proposed | Accepted | Deprecated | Superseded by [ADR-XXXX](XXXX-title.md)

## Context

What is the issue that we're seeing that is motivating this decision or change?

## Decision

What is the change that we're proposing and/or doing?

## Consequences

What becomes easier or more difficult to do because of this change?

## Alternatives Considered

What other options were evaluated?
```

## References

- [ADR GitHub Organization](https://adr.github.io/)
- [Documenting Architecture Decisions](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
