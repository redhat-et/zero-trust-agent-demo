# Security Documentation

This document describes the security model, threat analysis, and trust boundaries for the SPIFFE/SPIRE Zero Trust Demo.

## Overview

This demo implements a Zero Trust security model where:
- Every workload has a cryptographic identity (SPIFFE ID)
- All service-to-service communication is mutually authenticated (mTLS)
- Authorization decisions are policy-driven (OPA)
- AI agents operate under the principle of least privilege

## Threat Model

### Assets Protected

| Asset | Sensitivity | Protection Mechanism |
|-------|-------------|---------------------|
| Documents (DOC-001 to DOC-007) | Varies by department | OPA policy + mTLS |
| User delegation tokens | High | Short-lived, cryptographically bound |
| SPIFFE SVIDs | Critical | X.509 certificates, 1-hour TTL |
| OPA policies | High | ConfigMap, GitOps controlled |

### Threat Actors

| Actor | Capability | Mitigations |
|-------|-----------|-------------|
| Compromised container | Network access, local filesystem | mTLS prevents impersonation, SVID bound to workload |
| Malicious insider | Valid credentials | Permission intersection limits blast radius |
| Network attacker | Traffic interception | mTLS encryption, certificate validation |
| Rogue AI agent | Attempts autonomous access | Agents require valid user delegation |

### Attack Vectors

#### 1. SVID Theft
**Threat**: Attacker extracts SVID from compromised pod.

**Mitigations**:
- SVIDs have 1-hour TTL (configurable)
- SVIDs are memory-only (not persisted to disk)
- SPIRE Workload API requires attestation
- Network policies limit lateral movement

#### 2. Delegation Token Forgery
**Threat**: Attacker creates fake delegation to bypass authorization.

**Mitigations**:
- Delegation context is cryptographically signed
- OPA validates SPIFFE IDs against known users/agents
- Delegation requires both user AND agent to have permissions

#### 3. Policy Bypass
**Threat**: Attacker modifies OPA policies to grant unauthorized access.

**Mitigations**:
- Policies stored in ConfigMap (requires K8s RBAC)
- GitOps workflow for policy changes
- Policy testing in CI pipeline
- Audit logging of policy evaluation

#### 4. Agent Autonomy Attack
**Threat**: AI agent attempts to access documents without user delegation.

**Mitigations**:
- OPA policy requires `delegation.user_spiffe_id` for agent access
- Agent-only requests are explicitly denied
- All access decisions are logged

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                        Trust Domain                              │
│                   spiffe://demo.example.com                      │
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │ SPIRE Server │    │ SPIRE Agent  │    │ SPIRE Agent  │       │
│  │   (Root CA)  │◄───│   (Node 1)   │    │   (Node 2)   │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│         │                   │                   │                │
│         │            ┌──────┴──────┐     ┌──────┴──────┐        │
│         │            │  Workloads  │     │  Workloads  │        │
│         │            └─────────────┘     └─────────────┘        │
│         │                                                        │
│  ┌──────┴─────────────────────────────────────────────────────┐ │
│  │                    Trust Boundary 1                         │ │
│  │  All SVIDs issued by this SPIRE server are trusted         │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    Trust Boundary 2                              │
│            Service-to-Service Communication                      │
│                                                                  │
│  ┌─────────────┐         mTLS          ┌─────────────┐          │
│  │user-service │◄─────────────────────►│doc-service  │          │
│  │             │    Mutual Auth        │             │          │
│  └─────────────┘                       └─────────────┘          │
│                                                                  │
│  Each service validates peer's SPIFFE ID before accepting       │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    Trust Boundary 3                              │
│                  Policy Evaluation                               │
│                                                                  │
│  ┌─────────────┐        Query          ┌─────────────┐          │
│  │doc-service  │──────────────────────►│opa-service  │          │
│  │             │◄──────────────────────│             │          │
│  └─────────────┘       Decision        └─────────────┘          │
│                                                                  │
│  OPA is the single source of truth for authorization            │
└─────────────────────────────────────────────────────────────────┘
```

## SPIFFE ID Format

All identities follow the SPIFFE ID format:

```
spiffe://<trust-domain>/<path>
```

### Trust Domain
- **Production**: `demo.example.com`
- **Development**: `demo.example.com` (same for consistency)

### Path Conventions

| Entity Type | Format | Example |
|------------|--------|---------|
| Services | `/service/<name>` | `spiffe://demo.example.com/service/user-service` |
| Users | `/user/<username>` | `spiffe://demo.example.com/user/alice` |
| AI Agents | `/agent/<agent-name>` | `spiffe://demo.example.com/agent/gpt4` |

### Registration Entries

Services are registered via SPIRE entry creation:

```bash
# Service registration
spire-server entry create \
  -spiffeID spiffe://demo.example.com/service/document-service \
  -parentID spiffe://demo.example.com/spire/agent/k8s_psat/demo-cluster/... \
  -selector k8s:ns:spiffe-demo \
  -selector k8s:sa:document-service
```

## Network Security

### Kubernetes Network Policies

Each service has ingress/egress policies restricting communication:

```yaml
# document-service network policy
spec:
  podSelector:
    matchLabels:
      app: document-service
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: user-service
        - podSelector:
            matchLabels:
              app: agent-service
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: opa-service
```

### Communication Matrix

| Source | Destination | Port | Protocol |
|--------|-------------|------|----------|
| web-dashboard | user-service | 8082 | HTTPS (mTLS) |
| web-dashboard | agent-service | 8083 | HTTPS (mTLS) |
| user-service | document-service | 8084 | HTTPS (mTLS) |
| agent-service | document-service | 8084 | HTTPS (mTLS) |
| document-service | opa-service | 8085 | HTTPS (mTLS) |
| all services | SPIRE Agent | /tmp/spire-agent/public/api.sock | Unix socket |

## Secret Management

### Secrets in This Demo

| Secret | Storage | Rotation |
|--------|---------|----------|
| SPIFFE SVIDs | In-memory only | Automatic (1-hour TTL) |
| SPIRE Server CA | SPIRE data directory | Manual (yearly) |
| SPIRE Agent tokens | Kubernetes Secret | On agent restart |

### Production Recommendations

1. **Use external secret management** (Vault, AWS Secrets Manager)
2. **Enable SPIRE UpstreamAuthority** for PKI integration
3. **Rotate SPIRE Server CA** before expiration
4. **Use hardware security modules (HSM)** for CA key protection

## Audit Logging

### What Gets Logged

All authorization decisions are logged with:

```json
{
  "time": "2026-01-26T10:00:00Z",
  "level": "INFO",
  "msg": "Authorization decision",
  "component": "document-service",
  "caller_spiffe_id": "spiffe://demo.example.com/agent/gpt4",
  "document_id": "DOC-001",
  "decision": "allow",
  "delegation": {
    "user_spiffe_id": "spiffe://demo.example.com/user/alice",
    "effective_permissions": ["engineering", "finance"]
  }
}
```

### Log Retention

- **Development**: Console output only
- **Production**: Ship to centralized logging (ELK, Loki, CloudWatch)
- **Retention**: 90 days minimum for security audit

## Incident Response

### Detection

Monitor for:
- Unusual authorization denials (potential attack probing)
- SVID rotation failures (potential SPIRE issues)
- Cross-namespace traffic (potential policy bypass)

### Response Procedures

#### 1. Compromised Workload
```bash
# Isolate the pod
kubectl label pod <pod-name> -n spiffe-demo quarantine=true

# Delete the SPIRE entry (revokes SVID)
spire-server entry delete -entryID <entry-id>

# Restart the workload with fresh SVID
kubectl delete pod <pod-name> -n spiffe-demo
```

#### 2. Suspected Policy Tampering
```bash
# Check policy ConfigMap history
kubectl rollout history configmap/opa-policies -n spiffe-demo

# Revert to known-good policy
kubectl rollout undo configmap/opa-policies -n spiffe-demo

# Restart OPA to reload policies
kubectl rollout restart deployment/opa-service -n spiffe-demo
```

#### 3. SPIRE Server Compromise
```bash
# This is a critical incident - rotate everything

# 1. Rotate SPIRE Server CA
spire-server bundle rotate

# 2. Force agent re-attestation
kubectl rollout restart daemonset/spire-agent -n spire

# 3. All workloads will get new SVIDs on next rotation
# Consider forcing restart of all workloads for immediate rotation
```

## Compliance Considerations

This demo architecture supports:

| Framework | Relevant Controls |
|-----------|-------------------|
| **SOC 2** | CC6.1 (Logical Access), CC6.7 (Encryption) |
| **PCI DSS** | 7.1 (Access Control), 8.3 (Strong Auth) |
| **NIST 800-207** | Zero Trust Architecture principles |
| **FedRAMP** | AC-17 (Remote Access), IA-2 (Identification) |

## References

- [SPIFFE Specification](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/)
- [SPIRE Documentation](https://spiffe.io/docs/latest/spire-about/spire-concepts/)
- [Zero Trust Architecture (NIST 800-207)](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
