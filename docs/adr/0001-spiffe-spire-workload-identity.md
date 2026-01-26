# ADR-0001: Use SPIFFE/SPIRE for Workload Identity

## Status

Accepted

## Date

2026-01-20

## Context

This demo requires a mechanism to establish cryptographic identity for workloads (services, users, AI agents) in a Kubernetes environment. The identities must:

1. Be verifiable without shared secrets
2. Work across different deployment environments (local, Kind, OpenShift)
3. Support mutual TLS (mTLS) for service-to-service communication
4. Rotate automatically without service disruption
5. Be compatible with Zero Trust architecture principles

Traditional approaches like Kubernetes ServiceAccount tokens have limitations:
- Not designed for mTLS
- Limited to Kubernetes API authentication
- No standard format for workload identity

## Decision

We will use **SPIFFE (Secure Production Identity Framework for Everyone)** as the identity standard and **SPIRE (SPIFFE Runtime Environment)** as the implementation.

Key aspects:
- Every workload gets a SPIFFE ID in the format `spiffe://demo.example.com/<path>`
- SPIRE issues X.509 SVIDs (SPIFFE Verifiable Identity Documents) as certificates
- Services use the go-spiffe library to obtain SVIDs via the Workload API
- mTLS is established using SVID certificates

Identity hierarchy:
```
spiffe://demo.example.com/
├── service/          # Backend services
│   ├── user-service
│   ├── agent-service
│   ├── document-service
│   └── opa-service
├── user/             # Human users
│   ├── alice
│   ├── bob
│   └── carol
└── agent/            # AI agents
    ├── gpt4
    ├── claude
    └── summarizer
```

## Consequences

### Positive

- **Standards-based**: SPIFFE is a CNCF graduated project with wide industry adoption
- **Platform-agnostic**: Works on any Kubernetes distribution, VMs, or bare metal
- **Automatic rotation**: SVIDs rotate without application involvement
- **Strong security**: Cryptographic identities backed by X.509 certificates
- **Zero Trust ready**: No implicit trust based on network location

### Negative

- **Operational complexity**: Requires running SPIRE server and agents
- **Learning curve**: Team needs to understand SPIFFE concepts
- **Resource overhead**: SPIRE agent runs as DaemonSet on every node
- **Bootstrap trust**: Initial SPIRE agent attestation requires careful setup

### Neutral

- SVIDs have short TTL (1 hour by default), requiring robust rotation handling
- Need to register entries for each workload type

## Alternatives Considered

### 1. Kubernetes ServiceAccount Tokens
- **Pros**: Built-in, no additional infrastructure
- **Cons**: Not designed for mTLS, limited to K8s API auth, projected tokens have TTL issues

### 2. HashiCorp Vault PKI
- **Pros**: Mature, feature-rich, enterprise support
- **Cons**: More complex to operate, not purpose-built for workload identity, requires additional license for some features

### 3. Istio Service Mesh
- **Pros**: Includes identity, mTLS, and more
- **Cons**: Much heavier footprint, overkill for demo, abstracts away identity concepts we want to demonstrate

### 4. cert-manager with self-signed CA
- **Pros**: Simpler than SPIRE, Kubernetes-native
- **Cons**: No workload attestation, manual rotation, not SPIFFE-compatible

## References

- [SPIFFE Specification](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/)
- [SPIRE Documentation](https://spiffe.io/docs/latest/spire-about/spire-concepts/)
- [CNCF SPIFFE Project](https://www.cncf.io/projects/spiffe/)
- [go-spiffe Library](https://github.com/spiffe/go-spiffe)
