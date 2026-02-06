# Zero Trust & SPIFFE/SPIRE Learning Guide

This guide provides a deep dive into the Zero Trust concepts and SPIFFE/SPIRE technologies demonstrated in this project. It includes links to official documentation and pointers to specific code implementations.

## Table of Contents

1. [Zero Trust Architecture](#zero-trust-architecture)
2. [SPIFFE Overview](#spiffe-overview)
3. [SPIRE Implementation](#spire-implementation)
4. [X.509 SVIDs](#x509-svids)
5. [Mutual TLS (mTLS)](#mutual-tls-mtls)
6. [Workload Registration](#workload-registration)
7. [Policy-Based Access Control with OPA](#policy-based-access-control-with-opa)
8. [Permission Intersection Pattern](#permission-intersection-pattern)
9. [Code Implementation Guide](#code-implementation-guide)
10. [Extending the Demo: Adding Users and Agents](#extending-the-demo-adding-users-and-agents)
11. [Advanced Topics](#advanced-topics)
12. [Further Reading](#further-reading)
13. [Glossary](#glossary)

---

## Zero Trust Architecture

### What is Zero Trust?

Zero Trust is a security model based on the principle of **"never trust, always verify."** Unlike traditional perimeter-based security, Zero Trust assumes that threats can exist both inside and outside the network.

### Core Principles

| Principle             | Description                                                   | Implementation in This Demo                         |
| --------------------- | ------------------------------------------------------------- | --------------------------------------------------- |
| **Verify Explicitly** | Always authenticate and authorize based on all available data | Every service call requires mTLS + OPA policy check |
| **Least Privilege**   | Limit access to only what's needed                            | Permission intersection ensures minimal access      |
| **Assume Breach**     | Minimize blast radius and segment access                      | Each service has its own SPIFFE ID                  |

### Official Resources

- [NIST Zero Trust Architecture (SP 800-207)](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [Google BeyondCorp](https://cloud.google.com/beyondcorp)
- [CNCF Zero Trust Whitepaper](https://www.cncf.io/blog/2021/08/18/zero-trust-architecture/)

---

## SPIFFE Overview

### What is SPIFFE?

**SPIFFE** (Secure Production Identity Framework for Everyone) is a set of open-source standards for securely identifying software systems in dynamic and heterogeneous environments.

### Key Concepts

| Concept          | Description                                                                                        |
| ---------------- | -------------------------------------------------------------------------------------------------- |
| **SPIFFE ID**    | A URI that uniquely identifies a workload (e.g., `spiffe://demo.example.com/service/user-service`) |
| **Trust Domain** | The root of trust, like a DNS domain (e.g., `demo.example.com`)                                    |
| **SVID**         | SPIFFE Verifiable Identity Document - the credential that proves identity                          |
| **Workload**     | Any software system that needs an identity                                                         |

### SPIFFE ID Format

```text
spiffe://trust-domain/path
```

Examples from this demo:
- `spiffe://demo.example.com/service/opa-service`
- `spiffe://demo.example.com/service/document-service`
- `spiffe://demo.example.com/service/user-service`

### Official Resources

- [SPIFFE Official Website](https://spiffe.io/)
- [SPIFFE Specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md)
- [SPIFFE ID Specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md)

---

## SPIRE Implementation

### What is SPIRE?

**SPIRE** (SPIFFE Runtime Environment) is the reference implementation of SPIFFE. It provides:
- Identity issuance to workloads
- Automatic credential rotation
- Workload attestation (proving a workload is what it claims to be)

### SPIRE Architecture

```text
┌─────────────────────────────────────────────────────┐
│                   SPIRE Server                      │
│  - Manages trust domain                             │
│  - Signs SVIDs                                      │
│  - Stores registration entries                      │
└─────────────────────┬───────────────────────────────┘
                      │
        ┌─────────────┴─────────────┐
        │                           │
┌───────▼───────┐           ┌───────▼───────┐
│  SPIRE Agent  │           │  SPIRE Agent  │
│   (Node 1)    │           │   (Node 2)    │
└───────┬───────┘           └───────┬───────┘
        │                           │
   ┌────┴────┐                 ┌────┴────┐
   │Workload │                 │Workload │
   │   A     │                 │   B     │
   └─────────┘                 └─────────┘
```

### Workload API

Workloads communicate with SPIRE Agent via a Unix Domain Socket to:
1. Fetch their SVID
2. Get trust bundles (CA certificates)
3. Receive notifications when SVIDs are rotated

**Code Reference**: `pkg/spiffe/workload.go:56-102`

```go
// FetchIdentity fetches the workload's SVID from SPIRE Agent
func (c *WorkloadClient) FetchIdentity(ctx context.Context) (*Identity, error) {
    opts := []workloadapi.X509SourceOption{
        workloadapi.WithClientOptions(workloadapi.WithAddr(c.socketPath)),
    }
    source, err := workloadapi.NewX509Source(ctx, opts...)
    // ...
    svid, err := source.GetX509SVID()
    // ...
}
```

### Installation in This Demo

SPIRE is installed via Helm chart with custom values.

**Configuration File**: `deploy/spire/values.yaml`

```yaml
global:
  spiffe:
    trustDomain: "demo.example.com"
```

### Official Resources

- [SPIRE Documentation](https://spiffe.io/docs/latest/spire-about/)
- [SPIRE Architecture](https://spiffe.io/docs/latest/spire-about/spire-concepts/)
- [SPIRE on Kubernetes](https://spiffe.io/docs/latest/deploying/k8s/)
- [spiffe-csi-driver](https://github.com/spiffe/spiffe-csi)

---

## X.509 SVIDs

### What is an SVID?

An **SVID** (SPIFFE Verifiable Identity Document) is a cryptographically signed document that proves a workload's identity. X.509 SVIDs use X.509 certificates.

### SVID Lifecycle

```text
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Workload   │────▶│ SPIRE Agent  │────▶│ SPIRE Server │
│ Requests ID  │     │  Attests WL  │     │  Signs SVID  │
└──────────────┘     └──────────────┘     └──────────────┘
                            │
                     ┌──────▼──────┐
                     │ X.509 SVID  │
                     │ - SPIFFE ID │
                     │ - Public Key│
                     │ - TTL: 1hr  │
                     └─────────────┘
```

### SVID Contents

An X.509 SVID contains:
- **Subject Alternative Name (SAN)**: The SPIFFE ID as a URI
- **Public Key**: For TLS handshakes
- **Validity Period**: Short-lived (default 1 hour)
- **Issuer**: The SPIRE Server's signing CA

### Automatic Rotation

SVIDs are automatically rotated before expiration. SPIRE Agent:
1. Fetches new SVID before old one expires
2. Notifies workloads via Workload API
3. Workloads update their TLS configurations

**Code Reference**: `pkg/spiffe/workload.go:73-102` - X509Source handles rotation automatically

### Official Resources

- [X.509-SVID Specification](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md)
- [JWT-SVID Specification](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md)

---

## Mutual TLS (mTLS)

### What is mTLS?

In standard TLS, only the server presents a certificate. In **mutual TLS (mTLS)**, both client and server present certificates and verify each other's identity.

```text
┌────────────┐                              ┌────────────┐
│   Client   │                              │   Server   │
│ (has SVID) │                              │ (has SVID) │
└─────┬──────┘                              └─────┬──────┘
      │                                           │
      │─────── Client Hello ─────────────────────▶│
      │                                           │
      │◀────── Server Hello + Server Cert ────────│
      │                                           │
      │─────── Client Cert ──────────────────────▶│
      │                                           │
      │◀─╌╌╌╌ Both verify each other ╌╌╌╌╌╌╌╌╌╌╌╌╌│
      │                                           │
      │═══════ Encrypted Communication ══════════▶│
```

### mTLS in This Demo

Every service-to-service call uses mTLS:
- **user-service** → **document-service**: mTLS
- **agent-service** → **document-service**: mTLS
- **document-service** → **opa-service**: mTLS

### Server-Side mTLS Implementation

**Code Reference**: `pkg/spiffe/workload.go:183-207`

```go
// CreateHTTPServer creates an mTLS-enabled HTTP server
func (c *WorkloadClient) CreateHTTPServer(handler http.Handler, addr string) (*http.Server, error) {
    // Configure mTLS server: present our SVID, verify client's SVID
    tlsConfig := tlsconfig.MTLSServerConfig(
        source,  // Our identity (X509Source)
        source,  // Trust bundle for verifying clients
        tlsconfig.AuthorizeAny(),  // Allow any authenticated client
    )
    // ...
}
```

### Client-Side mTLS Implementation

**Code Reference**: `pkg/spiffe/workload.go:148-179`

```go
// CreateHTTPClient creates an mTLS-enabled HTTP client
func (c *WorkloadClient) CreateHTTPClient(ctx context.Context) (*http.Client, error) {
    // Configure mTLS: present our SVID, verify peer's SVID
    tlsConfig := tlsconfig.MTLSClientConfig(
        source,  // Our identity (X509SVIDSource)
        source,  // Trust bundle for verifying servers
        tlsconfig.AuthorizeAny(),
    )
    // ...
}
```

### TLS Configuration with go-spiffe

The `go-spiffe` library provides `tlsconfig` helpers:

| Function              | Purpose                                  |
| --------------------- | ---------------------------------------- |
| `MTLSServerConfig()`  | Server TLS config requiring client certs |
| `MTLSClientConfig()`  | Client TLS config presenting our cert    |
| `AuthorizeAny()`      | Accept any valid SPIFFE ID               |
| `AuthorizeMemberOf()` | Only accept specific trust domains       |
| `AuthorizeID()`       | Only accept specific SPIFFE IDs          |

### Official Resources

- [go-spiffe Library](https://github.com/spiffe/go-spiffe)
- [go-spiffe TLS Config](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig)
- [mTLS Explained](https://www.cloudflare.com/learning/access-management/what-is-mutual-tls/)

---

## Workload Registration

### What is Workload Registration?

Before a workload can receive an SVID, it must be registered with SPIRE Server. Registration defines:
- What SPIFFE ID the workload should receive
- How to identify (attest) the workload

### Kubernetes Workload Registration

In Kubernetes, SPIRE uses **ClusterSPIFFEID** custom resources.

**Configuration File**: `deploy/spire/clusterspiffeids.yaml`

```yaml
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: spiffe-demo-opa-service
spec:
  className: spire-system-spire
  spiffeIDTemplate: "spiffe://demo.example.com/service/opa-service"
  podSelector:
    matchLabels:
      app: opa-service
  namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: spiffe-demo
```

### Registration Components

| Field               | Purpose                          |
| ------------------- | -------------------------------- |
| `spiffeIDTemplate`  | The SPIFFE ID to issue           |
| `podSelector`       | Which pods receive this identity |
| `namespaceSelector` | Which namespaces to search       |
| `className`         | Links to SPIREControllerManager  |

### Attestation Methods

SPIRE supports various attestation methods:

| Attestor     | How it Works                               |
| ------------ | ------------------------------------------ |
| **k8s_psat** | Kubernetes Projected Service Account Token |
| **k8s_sat**  | Kubernetes Service Account Token           |
| **docker**   | Docker container ID                        |
| **unix**     | Unix process UID/GID                       |

### Official Resources

- [SPIRE Workload Registration](https://spiffe.io/docs/latest/deploying/registering/)
- [Kubernetes Workload Registrar](https://github.com/spiffe/spire/tree/main/support/k8s/k8s-workload-registrar)
- [spire-controller-manager](https://github.com/spiffe/spire-controller-manager)

---

## Policy-Based Access Control with OPA

### What is OPA?

**Open Policy Agent (OPA)** is a general-purpose policy engine. It uses a declarative language called **Rego** to express policies.

### OPA in This Demo

The **opa-service** evaluates authorization requests using Rego policies.

```text
┌────────────────┐      ┌───────────────┐
│ document-svc   │─────▶│  opa-service  │
│ "Can X access  │      │               │
│  document Y?"  │◀─────│ allow: true   │
└────────────────┘      └───────────────┘
```

### Policy Structure

**Main Policy File**: `opa-service/policies/delegation.rego`

```rego
package demo.authorization

# Default deny
default allow := false

# Public documents are always allowed
allow if {
    doc := documents[input.document_id]
    doc.required_department == ""
}

# Direct user access
allow if {
    not input.delegation
    caller := parse_spiffe_id(input.caller_spiffe_id)
    caller.type == "user"
    user_depts := users.get_departments(caller.name)
    has_any_required_department(user_depts, input.document_id)
}

# Delegated access (permission intersection)
allow if {
    input.delegation
    user := parse_spiffe_id(input.delegation.user_spiffe_id)
    agent := parse_spiffe_id(input.delegation.agent_spiffe_id)

    user_depts := users.get_departments(user.name)
    agent_caps := agents.get_capabilities(agent.name)

    # Permission intersection
    effective := {d | d := user_depts[_]; d in agent_caps}
    has_any_required_department(effective, input.document_id)
}
```

### Policy Evaluation Request

**Code Reference**: `document-service/cmd/serve.go:134-170` - OPA client call

```go
// OPA authorization request
type authzRequest struct {
    Input struct {
        CallerSPIFFEID string `json:"caller_spiffe_id"`
        DocumentID     string `json:"document_id"`
        Delegation     *struct {
            UserSPIFFEID  string `json:"user_spiffe_id"`
            AgentSPIFFEID string `json:"agent_spiffe_id"`
        } `json:"delegation,omitempty"`
    } `json:"input"`
}
```

### Official Resources

- [Open Policy Agent](https://www.openpolicyagent.org/)
- [Rego Language Reference](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [OPA Playground](https://play.openpolicyagent.org/)
- [OPA Best Practices](https://www.openpolicyagent.org/docs/latest/best-practices/)

---

## Permission Intersection Pattern

### The Problem

When an AI agent acts on behalf of a user, what permissions should it have?

| Approach                 | Risk                                         |
| ------------------------ | -------------------------------------------- |
| Agent's permissions      | User data exposed to over-privileged agents  |
| User's permissions       | Agent could exceed its intended capabilities |
| Union of both            | Maximum exposure, worst security             |
| **Intersection of both** | Minimum necessary permissions                |

### The Solution: Permission Intersection

```text
Effective Permissions = User Permissions ∩ Agent Capabilities
```

### Example

```text
Alice has: [engineering, finance]
GPT-4 has: [engineering, finance]
Intersection: [engineering, finance] ✅

Alice has: [engineering, finance]
Summarizer has: [finance]
Intersection: [finance] only ✅

Carol has: [hr]
GPT-4 has: [engineering, finance]
Intersection: [] (empty) ❌
```

### Implementation in Rego

**Code Reference**: `opa-service/policies/delegation.rego:112-135`

```rego
allow if {
    input.delegation

    user := parse_spiffe_id(input.delegation.user_spiffe_id)
    agent := parse_spiffe_id(input.delegation.agent_spiffe_id)

    user_depts := users.get_departments(user.name)
    agent_caps := agents.get_capabilities(agent.name)

    # Set intersection
    effective := {d | d := user_depts[_]; d in agent_caps}

    has_any_required_department(effective, input.document_id)
}
```

### Why This Matters for AI Agents

1. **Agents cannot exceed user permissions** - Even a powerful agent can't access what the user can't
2. **Agents cannot exceed their capabilities** - Purpose-built agents stay within their scope
3. **Users cannot escalate via agents** - Delegating to Claude doesn't give Carol engineering access
4. **Agents require explicit delegation** - No autonomous agent access

---

## Code Implementation Guide

### Key Files and Their Purposes

| File                                   | Purpose                                           | Key Lines                                               |
| -------------------------------------- | ------------------------------------------------- | ------------------------------------------------------- |
| `pkg/spiffe/workload.go`               | SPIFFE client for SVID fetching and mTLS          | 56-102: FetchIdentity, 148-207: CreateHTTPClient/Server |
| `pkg/config/config.go`                 | Viper configuration with SPIFFE settings          | SPIFFEConfig struct                                     |
| `opa-service/policies/delegation.rego` | Authorization policy with permission intersection | 90-135: allow rules                                     |
| `document-service/cmd/serve.go`        | Protected resource service with OPA integration   | 134-170: OPA call, 195: mTLS server                     |
| `user-service/cmd/serve.go`            | User service with delegation support              | 179: mTLS server, 254-296: access handlers              |
| `agent-service/cmd/serve.go`           | Agent service for delegated access                | 168: mTLS server, 266-267: delegation handling          |
| `deploy/spire/clusterspiffeids.yaml`   | Workload registration for Kubernetes              | ClusterSPIFFEID resources                               |
| `deploy/spire/values.yaml`             | SPIRE Helm chart configuration                    | Trust domain, CSI driver config                         |

### Adding a New Service

1. **Create the service** with SPIFFE client:
   ```go
   import "github.com/redhat-et/zero-trust-agent-demo/pkg/spiffe"

   client := spiffe.NewWorkloadClient(cfg.SPIFFE, logger)
   identity, err := client.FetchIdentity(ctx)
   ```

2. **Create mTLS server**:
   ```go
   server, err := client.CreateHTTPServer(handler, cfg.Service.Addr())
   server.ListenAndServeTLS("", "")
   ```

3. **Create mTLS client** for calling other services:
   ```go
   httpClient, err := client.CreateHTTPClient(ctx)
   ```

4. **Register the workload** in `deploy/spire/clusterspiffeids.yaml`

5. **Add to Kustomize overlays** in `deploy/k8s/overlays/*/kustomization.yaml`

### Testing Authorization Policies

Run OPA policy tests:
```bash
make test-policies
```

**Test File**: `opa-service/policies/delegation_test.rego`

---

## Extending the Demo: Adding Users and Agents

This section explains how to extend the demo by adding new users and agents. Understanding this process reveals important architectural distinctions between **identity** and **policy**.

### Key Insight: Identity vs Policy

Before diving into the steps, understand this crucial distinction:

| Concept                | Users                                      | Agents                                               |
| ---------------------- | ------------------------------------------ | ---------------------------------------------------- |
| **What it represents** | "Who is this person?"                      | "What should this workload be allowed to do?"        |
| **Source**             | Identity Provider (LDAP, Keycloak)         | Security Policy (OPA)                                |
| **Managed by**         | HR / IT Admin                              | Security Team                                        |
| **Example**            | Alice is in engineering (fact about Alice) | Summarizer can only access finance (policy decision) |

User **departments** are identity attributes (facts about who they are).
Agent **capabilities** are policy decisions (what we allow them to do).

### Understanding User "SPIFFE IDs"

In this demo, you'll see user SPIFFE IDs like `spiffe://demo.example.com/user/alice`. But these are **not real SVIDs** issued by SPIRE.

| Entity                  | Real SVID? | Source                         |
| ----------------------- | ---------- | ------------------------------ |
| user-service (workload) | Yes        | SPIRE issues X.509 certificate |
| alice (human)           | No         | Constructed from username      |

Humans can't receive SVIDs because they're not processes running on machines. The "user SPIFFE ID" is a **naming convention** for representing users in policy decisions:

```go
// Constructed at runtime from JWT subject claim or selected username
userSPIFFEID := fmt.Sprintf("spiffe://%s/user/%s", trustDomain, username)
```

### Adding a New User (Current Demo)

To add a user named "David" with departments `["engineering", "hr"]`:

#### Step 1: Update User Store

**File**: `user-service/internal/store/users.go`

```go
s.users["david"] = &User{
    ID:          "david",
    Name:        "David",
    Departments: []string{"engineering", "hr"},
    SPIFFEID:    "spiffe://" + trustDomain + "/user/david",
}
```

#### Step 2: Update OPA Policy

**File**: `opa-service/policies/user_permissions.rego`

```rego
user_departments := {
    "alice": ["engineering", "finance"],
    "bob": ["finance", "admin"],
    "carol": ["hr"],
    "david": ["engineering", "hr"]  # Add David
}
```

#### Step 3: Update Kubernetes ConfigMap

**File**: `deploy/k8s/opa-policies-configmap.yaml`

Update the embedded Rego policy to match.

#### Step 4: Rebuild and Deploy

```bash
make build
kubectl apply -k deploy/k8s/base
kubectl rollout restart deployment/user-service -n spiffe-demo
kubectl rollout restart deployment/opa-service -n spiffe-demo
```

### Adding a New Agent (Current Demo)

To add an agent named "Reviewer" with capabilities `["engineering", "hr"]`:

#### Step 1: Create Agent Workload (if it's a real service)

```yaml
# deploy/k8s/reviewer-agent.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: reviewer-agent
  namespace: spiffe-demo
spec:
  template:
    metadata:
      labels:
        app: reviewer-agent  # Used for SPIFFE ID matching
    spec:
      containers:
      - name: reviewer
        image: your-registry/reviewer-agent:latest
```

#### Step 2: Register SPIFFE ID

**File**: `deploy/spire/clusterspiffeids.yaml`

```yaml
---
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: spiffe-demo-reviewer-agent
spec:
  className: spire-system-spire
  spiffeIDTemplate: "spiffe://demo.example.com/agent/reviewer"
  podSelector:
    matchLabels:
      app: reviewer-agent
  namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: spiffe-demo
```

#### Step 3: Define Agent Capabilities (Policy)

**File**: `opa-service/policies/agent_permissions.rego`

```rego
agent_capabilities := {
    "gpt4": ["engineering", "finance"],
    "claude": ["engineering", "finance", "admin", "hr"],
    "summarizer": ["finance"],
    "reviewer": ["engineering", "hr"]  # Add Reviewer
}
```

#### Step 4: Update Agent Store (for UI listing)

**File**: `agent-service/internal/store/agents.go`

```go
s.agents["reviewer"] = &Agent{
    ID:           "reviewer",
    Name:         "Reviewer Agent",
    Capabilities: []string{"engineering", "hr"},
    SPIFFEID:     "spiffe://" + trustDomain + "/agent/reviewer",
    Description:  "Reviews engineering docs and HR policies",
}
```

#### Step 5: Update ConfigMap and Deploy

Same as user steps - update ConfigMap and redeploy.

### Why the Duplication?

You may have noticed that user/agent data exists in multiple places:
- Go code (for service logic and UI)
- Rego policies (for authorization)
- Kubernetes ConfigMap (for deployment)

**This duplication is a demo simplification**. In production:

| Data               | Demo Approach           | Production Approach           |
| ------------------ | ----------------------- | ----------------------------- |
| User departments   | Hardcoded in Go + Rego  | LDAP/Keycloak (single source) |
| Agent capabilities | Hardcoded in Go + Rego  | OPA policy (single source)    |
| Policies in K8s    | ConfigMap (manual sync) | OPA Bundles (auto-sync)       |

### Production Architecture Preview

With identity federation (Phase 4), the process simplifies dramatically:

**Adding a User (Production)**:
1. Add user to FreeIPA: `ipa user-add david`
2. Assign to groups: `ipa group-add-member engineering --users=david`
3. **Done** - no code changes needed

**Adding an Agent (Production)**:
1. Deploy agent workload with appropriate labels
2. Add ClusterSPIFFEID registration
3. Add capabilities to OPA policy
4. **Done** - agent gets SVID automatically

The key difference: **users come from identity infrastructure** (FreeIPA/Keycloak), while **agent capabilities remain in policy** (OPA) because they represent security decisions, not identity facts.

### Summary: Who Changes What

| Change                    | Files to Modify                                               | Who Typically Does This |
| ------------------------- | ------------------------------------------------------------- | ----------------------- |
| Add user (demo)           | users.go, user_permissions.rego, ConfigMap                    | Developer               |
| Add user (production)     | FreeIPA only                                                  | IT Admin / HR           |
| Add agent                 | agents.go, agent_permissions.rego, ClusterSPIFFEID, ConfigMap | Platform Team           |
| Change user departments   | Same as add user                                              | IT Admin                |
| Change agent capabilities | agent_permissions.rego, ConfigMap                             | Security Team           |

For detailed production architecture, see [Phase 4: Identity Federation](dev/PHASE4_IDENTITY_FEDERATION.md).

---

## Advanced topics

### RFC 8693 token exchange with Keycloak

Token exchange enables services to swap tokens for different audiences - essential for zero-trust architectures where each service requires tokens specifically scoped to it.

**Learning path:**

1. **Keycloak setup** - Configure Keycloak for token exchange
   - [Keycloak Token Exchange Setup](KEYCLOAK_TOKEN_EXCHANGE_SETUP.md) - Complete configuration guide
   - Key setting: `standard.token.exchange.enabled: true` on clients
   - Requires `--features=token-exchange` on Keycloak startup

2. **Go implementation** - Build a CLI that performs token exchange
   - [STS Token Exchange Learning Project](../learn/sts-token-exchange/README.md)
   - Tasks: Config loading → Request building → Exchange execution → Token verification

3. **Envoy ext-proc** - Integrate with Envoy as an external processor
   - [Envoy Ext-Proc Learning Project](../learn/envoy-ext-proc/README.md)
   - Intercept requests, exchange tokens, modify headers

**Token exchange flow:**

```text
agent-service token (aud: agent-service)
    ↓ POST /token (grant_type=token-exchange)
document-service token (aud: document-service)
```

**Key concepts:**

| Concept | Description |
|---------|-------------|
| Subject token | The original token to exchange |
| Audience | The target service for the new token |
| `azp` claim | Authorized party - who performed the exchange |
| Audience scope | Client scope with `oidc-audience-mapper` |

### AuthBridge integration (Kagenti project)

For integrating this demo with the Kagenti AuthBridge for dynamic token exchange and agent permission re-scoping, see:

- [AuthBridge Integration Learning Guide](AUTHBRIDGE_INTEGRATION_LEARNING.md) - A Socratic exploration of how AuthBridge enables real-time permission re-scoping through token exchange

AuthBridge builds on token exchange to add:

- **Envoy sidecar integration** via ext-proc gRPC protocol
- **Dynamic user attributes** from Keycloak (replacing hardcoded OPA data)
- **Session-based revocation** for immediate access control changes
- **Temporal scoping** for time-bounded delegation

---

## Further Reading

### SPIFFE/SPIRE

- [SPIFFE Official Documentation](https://spiffe.io/docs/latest/)
- [SPIRE GitHub Repository](https://github.com/spiffe/spire)
- [go-spiffe Library](https://github.com/spiffe/go-spiffe)
- [SPIFFE Slack Community](https://slack.spiffe.io/)
- [CNCF SPIFFE Project](https://www.cncf.io/projects/spiffe/)

### Zero Trust

- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [Google BeyondCorp Papers](https://cloud.google.com/beyondcorp#resources)
- [Forrester Zero Trust Research](https://www.forrester.com/report/the-forrester-wave-zero-trust-network-access-q3-2023/RES179548)

### Open Policy Agent

- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego Playground](https://play.openpolicyagent.org/)
- [Styra Academy (Free OPA Training)](https://academy.styra.com/)
- [OPA Slack Community](https://slack.openpolicyagent.org/)

### mTLS and Certificates

- [Cloudflare mTLS Explainer](https://www.cloudflare.com/learning/access-management/what-is-mutual-tls/)
- [X.509 Certificate Format (RFC 5280)](https://datatracker.ietf.org/doc/html/rfc5280)
- [TLS 1.3 Specification (RFC 8446)](https://datatracker.ietf.org/doc/html/rfc8446)

### Books

- "Zero Trust Networks" by Evan Gilman & Doug Barth (O'Reilly)
- "Identity-Native Infrastructure" by Phil Vachon (O'Reilly)

### Conference Talks

- [SPIFFE and SPIRE: Universal Workload Identity - KubeCon](https://www.youtube.com/watch?v=Q2SiGeebRKY)
- [Deep Dive: SPIRE - KubeCon](https://www.youtube.com/watch?v=sXnJgJvB8qk)
- [OPA Deep Dive - KubeCon](https://www.youtube.com/watch?v=Vdy26oS3stU)

---

## Glossary

| Term                  | Definition                                                         |
| --------------------- | ------------------------------------------------------------------ |
| **Attestation**       | The process of verifying a workload's identity                     |
| **Audience (aud)**    | JWT claim identifying intended recipient of the token              |
| **azp**               | Authorized party - the client that obtained/exchanged the token    |
| **ext-proc**          | Envoy external processing filter for request/response modification |
| **mTLS**              | Mutual TLS - both parties authenticate each other                  |
| **OPA**               | Open Policy Agent - policy decision point                          |
| **Rego**              | OPA's declarative policy language                                  |
| **RFC 8693**          | OAuth 2.0 Token Exchange specification                             |
| **SPIFFE**            | Secure Production Identity Framework for Everyone                  |
| **SPIFFE ID**         | URI identifying a workload (e.g., `spiffe://domain/path`)          |
| **SPIRE**             | SPIFFE Runtime Environment (reference implementation)              |
| **Subject token**     | The original token being exchanged in token exchange flow          |
| **SVID**              | SPIFFE Verifiable Identity Document                                |
| **Token exchange**    | Swapping one token for another with different audience/scope       |
| **Trust Domain**      | The root of trust in SPIFFE (like a DNS domain)                    |
| **Workload**          | A software system that needs an identity                           |
| **Workload API**      | Unix socket interface for fetching SVIDs                           |
| **X.509**             | Standard format for public key certificates                        |
| **Zero Trust**        | Security model: "never trust, always verify"                       |
