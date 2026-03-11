# Credential gateway for heterogeneous services

## Research document

**Status**: Draft for team discussion
**Date**: 2026-03-10
**Context**: After implementing RFC 8693 act claim chaining for
delegation tracking, we need to extend the pattern to real-world
services that don't speak OAuth/OIDC.

## Problem statement

Our current AuthBridge flow produces JWTs with nested `act` claims
that cryptographically prove the delegation chain:

```text
User (Alice) -> Agent (Summarizer) -> Document Service
```

The document-service validates the JWT, extracts the delegation
chain, and OPA computes the permission intersection:

```text
Effective Permissions = User Departments ∩ Agent Capabilities
```

This works because document-service is **our service** — we control
its authentication. Real-world applications use diverse authn/authz
mechanisms:

| Service    | Auth mechanism    | Credential type                            |
| ---------- | ----------------- | ------------------------------------------ |
| AWS S3     | IAM/STS           | ACCESS_KEY + SECRET_KEY (or session token) |
| GitHub     | OAuth / PAT       | Fine-grained PAT or App installation token |
| Slack      | Bot tokens        | OAuth Bot token with scopes                |
| PostgreSQL | Username/password | Connection credentials                     |
| SSH hosts  | Certificates      | SSH certificates or keys                   |
| Kubernetes | ServiceAccount    | Bearer token or X.509                      |

**The core challenge**: How do we translate our JWT with act claims
into service-specific credentials that enforce the permission
intersection?

### Concrete example: S3

- **Alice** has access to S3 prefixes: `s3://data/finance/*`,
  `s3://data/engineering/*` (within a shared bucket)
- **Summarizer agent** capabilities: `engineering`, `admin`
- **Permission intersection**: `s3://data/engineering/*` only
- **Need**: An AWS session scoped to `s3://data/engineering/*`
  that the Summarizer uses when acting on Alice's behalf

### Concrete example: GitHub

- **Alice** has access to repos: `finance-reports`, `eng-roadmap`
- **Summarizer agent** capabilities: `engineering`
- **Permission intersection**: `eng-roadmap` only
- **Need**: A GitHub token scoped to the `eng-roadmap` repository

## Architectural patterns

### Pattern 1: Credential broker (Vault-centric)

```text
                              ┌──────────────┐
  JWT with act claims         │              │    Dynamic
  ─────────────────────────►  │  HashiCorp   │    credentials
  (OIDC auth method)          │    Vault     │  ────────────►
                              │              │  (scoped to
  OPA intersection ────────►  │  Policy      │   intersection)
  (external policy input)     │  evaluation  │
                              └──────────────┘
```

**How it works:**

1. Agent presents JWT (with act claims) to Vault's JWT/OIDC
  auth backend
2. Vault authenticates the JWT and maps claims to a Vault identity
3. A policy computation step (external or via Vault Sentinel)
  determines the intersection of user and agent permissions
4. Vault's dynamic secrets engine generates scoped credentials:
- **AWS**: STS `AssumeRole` with an inline session policy
   restricting to the intersection
- **Database**: Time-limited credentials with reduced privileges
- **SSH**: Signed certificates with restricted principals

**AWS STS session policies** are particularly well-suited because
they natively implement permission intersection:

```text
Effective permissions = IAM role policy ∩ Session policy
```

This is exactly our model. If Alice's IAM role grants access to
`finance/*` and `engineering/*`, and the session policy (computed
from the agent intersection) only allows `engineering/*`, the
effective permissions are `engineering/*`.

Session policies can be passed as inline JSON (up to 2,048 chars)
or as up to 10 managed policy ARNs. They work with `AssumeRole`,
`AssumeRoleWithSAML`, and `AssumeRoleWithWebIdentity`. If a
permissions boundary is also present:

```text
Effective = Identity Policy ∩ Session Policy ∩ Permissions Boundary
```

**Note**: Resource-based policies that name the session ARN as
principal are additive (not filtered by the session policy).

Vault's AWS secrets engine supports three credential types:

- `**assumed_role`**: Calls `sts:AssumeRole`, returns temporary
credentials. Supports session policies for intersection.
- `**federation_token**`: Calls `sts:GetFederationToken` with a
supplied policy document. Effective permissions =
root credentials ∩ inline policy ∩ managed policies.
- `**iam_user**`: Creates a real IAM user (not STS-based).

The **JWT/OIDC auth method** supports static keys, JWKS URLs, and
OIDC Discovery. External JWTs (from Keycloak, SPIRE, etc.) can be
validated without a browser flow. Roles define `bound_audiences`,
`bound_claims`, and claim-to-policy mappings — our act-claim JWTs
can authenticate directly.

**Strengths:**

- Vault is mature and widely adopted
- Dynamic secrets engines exist for AWS, Azure, GCP, databases,
SSH, Kubernetes, PKI, and more
- Built-in audit logging, lease management, revocation
- JWT/OIDC auth backend can consume our act-claim tokens directly
- `federation_token` credential type explicitly implements
permission intersection
- Enterprise version supports Sentinel policies for complex logic

**Weaknesses:**

- Vault policy language is path-based, not claim-aware — computing
intersection from act claims requires custom logic (external
policy engine or Sentinel in Enterprise)
- Each target service type needs a configured secrets engine
- Operational complexity of running Vault in production
- Open-source Vault (now OpenBao after the BSL change) lacks
Sentinel; intersection logic must live outside Vault

**Open source**: Vault is BSL-licensed since 2023. **OpenBao**
(Linux Foundation fork) is the open-source alternative with
identical dynamic secrets engines.

### Pattern 2: Scoped credential vending machine

```text
┌──────────┐     ┌─────────────────────┐     ┌──────────────┐
│  Agent   │────►│ Credential Vending  │────►│ Target       │
│  (JWT)   │     │ Machine             │     │ Service      │
└──────────┘     │                     │     └──────────────┘
                 │ 1. Validate JWT     │
                 │ 2. Extract act chain│
                 │ 3. Query OPA for    │
                 │    intersection     │
                 │ 4. Generate scoped  │
                 │    credential       │
                 └─────────────────────┘
                          │
                    ┌─────▼─────┐
                    │    OPA    │
                    │ (policy)  │
                    └───────────┘
```

**How it works:**

A purpose-built microservice that:

1. Accepts the JWT with act claims
2. Parses the delegation chain from nested `act` claims
3. Queries OPA with the chain + target service to compute the
  permission intersection
4. Calls the target service's credential API to generate scoped
  credentials:
- AWS: `sts:AssumeRole` with computed session policy
- GitHub: Create a scoped installation token via GitHub App API
- Database: Create a temporary user with restricted grants
- S3 presigned URLs: Generate URLs for allowed paths only

**Strengths:**

- Full control over intersection logic
- OPA integration reuses our existing policy infrastructure
- Can handle any target service with a credential API
- No dependency on Vault or other infrastructure

**Weaknesses:**

- Custom development for each service type (credential plugins)
- Must manage credential lifecycle (expiry, rotation, revocation)
- Becomes a critical security component that needs hardening
- Duplicates some Vault functionality

### Pattern 3: Identity-aware proxy with credential injection

```text
┌──────────┐     ┌──────────────────┐     ┌──────────────┐
│  Agent   │────►│  Envoy/Proxy     │────►│ Target       │
│  (JWT)   │     │  + ext-proc      │     │ Service      │
└──────────┘     │                  │     └──────────────┘
                 │ 1. Validate JWT  │
                 │ 2. Compute       │
                 │    intersection  │
                 │ 3. Inject creds  │
                 │    into request  │
                 │ 4. Filter        │
                 │    responses     │
                 └──────────────────┘
```

**How it works:**

Extends our existing Envoy ext-proc pattern. Instead of just
exchanging tokens, the proxy:

1. Validates the incoming JWT with act claims
2. Computes the permission intersection via OPA
3. Retrieves or generates credentials for the target service
4. Injects credentials into the outgoing request
  (e.g., AWS SigV4 signing, Authorization header)
5. Optionally filters responses to remove data outside the
  intersection scope

This is similar to what **HashiCorp Boundary** does for SSH and
database sessions. Boundary supports two modes: **credential
brokering** (Community Edition) where credentials are returned to
the user, and **credential injection** (HCP/Enterprise) where
credentials are injected into the session and the user never sees
them. Boundary ties credential lifecycle to session lifecycle —
when a session ends, the Vault lease is revoked.

**Strengths:**

- Transparent to the agent — it just makes HTTP requests
- Builds on our existing Envoy + ext-proc architecture
- Request-level filtering provides defense in depth
- No credential exposure to the agent itself

**Weaknesses:**

- Only works for HTTP-based services (not SSH, raw TCP)
- Proxy must understand each target service's API for filtering
- Credential management still needed (where do S3 keys live?)
- Performance overhead of per-request policy evaluation
- Complex to implement response filtering correctly

### Pattern 4: Capability tokens (Biscuit/Macaroons)

```text
JWT with act claims
        │
        ▼
┌───────────────┐     Attenuated        ┌──────────────┐
│  Capability   │     Biscuit token     │ Target       │
│  Token Forge  │────────────────────►  │ Service      │
│               │  (intersection is     │ (validates   │
│ Computes      │   cryptographically   │  Biscuit)    │
│ intersection, │   enforced)           └──────────────┘
│ bakes into    │
│ token         │
└───────────────┘
```

**How it works:**

Capability-based tokens like **Biscuit** support a property called
**attenuation**: any holder of a token can add restrictions to it
(but never expand permissions). This maps naturally to delegation
chains:

1. Alice's base token grants: `read(finance), read(engineering)`
2. When delegating to Summarizer, attenuate:
  `restrict(capabilities, [engineering, admin])`
3. Resulting token: `read(engineering)` — the intersection is
  cryptographically enforced in the token itself

**Biscuit** uses a Datalog-based authorization language:

```
// Alice's authority block
right("s3", "finance/*", "read");
right("s3", "engineering/*", "read");

// Attenuation block (added during delegation)
check if right($service, $path, $action),
  $path.starts_with("engineering/");
```

Attenuation works structurally: each attenuated block adds checks
that must all pass. The effective capability is the intersection
of the original token's authority and all attenuation blocks.
Tokens use Ed25519 public key cryptography (not HMAC like
Macaroons), so anyone with the public key can verify — no shared
secret needed.

**Biscuit vs. Macaroons:**

| Property        | Biscuit                        | Macaroons                   |
| --------------- | ------------------------------ | --------------------------- |
| Crypto          | Public key (Ed25519)           | HMAC (shared secret)        |
| Policy language | Datalog (formal, expressive)   | Opaque bytes (BYO encoding) |
| Verification    | Anyone with public key         | Only secret holders         |
| Governance      | Eclipse Foundation, Apache 2.0 | Google (original paper)     |

**Production users**: Clever Cloud (Apache Pulsar, internal
tooling), Space and Time (decentralized data platform).
Libraries exist for Rust (reference), Go, Java, Python,
WebAssembly, Haskell, .NET.

**Strengths:**

- Permission intersection is cryptographic, not policy-based
- Each delegation step can only reduce permissions (by design)
- No central policy engine needed for intersection computation
- Offline verification — no network calls to validate
- Directly models delegation chains (each block = one hop)
- Open source, Apache 2.0 (Eclipse Foundation)

**Weaknesses:**

- Target services must understand Biscuit tokens — requires
integration work or a translation proxy
- Moderate adoption (growing but not mainstream)
- Mapping between Biscuit facts and service-specific permissions
requires careful design
- No existing integrations with AWS, GitHub, Slack, etc.

### Pattern 5: Cloud-native workload identity federation

```text
┌──────────┐     SPIFFE SVID      ┌─────────────┐
│  Agent   │────────────────────► │ Cloud IAM   │
│          │     (X.509 or JWT)   │ Federation  │
└──────────┘                      │             │
                                  │ Maps SPIFFE │
                                  │ ID to role  │
                                  └──────┬──────┘
                                         │ Scoped cloud
                                         │ credentials
                                         ▼
                                  ┌─────────────┐
                                  │ Cloud       │
                                  │ Service     │
                                  └─────────────┘
```

**How it works:**

Cloud providers have native support for federating external
identities:

- **AWS IAM Roles Anywhere**: X.509 certificates (SPIFFE SVIDs)
map to IAM roles with session policies
- **GCP Workload Identity Federation**: OIDC tokens or SPIFFE
SVIDs map to GCP service accounts
- **Azure Workload Identity**: Federated credentials from
external OIDC issuers

**Strengths:**

- No intermediate credential broker needed
- Native cloud integration, well-supported
- SPIFFE identity directly usable as authentication
- Short-lived credentials generated by the cloud provider

**Weaknesses:**

- Only works for cloud services (AWS, GCP, Azure)
- Doesn't solve GitHub, Slack, databases, SSH
- Permission intersection requires mapping act claims to session
policies — the federation endpoint doesn't understand act claims
- Each cloud provider has different federation mechanisms

## Comparison matrix

| Criterion                  | Vault/OpenBao      | Vending Machine    | Proxy             | Biscuit          | Cloud Federation |
| -------------------------- | ------------------ | ------------------ | ----------------- | ---------------- | ---------------- |
| Permission intersection    | Needs custom logic | OPA-native         | OPA-native        | Cryptographic    | Session policies |
| Service coverage           | Broad (plugins)    | Custom per service | HTTP only         | Needs adoption   | Cloud only       |
| Credential lifecycle       | Built-in (leases)  | Must build         | Must build        | Token-based      | Cloud-managed    |
| Operational complexity     | High               | Medium             | Medium            | Low              | Low              |
| Delegation chain awareness | JWT auth only      | Full (act claims)  | Full (act claims) | Native (blocks)  | Limited          |
| Open source                | OpenBao (LF)       | Custom             | Envoy (CNCF)      | Yes (Rust)       | N/A (vendor)     |
| Maturity                   | Production-ready   | Greenfield         | Proven pattern    | Early            | Production-ready |
| Agent credential exposure  | Agent gets creds   | Agent gets creds   | No exposure       | Agent gets token | Agent gets creds |

## Recommended architecture: Hybrid approach

No single pattern solves all cases. The most practical approach
combines patterns based on service type:

```text
                    ┌──────────────────────────────────────┐
                    │       Credential Gateway             │
                    │                                      │
  JWT with ─────►   │  ┌─────────────────────────────┐     │
  act claims        │  │  1. Validate JWT + act chain │     │
                    │  │  2. Query OPA for            │     │
                    │  │     permission intersection  │     │
                    │  └──────────────┬──────────────┘     │
                    │                 │                     │
                    │    ┌────────────┼────────────┐       │
                    │    ▼            ▼            ▼       │
                    │ ┌──────┐  ┌──────────┐  ┌────────┐  │
                    │ │Cloud │  │ Vault/   │  │Service │  │
                    │ │ STS  │  │ OpenBao  │  │-specific│ │
                    │ │      │  │          │  │adapters│  │
                    │ └──┬───┘  └────┬─────┘  └───┬────┘  │
                    └────┼──────────┼─────────────┼───────┘
                         ▼          ▼             ▼
                    ┌────────┐ ┌────────┐  ┌───────────┐
                    │AWS/GCP │ │Database│  │GitHub/    │
                    │Azure   │ │SSH     │  │Slack/etc  │
                    └────────┘ └────────┘  └───────────┘
```

### Components

**1. Credential Gateway (new microservice)**

The gateway is the single entry point. It:

- Validates the JWT and extracts the delegation chain from
`act` claims
- Queries OPA with the user identity, agent identity, and
target service to compute the permission intersection
- Routes to the appropriate credential backend

This is essentially Pattern 2 (Vending Machine) as the
orchestration layer.

**2. OPA policy extension**

Extend our existing OPA policies to compute service-specific
permission intersections:

```rego
# Compute the intersection for a specific target service
intersection := result {
    user_perms := data.service_permissions[input.user_id][input.target_service]
    agent_caps := data.agent_capabilities[input.agent_id][input.target_service]
    result := user_perms & agent_caps
}

# For S3: compute allowed prefix paths
s3_session_policy := policy {
    allowed := intersection
    policy := {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": array.concat(
                ["arn:aws:s3:::data"],
                [sprintf("arn:aws:s3:::data/%v/*", [prefix]) |
                    prefix := allowed[_]])
        }]
    }
}
```

**3. Backend-specific credential adapters**

| Backend    | Mechanism                         | Intersection enforcement           |
| ---------- | --------------------------------- | ---------------------------------- |
| AWS S3     | STS `AssumeRole` + session policy | Native (AWS enforces intersection) |
| GitHub     | GitHub App installation token     | Scoped to repository subset        |
| Slack      | Proxy-based (filter channels)     | Gateway filters API calls          |
| PostgreSQL | Vault database secrets engine     | Dynamic user with restricted GRANT |
| SSH        | Vault SSH secrets engine          | Signed certificate with principals |
| Kubernetes | Pre-scoped ServiceAccount + RBAC  | Restricted RBAC rules per SA       |

### AWS S3 walkthrough

Step-by-step for the Alice + Summarizer + S3 example:

1. **Summarizer** receives Alice's delegated JWT with:

  ```json
   {"sub": "summarizer", "act": {"sub": "alice"}}
  ```

1. **Summarizer** calls the Credential Gateway:

  ```text
   POST /credentials
   Authorization: Bearer <JWT-with-act-claims>
   {"target_service": "s3", "action": "read"}
  ```

1. **Gateway** validates the JWT, extracts the chain, calls OPA:

  ```json
   {
     "user": "alice",
     "agent": "summarizer",
     "target": "s3",
     "action": "read"
   }
  ```
1. **OPA** returns the intersection:

  ```json
   {"allowed_buckets": ["engineering"]}
  ```

1. **Gateway** calls AWS STS:

  ```text
   AssumeRole(
     RoleArn: "arn:aws:iam::123:role/delegated-access",
     Policy: {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Allow",
         "Action": ["s3:GetObject", "s3:ListBucket"],
         "Resource": [
           "arn:aws:s3:::data",
           "arn:aws:s3:::data/engineering/*"
         ]
       }]
     },
     DurationSeconds: 900
   )
  ```
1. **Gateway** returns temporary credentials to Summarizer:

  ```json
   {
     "access_key_id": "ASIA...",
     "secret_access_key": "...",
     "session_token": "...",
     "expiration": "2026-03-10T15:00:00Z"
   }
  ```

1. **Summarizer** uses the credentials to access S3 — can only
  read from `engineering/`*

### GitHub walkthrough

1. **Summarizer** calls the Credential Gateway with the delegated
  JWT
2. **OPA** computes intersection: Alice's repos ∩ Summarizer's
  capabilities → `[eng-roadmap]`
3. **Gateway** uses a GitHub App (installed on the org) to create
  an installation token scoped to specific repositories:
4. **Summarizer** receives a GitHub token that only works for
  `eng-roadmap` with read-only access

## Implementation phases

| Phase | Description                                                         | Complexity   |
| ----- | ------------------------------------------------------------------- | ------------ |
| 1     | Credential Gateway skeleton with JWT validation and OPA integration | Medium       |
| 2     | AWS S3 adapter using STS session policies                           | Medium       |
| 3     | GitHub adapter using GitHub App installation tokens                 | Medium       |
| 4     | Vault/OpenBao integration for databases and SSH                     | High         |
| 5     | Proxy mode for services without credential APIs (Slack, etc.)       | High         |
| 6     | Biscuit token support for service-to-service chains                 | Experimental |

## Open questions

1. **Credential caching**: Should the gateway cache credentials
  for repeated requests with the same intersection? STS sessions
   last 15 min to 12 hours. Caching reduces STS calls but adds
   complexity.
2. **Credential revocation**: If Alice revokes delegation to
  Summarizer, how do we invalidate already-issued S3 sessions?
   Individual STS sessions can't be deleted via API, but AWS
   provides immediate containment: an IAM deny policy with
   `aws:TokenIssueTime` condition revokes all sessions issued
   before a given timestamp. Options:
- Short TTLs (15 min) to limit exposure window
- IAM deny policy with `aws:TokenIssueTime` for immediate
     role-level revocation
- Vault's lease revocation for Vault-issued credentials
1. **Multi-hop credential chains**: In our current flow,
  User → Agent → Summarizer → Document Service, the Summarizer
   might need to access S3 on behalf of the user via the agent.
   Should the Credential Gateway accept multi-level act chains
   and compute the intersection across all hops?
2. **Audit trail**: The act claim chain provides audit for the
  JWT flow. When we translate to service-specific credentials,
   how do we maintain the audit trail? Options:
- Tag AWS sessions with `alice-via-summarizer`
- Log all credential issuance in the gateway with full chain
- Use CloudTrail / audit logs with session name correlation
1. **Separation of credential storage**: Where do the "master"
  credentials live (the IAM role ARN, the GitHub App private
   key, the database root password)? Options:
- Vault (purpose-built for this)
- Kubernetes Secrets (simpler but less secure)
- Cloud-native secret managers (AWS Secrets Manager, etc.)
1. **Service mesh integration**: Should the Credential Gateway
  be a standalone service, an Envoy ext-proc filter, or
   integrated into a service mesh? Our ext-proc pattern could
   extend naturally, but the gateway needs state (credential
   cache, Vault connections).

## Related work and references

| Project                                                                                                                                                                          | Relevance                                            |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| [OpenBao](https://openbao.org/)                                                                                                                                                  | Open-source Vault fork (LF); dynamic secrets engines |
| [HashiCorp Boundary](https://www.boundaryproject.io/)                                                                                                                            | Session-based credential injection                   |
| [Biscuit](https://www.biscuitsec.org/)                                                                                                                                           | Capability tokens with attenuation                   |
| [Teleport](https://goteleport.com/)                                                                                                                                              | Certificate-based access to infrastructure           |
| [Athenz](https://www.athenz.io/)                                                                                                                                                 | CNCF role-based authorization with temp credentials  |
| [SPIFFE OIDC Federation](https://spiffe.io/docs/latest/keyless/)                                                                                                                 | SPIFFE to cloud identity federation                  |
| [AWS IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/)                                                                                                             | X.509 to IAM role mapping                            |
| [AWS STS Session Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session)                                                               | Native permission intersection                       |
| [GitHub App Installation Tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app) | Repository-scoped tokens                             |

## Conclusion

The permission intersection model we built for document-service
extends naturally to external services, but through different
mechanisms per service type. The key insight is:

**AWS STS session policies already implement permission
intersection natively.** This is the cleanest path for AWS
services and validates our architectural model.

For other services, we need a **Credential Gateway** that:

1. Accepts our JWT with act claims (reusing AuthBridge patterns)
2. Computes intersection via OPA (reusing our policy engine)
3. Translates to service-specific credentials via adapters

The recommended starting point is **AWS S3 via STS session
policies** — it demonstrates the full pattern with minimal custom
code and leverages a well-understood intersection mechanism.
OpenBao/Vault can be added later as the credential backend for
services that need dynamic secret generation (databases, SSH).

Biscuit tokens are worth watching as a longer-term solution — their
native attenuation model is a perfect fit for delegation chains,
but adoption is still early.
