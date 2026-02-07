# AuthBridge integration learning guide

This document captures a Socratic exploration of integrating the Kagenti AuthBridge with this Zero Trust demo. It preserves the discovery process to help others understand not just *what* to integrate, but *why* each component matters.

## Table of contents

1. [Background](#background)
2. [The Socratic exploration](#the-socratic-exploration)
3. [Key discoveries](#key-discoveries)
4. [Integration architecture](#integration-architecture)
5. [Implementation plan](#implementation-plan)
6. [Resource credential exchange](#resource-credential-exchange)
7. [Glossary of new terms](#glossary-of-new-terms)
8. [References](#references)

---

## Background

### What is AuthBridge?

AuthBridge is a component of the [Kagenti project](https://github.com/kagenti) that provides transparent token exchange for Kubernetes workloads. It combines:

- **SPIFFE/SPIRE** for workload identity
- **Keycloak** for token management and user identity
- **Envoy proxy** with external processing for transparent token exchange

### Why integrate with this demo?

This Zero Trust demo already demonstrates:

- SPIFFE-based workload identity
- OPA policy-based authorization
- Permission intersection (user permissions ∩ agent capabilities)

AuthBridge adds:

- **Real-time token exchange** (audience re-scoping per request)
- **Dynamic user attributes** from Keycloak (instead of hardcoded OPA data)
- **Session-based revocation** (immediately revoke agent access)

### The learning method

This exploration used the [Socratic dialogue method](https://github.com/hardwaylabs/learning-prompts) - a teaching approach that uses carefully sequenced questions to guide discovery rather than direct explanation.

---

## The Socratic exploration

### Question 1: Observing the token transformation

**Question**: In the AuthBridge demo, you obtained a token using `client_credentials` grant, then called `auth-target`. When you decoded the token before and after calling the service through the proxy, what did you notice about the `aud` (audience) claim?

**Discovery**: The `aud` claim changed from the agent's SPIFFE ID to `auth-target`. This transformation happens in the AuthProxy sidecar's `ext-proc` container, which performs RFC 8693 token exchange with Keycloak.

**Insight**: The two-step process (get token → exchange per target) enables centralized control. Keycloak can dynamically change permissions, and tokens can be revoked - unlike a pre-issued broad token.

---

### Question 2: Comparing token strategies

**Question**: Consider two scenarios:

- **Scenario A**: Agent gets one token with `aud: [auth-target, billing-service, user-db]`
- **Scenario B**: Agent gets token with `aud: agent-spiffe-id`, then exchanges per target

How does Scenario B relate to the permission intersection pattern?

**Discovery**: Scenario B adds a **temporal dimension** to authorization. With per-request exchange:

- Time-bounded delegation becomes possible ("access for 2 hours only")
- Policies are evaluated at access time, not token issuance time
- Revocation takes effect immediately

**Insight**: The exchange moment provides information that wasn't available at token issuance:

- Which specific target is being accessed?
- Is the delegation still valid?
- Have policies changed since the original token was issued?

---

### Question 3: Real-time policy checks

**Question**: Given this timeline:

```text
10:00 AM - Alice delegates to GPT-4, agent gets token
10:15 AM - Security discovers GPT-4 vulnerability
10:16 AM - Admin revokes GPT-4's finance access in Keycloak
10:20 AM - GPT-4 tries to access DOC-002 (finance)
```

What happens with pre-issued tokens vs. AuthBridge exchange?

**Discovery**:

- **Pre-issued token**: GPT-4 still has valid token, access succeeds (security gap)
- **AuthBridge exchange**: ext-proc contacts Keycloak, exchange fails, access denied

**Insight**: Token exchange implements "verify on every access" - a core Zero Trust principle.

---

### Question 4: Separating concerns (Keycloak vs OPA)

**Question**: What should Keycloak decide vs. what should OPA decide?

**Discovery**: There's a natural separation:

| Layer                      | Tool            | Decides                                           |
| -------------------------- | --------------- | ------------------------------------------------- |
| Authentication             | Keycloak        | "Is this a valid agent with valid delegation?"    |
| Coarse authorization       | Keycloak scopes | "Can this agent talk to document-service at all?" |
| Fine-grained authorization | OPA             | "Can this agent access THIS specific document?"   |

**Insight**: Keycloak excels at identity and session management. OPA excels at evaluating complex rules over structured data (document-to-department mappings, permission intersection).

---

### Question 5: Integration point for OPA

**Question**: Should ext-proc (caller-side) call OPA, or should document-service (target-side) call OPA?

**Discovery**: Target-side authorization is more appropriate because:

- Only document-service knows which specific document is being requested
- Only document-service has access to document metadata (required departments)
- ext-proc only sees the target service, not the resource within it

**Insight**: This reveals the **Resource Gateway** pattern:

```text
Agent → AuthBridge → document-service → OPA
                           ↓
                     (knows document metadata)
```

Each resource type (S3, GitHub, Slack) needs a gateway that understands its resources.

---

### Question 6: Data flow in mTLS vs JWT

**Question**: Looking at `document-service/cmd/serve.go`, what identity information comes from mTLS vs. from the request body?

**Discovery**:

| Data               | Current (mTLS)      | With JWT                 |
| ------------------ | ------------------- | ------------------------ |
| Caller identity    | TLS certificate SAN | JWT `sub` or `azp` claim |
| User departments   | OPA static lookup   | JWT `groups` claim       |
| Delegation context | Request body JSON   | Request body JSON        |

**Insight**: The key change is where user departments come from. Currently OPA looks them up from hardcoded data. With JWT, they come directly from Keycloak (source of truth).

---

### Question 7: Detecting delegation from JWT claims

**Question**: How would document-service detect delegation from JWT claims alone?

**Discovery**: Compare `sub` (subject) with `azp` (authorized party):

```json
{
  "sub": "alice",
  "azp": "spiffe://demo.example.com/agent/gpt4",
  "groups": ["engineering", "finance"]
}
```

If `sub != azp`, delegation is occurring:

- `sub` = the human user (alice)
- `azp` = the client that obtained/exchanged the token (gpt4)

**Insight**: The JWT carries all information needed to construct the delegation context for OPA.

---

### Question 8: OPA is already prepared

**Question**: Looking at `opa-service/policies/user_permissions.rego`, is OPA ready for JWT claims?

**Discovery**: Yes! The policy already has priority rules:

```rego
# Rule 1: Use JWT claims from direct access
get_departments(_) := departments if {
    not input.delegation
    departments := input.user_departments
    count(departments) > 0
}

# Rule 2: Use JWT claims from delegation
get_departments(_) := departments if {
    input.delegation
    departments := input.delegation.user_departments
    count(departments) > 0
}

# Rule 3: Fallback to hardcoded (mock mode only)
get_departments(user_name) := departments if {
    not jwt_claims_provided
    departments := user_departments_fallback[user_name]
}
```

**Insight**: The integration only requires document-service to extract JWT claims and pass them to OPA. No OPA policy changes needed!

---

### Question 9: JWT validation with JWKS

**Question**: Should document-service validate the JWT, or trust that AuthBridge already validated it?

**Discovery**: "Always verify" means always verify. Document-service should:

1. Fetch Keycloak's public keys from JWKS endpoint
2. Validate JWT signature
3. Then extract claims

Keycloak's JWKS endpoint:

```text
http://keycloak-service.keycloak.svc:8080/realms/demo/protocol/openid-connect/certs
```

**Insight**: JWKS fetching should bypass AuthBridge proxy (direct to Keycloak) to avoid circular dependencies.

---

## Key discoveries

### Discovery 1: Permission re-scoping happens at multiple levels

```text
Level 1: Audience narrowing (AuthBridge)
         Token scoped to specific target service

Level 2: Claim-based filtering (Keycloak → JWT)
         User groups/roles embedded in token

Level 3: Permission intersection (OPA)
         effective = user_departments ∩ agent_capabilities

Level 4: Resource-specific rules (OPA)
         Does effective permission satisfy document requirements?
```

### Discovery 2: The temporal dimension

Pre-issued tokens are a snapshot. Token exchange enables:

- Real-time revocation
- Time-bounded delegation
- Policy changes that take effect immediately
- Audit trail of which client performed each exchange

### Discovery 3: Identity vs. policy separation

| Aspect                  | Managed by | Examples                             |
| ----------------------- | ---------- | ------------------------------------ |
| User identity           | Keycloak   | alice is in engineering group        |
| User sessions           | Keycloak   | alice's session is valid for 8 hours |
| Agent capabilities      | OPA        | summarizer can only access finance   |
| Resource requirements   | OPA        | DOC-002 requires finance department  |
| Permission intersection | OPA        | effective = user ∩ agent             |

### Discovery 4: The OPA policies were designed for this

The `user_permissions.rego` already prioritizes JWT claims over fallback data. The comment at line 5-6 states:

```rego
# User-to-department mappings (fallback)
# In production, prefer JWT claims from OIDC provider
```

---

## Integration architecture

### Component responsibilities

```text
┌─────────────────────────────────────────────────────────────────────────┐
│  PHASE 1: User delegates to agent (Keycloak)                            │
├─────────────────────────────────────────────────────────────────────────┤
│  Alice logs in → delegates to GPT-4 agent                               │
│  Agent gets token: aud=agent-spiffe-id, sub=alice, azp=gpt4             │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  PHASE 2: Audience re-scoping (AuthBridge ext-proc)                     │
├─────────────────────────────────────────────────────────────────────────┤
│  Agent calls document-service with token                                │
│  ext-proc intercepts → exchanges token via Keycloak (RFC 8693)          │
│  New token: aud=document-service, sub=alice, azp=gpt4,                  │
│             groups=[engineering, finance]                               │
│                                                                         │
│  ✓ Keycloak can DENY if agent is revoked                                │
│  ✓ Token now scoped to THIS service only                                │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  PHASE 3: Fine-grained authorization (document-service + OPA)           │
├─────────────────────────────────────────────────────────────────────────┤
│  document-service validates JWT against Keycloak JWKS                   │
│  Extracts: sub=alice, azp=gpt4, groups=[engineering, finance]           │
│  Detects delegation (sub != azp)                                        │
│  Calls OPA with:                                                        │
│    {                                                                    │
│      delegation: {                                                      │
│        user_spiffe_id: "spiffe://.../user/alice",                       │
│        agent_spiffe_id: "spiffe://.../agent/gpt4",                      │
│        user_departments: ["engineering", "finance"]                     │
│      },                                                                 │
│      document_metadata: { required_departments: ["finance"] }           │
│    }                                                                    │
│                                                                         │
│  OPA computes intersection → ALLOW or DENY                              │
└─────────────────────────────────────────────────────────────────────────┘
```

### What each component contributes

| Component           | Responsibility                    | Re-scoping contribution                   |
| ------------------- | --------------------------------- | ----------------------------------------- |
| Keycloak            | User auth, groups, sessions       | Source of truth for user→department       |
| AuthBridge ext-proc | Token exchange per target         | Audience narrowing, real-time revocation  |
| document-service    | JWT validation, resource metadata | Combines identity + resource requirements |
| OPA                 | Policy evaluation                 | Permission intersection (user ∩ agent)    |

---

## Implementation plan

### Prerequisites

- Keycloak already running (from Phase 4)
- SPIFFE/SPIRE already running
- Existing OPA policies support JWT claims

### Phase 1: Keycloak configuration

**Goal**: Enable token exchange in Keycloak

Tasks:

1. Enable token exchange in demo realm settings
2. Create `document-service` client (audience for exchanged tokens)
3. Configure `agent-spiffe-aud` scope to include SPIFFE ID in tokens
4. Verify token exchange works manually

**Verification**:

```bash
# Get initial token
TOKEN=$(curl -sX POST .../token -d 'grant_type=client_credentials' ...)

# Exchange for document-service audience
EXCHANGED=$(curl -sX POST .../token \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  -d 'subject_token='$TOKEN \
  -d 'audience=document-service' ...)

# Verify audience changed
echo $EXCHANGED | jq -r '.access_token' | cut -d. -f2 | base64 -d | jq .aud
```

### Phase 2: Add AuthProxy to agent pod

**Goal**: Transparent token exchange for agent-service

Tasks:

1. Build ext-proc and envoy images from AuthBridge repo
2. Add sidecar containers to agent-service deployment:
   - `envoy-proxy`: intercepts outbound traffic
   - `ext-proc`: performs token exchange
3. Add `client-registration` init container
4. Add `proxy-init` for iptables traffic interception
5. Configure `OUTBOUND_PORTS_EXCLUDE` for Keycloak access

**Files to create/modify**:

```text
deploy/k8s/base/agent-service-authproxy.yaml  (new)
deploy/k8s/base/kustomization.yaml            (add patch)
```

**Verification**:

```bash
# Check client registration
kubectl logs deployment/agent-service -c client-registration

# Check token exchange in envoy logs
kubectl logs deployment/agent-service -c envoy-proxy | grep "token"
```

### Phase 3: Modify document-service for JWT

**Goal**: Accept and validate JWTs, extract claims for OPA

Tasks:

1. Add JWT validation library (`github.com/golang-jwt/jwt/v5`)
2. Add JWKS fetcher (`github.com/MicahParks/keyfunc/v3`)
3. Modify `handleAccess` to check for `Authorization: Bearer` header
4. Extract claims and detect delegation (`sub != azp`)
5. Pass `user_departments` from JWT to OPA

**Code changes in** `document-service/cmd/serve.go`:

```go
// New: JWT validation at startup
jwksURL := "http://keycloak-service.keycloak.svc:8080/realms/demo/protocol/openid-connect/certs"
jwks, err := keyfunc.NewDefault([]string{jwksURL})

// In handleAccess: check for JWT
if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
    tokenString := strings.TrimPrefix(authHeader, "Bearer ")
    token, err := jwt.Parse(tokenString, jwks.Keyfunc,
        jwt.WithValidMethods([]string{"RS256"}),
        jwt.WithAudience("document-service"),
    )
    // Extract claims, detect delegation, build OPA input
}
```

**Verification**:

```bash
# Call with JWT (from inside agent pod)
curl -H "Authorization: Bearer $TOKEN" http://document-service:8084/access \
  -d '{"document_id": "DOC-002"}'
```

### Phase 4: End-to-end testing

**Goal**: Verify complete flow with permission re-scoping

Test scenarios:

1. **Direct user access** (no agent): Alice → DOC-001 ✓
2. **Delegated access allowed**: Alice → GPT-4 → DOC-002 ✓
3. **Delegated access denied** (intersection empty): Carol → GPT-4 → DOC-002 ✗
4. **Revocation test**: Revoke GPT-4 in Keycloak, verify immediate denial
5. **Time-bounded test**: Set short session timeout, verify expiration

**Dashboard updates** (optional):

- Show token exchange in flow visualization
- Display JWT claims in access details
- Indicate "via AuthBridge" in audit log

---

## Resource credential exchange

### The "last mile" problem

After OPA approves access, the resource gateway must actually fetch the resource. This raises a critical question: **what credentials does the gateway use to access S3, GitHub, or other backend services?**

This exploration revealed two authorization layers that must align:

| Layer              | Decision maker | Scope                               |
| ------------------ | -------------- | ----------------------------------- |
| Application policy | OPA            | Per-document, per-user, per-agent   |
| Resource policy    | S3/GitHub/etc. | Per-bucket, per-repo, per-workspace |

### The five-layer authorization model

```text
┌─────────────────────────────────────────────────────────────────────────┐
│  Layer 1: Identity (Keycloak)                                           │
│  "Who is this user/agent?"                                              │
├─────────────────────────────────────────────────────────────────────────┤
│  Layer 2: Token Exchange (AuthBridge)                                   │
│  "Is this agent allowed to talk to this service?"                       │
├─────────────────────────────────────────────────────────────────────────┤
│  Layer 3: Application Policy (OPA)                                      │
│  "Can this user+agent access this specific resource?"                   │
├─────────────────────────────────────────────────────────────────────────┤
│  Layer 4: Credential Broker (Vault or STS)                              │
│  "Generate credentials scoped to allowed resources"                     │
├─────────────────────────────────────────────────────────────────────────┤
│  Layer 5: Resource Access (S3/GitHub/Slack)                             │
│  "Access with scoped credentials"                                       │
└─────────────────────────────────────────────────────────────────────────┘
```

For resources that support OIDC/STS (AWS S3, MinIO, Azure, GCP), layers 3-4 can collapse.
For resources that don't (NooBaa, GitHub PATs), you need a credential broker at layer 4.

### Solution patterns

#### Pattern 1: OIDC federation with cloud providers

Cloud providers support exchanging JWT tokens for temporary credentials:

```text
JWT from Keycloak ──► Cloud Provider STS ──► Temporary cloud credentials
```

This is documented in [SPIFFE OIDC Federation with AWS](https://spiffe.io/docs/latest/keyless/oidc-federation-aws/):

> "A SPIRE identified workload can, using a JWT-SVID, authenticate to Amazon AWS APIs, assume an AWS IAM role, and retrieve data from an AWS S3 bucket. This avoids the need to create and deploy AWS IAM credentials with the workload itself."

#### Pattern 2: S3-compatible storage with STS

MinIO (and AWS S3) support `AssumeRoleWithWebIdentity`:

```text
Keycloak JWT ──► MinIO/AWS STS API ──► Temporary S3 credentials
```

The gateway can pass a **session policy** that restricts access to specific objects:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::documents/DOC-005"
  }]
}
```

#### Pattern 3: Vault as credential broker

For resources that don't support OIDC/STS natively:

```text
JWT-SVID ──► Vault (SPIFFE auth) ──► Dynamic secrets engine ──► Service-specific token
```

[Vault Enterprise 1.21](https://www.hashicorp.com/en/blog/vault-enterprise-1-21-spiffe-auth-fips-140-3-level-1-compliance-granular-secret-recovery) added native SPIFFE auth support:

> "With native SPIFFE auth support, Vault Enterprise simplifies authentication of non-human-identity workloads such as AI agents."

### Storage provider comparison

| Provider   | OIDC/STS Support   | Implementation approach            |
| ---------- | ------------------ | ---------------------------------- |
| AWS S3     | ✅ Full support     | AssumeRoleWithWebIdentity          |
| MinIO      | ✅ Full support     | AssumeRoleWithWebIdentity          |
| Azure Blob | ✅ Full support     | Workload Identity Federation       |
| GCP GCS    | ✅ Full support     | Workload Identity Federation       |
| NooBaa/MCG | ❌ Not for clients  | Gateway with static creds or Vault |
| GitHub     | ⚠️ GitHub Apps only | Installation tokens (short-lived)  |
| Slack      | ⚠️ OAuth refresh    | Store refresh token in Vault       |

### Implementation approach for this demo

#### Phase A: Gateway with static credentials (current)

Start with the existing pattern where document-service uses OBC-provided credentials:

```text
Agent → AuthBridge → document-service → OPA (ALLOW)
                           ↓
                     Uses static ACCESS_KEY/SECRET_KEY
                     (from OBC secret)
                           ↓
                         NooBaa
```

This demonstrates the core AuthBridge integration without additional complexity.

#### Phase B: AWS S3 with OIDC federation (production path)

For production deployments with AWS S3:

```text
Agent → AuthBridge → document-service → OPA (ALLOW)
                           ↓
                     Extract JWT claims
                           ↓
                     AWS STS AssumeRoleWithWebIdentity
                     (JWT → temporary credentials)
                           ↓
                     S3 GetObject with session policy
                     (scoped to specific object)
```

Implementation steps:

1. Configure AWS IAM OIDC identity provider with Keycloak's JWKS
2. Create IAM roles mapped to Keycloak groups (engineering-reader, finance-reader)
3. Modify document-service to call STS with the JWT
4. Use session policies to scope access to specific objects

#### Phase C: Vault for non-OIDC resources (advanced)

For resources like GitHub or legacy systems:

1. Deploy Vault with SPIFFE auth method
2. Configure dynamic secrets engines for each resource type
3. Document-service requests credentials from Vault after OPA approval
4. Credentials have short TTL and are scoped appropriately

### Key insight: Credential generation, not storage

The zero trust principle applies here too:

| Traditional approach              | Zero trust approach                        |
| --------------------------------- | ------------------------------------------ |
| Store long-lived credentials      | Generate short-lived credentials on demand |
| Rotate periodically               | Every request gets fresh credentials       |
| Broad access, filtered by gateway | Scoped access matching OPA decision        |

---

## Glossary of new terms

| Term                             | Definition                                                         |
| -------------------------------- | ------------------------------------------------------------------ |
| **AssumeRoleWithWebIdentity**    | AWS/MinIO STS API that exchanges JWT for temporary credentials     |
| **AuthBridge**                   | Kagenti component for transparent token exchange                   |
| **Audience (aud)**               | JWT claim specifying intended recipient of token                   |
| **Authorized Party (azp)**       | JWT claim identifying client that obtained the token               |
| **Credential Broker**            | Service that generates scoped credentials on demand (e.g., Vault)  |
| **Dynamic Secrets**              | Credentials generated on-demand with automatic expiration          |
| **ext-proc**                     | Envoy external processor that performs token exchange              |
| **JWKS**                         | JSON Web Key Set - public keys for validating JWTs                 |
| **OIDC Federation**              | Trusting an external identity provider for authentication          |
| **RFC 8693**                     | OAuth 2.0 Token Exchange specification                             |
| **Session Policy**               | Inline IAM policy that further restricts assumed role permissions  |
| **STS**                          | Security Token Service - generates temporary security credentials  |
| **Token Exchange**               | Swapping one token for another with different properties           |
| **Workload Identity Federation** | Cloud pattern for exchanging workload tokens for cloud credentials |

---

## References

### AuthBridge and Kagenti

- [Kagenti AuthBridge Demo](https://github.com/kagenti/kagenti-extensions/tree/main/AuthBridge)
- [RFC 8693: OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)

### Keycloak token exchange

- [Keycloak Token Exchange Documentation](https://www.keycloak.org/docs/latest/securing_apps/#_token-exchange)
- [JWKS Explanation](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets)

### SPIFFE OIDC federation

- [SPIFFE OIDC Federation with AWS](https://spiffe.io/docs/latest/keyless/oidc-federation-aws/)
- [Indeed Engineering - Workload Identity with SPIRE](https://engineering.indeedblog.com/blog/2024/07/workload-identity-with-spire-oidc-for-k8s-istio/)
- [SPIRE and Vault Integration](https://spiffe.io/docs/latest/keyless/vault/readme/)

### S3 STS and OIDC

- [AWS AssumeRoleWithWebIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html)
- [MinIO AssumeRoleWithWebIdentity](https://min.io/docs/minio/linux/developers/security-token-service/AssumeRoleWithWebIdentity.html)
- [MinIO OIDC Integration](https://blog.min.io/minio-openid-connect-integration/)

### HashiCorp Vault

- [Vault AWS Secrets Engine](https://developer.hashicorp.com/vault/docs/secrets/aws)
- [Vault Enterprise 1.21 SPIFFE Support](https://www.hashicorp.com/en/blog/vault-enterprise-1-21-spiffe-auth-fips-140-3-level-1-compliance-granular-secret-recovery)

### Go libraries for JWT

- [golang-jwt/jwt](https://github.com/golang-jwt/jwt) - JWT parsing and validation
- [MicahParks/keyfunc](https://github.com/MicahParks/keyfunc) - JWKS fetching with caching

### Learning methodology

- [Socratic Dialogue for Technical Learning](https://github.com/hardwaylabs/learning-prompts)
