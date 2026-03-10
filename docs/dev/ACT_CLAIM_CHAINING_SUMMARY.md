# Act claim chaining: implementation summary

## The problem

When Alice asks an AI agent to summarize a financial report, the request
travels through multiple services:

```text
Alice -> agent-service -> summarizer-service -> document-service
```

Each hop exchanges OAuth2 tokens (RFC 8693) so the downstream service
sees a properly scoped JWT. But the final JWT at document-service only
says *who* the token is for (`sub: alice`) and *who last exchanged it*
(`azp: summarizer`). There is no record that agent-service was also
involved.

The delegation context traveled via unsigned HTTP headers
(`X-Delegation-User`, `X-Delegation-Agent`). A compromised
intermediate service could forge these headers and impersonate a
different user or agent.

## The solution

RFC 8693 Section 4.1 defines an `act` (actor) claim that records who
is acting on behalf of whom. When token exchanges are chained, `act`
claims nest to form a **signed delegation chain** inside the JWT.

After this change, the JWT arriving at document-service looks like:

```json
{
  "sub": "d9ec0a88-...",
  "name": "Alice Smith",
  "aud": "document-service",
  "act": {
    "sub": "bf1ca556-...",
    "client_id": "spiffe://...sa/default",
    "act": {
      "sub": "d7438dbd-...",
      "client_id": "spiffe://...sa/agent-service"
    }
  }
}
```

Reading bottom-up: agent-service acted first (on behalf of Alice),
then summarizer-service acted (on behalf of the agent acting on behalf
of Alice). The entire chain is signed by Keycloak -- no intermediate
service can forge it.

## What changed (three repos)

### AuthProxy go-processor (kagenti-extensions)

**Branch**: `feat/actor-token-exchange`

The Envoy ext-proc (go-processor) already exchanged tokens on outbound
requests. We added actor token support:

| Change | What it does |
| ------ | ------------ |
| Actor token cache | Obtains and caches a client-credentials token for the service's own identity |
| `actor_token` parameter | Sends the cached token as `actor_token` + `actor_token_type` during RFC 8693 exchange |
| `ACTOR_TOKEN_ENABLED` flag | Feature flag (default: `true`) to disable without redeploying |
| Per-target routing | `routes.yaml` ConfigMap lets agent-service exchange tokens with different audiences per destination |
| Client registration 409 fix | Handles "client already exists" when SPIFFE ID clients survive Keycloak restarts |

### Keycloak SPI (keycloak-act-claim-spi)

**Branch**: `main`

The SPI intercepts token exchange responses and injects `act` claims:

| Change | What it does |
| ------ | ------------ |
| Read act chain from subject token | Previously read from actor token (wrong). Now correctly reads existing `act` chain from the token being exchanged, enabling proper nesting |
| Add `client_id` to act claim | Includes the actor's `azp` (SPIFFE ID) alongside `sub` (UUID). Enables auditing without Keycloak admin API access |
| Depth cap | Limits `act` nesting to 10 levels to prevent abuse |

### Demo platform (zero-trust-agent-demo)

**Branch**: `feature/act-claim-chaining`

| Change | What it does |
| ------ | ------------ |
| Audience scopes in realm JSON | Added `summarizer-service-aud` and `reviewer-service-aud` scopes with SPIFFE ID audiences |
| Demo users in realm JSON | Added alice, bob, carol, david with passwords and group memberships (survive Keycloak restarts) |
| OpenShift audience mappers | Added mappers for real cluster SPIFFE IDs alongside demo SPIFFE IDs |
| Post-import fixup script | `scripts/keycloak-post-import.sh` -- discovers real SPIFFE IDs from running pods and adds audience mappers |
| Routes ConfigMap | Per-target routing for agent-service (summarizer, reviewer audiences) |
| Test script updates | 19 tests covering act claims, multi-hop chains, A2A invokes, and log evidence |
| ADR-0010 | Architecture Decision Record documenting the design and alternatives |
| AUTHBRIDGE.md updates | Act claim section with token flow, example JWT, and configuration |

## How it works (step by step)

### Single hop: Alice -> agent-service -> document-service

```text
1. Alice logs in via Keycloak -> JWT {sub: "alice"}

2. Agent-service receives Alice's token on inbound request

3. Agent-service calls document-service
   -> Envoy ext-proc intercepts the outbound request
   -> ext-proc obtains its own token via client_credentials grant
   -> ext-proc calls Keycloak token exchange:
        subject_token = Alice's JWT
        actor_token   = agent-service's own JWT
        audience      = document-service
   -> Keycloak SPI builds: {sub: "alice", act: {sub: "agent-sa",
        client_id: "spiffe://...agent-service"}}
   -> Keycloak signs the new JWT

4. Document-service receives JWT with act claim proving the chain
```

### Multi-hop: Alice -> agent -> summarizer -> document-service

```text
1-3. Same as above, but audience = summarizer-service
     Result: JWT {sub: "alice", act: {sub: "agent-sa", ...}}

4. Summarizer receives the JWT with act claim

5. Summarizer calls document-service
   -> Envoy ext-proc intercepts
   -> ext-proc obtains summarizer's own token
   -> ext-proc calls Keycloak token exchange:
        subject_token = JWT from step 3 (already has act claim)
        actor_token   = summarizer's own JWT
        audience      = document-service
   -> Keycloak SPI reads existing act from subject token
   -> SPI builds: {sub: "alice", act: {sub: "summarizer-sa",
        client_id: "spiffe://...default",
        act: {sub: "agent-sa", client_id: "spiffe://...agent-service"}}}

6. Document-service receives JWT with full nested chain
```

## Auditing the delegation chain

The `act` claim uses Keycloak UUIDs for `sub` (opaque to humans) but
now includes `client_id` which maps to the service's SPIFFE ID. A
cluster admin can read the chain directly:

```json
{
  "act": {
    "sub": "bf1ca556-...",
    "client_id": "spiffe://apps.example.com/ns/spiffe-demo/sa/default",
    "act": {
      "sub": "d7438dbd-...",
      "client_id": "spiffe://apps.example.com/ns/spiffe-demo/sa/agent-service"
    }
  }
}
```

Reading: the request was handled by a workload in namespace
`spiffe-demo` with service account `default` (summarizer), which
received it from `agent-service`. Both SPIFFE IDs are
cryptographically attested by SPIRE.

For deeper investigation, the admin can look up UUIDs via:

```bash
# Get the username for a sub UUID
curl -s "$KEYCLOAK_URL/admin/realms/spiffe-demo/users/$UUID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.username'
```

## Bugs found and fixed along the way

| Bug | Impact | Fix |
| --- | ------ | --- |
| SPI read act chain from actor token instead of subject token | Act claims never nested (each hop overwrote the previous) | Read from `subject_token` form parameter instead |
| Client registration crashes on 409 | After Keycloak restart, service pods can't get client secrets | Handle 409 by looking up existing client via `get_clients()` |
| Go-processor starts without client secret | Token exchange skipped on outbound calls -> 401 at document-service | Fixed by the 409 fix above (secret now always written) |
| Alice's token missing agent-service audience | Token exchange failed ("client not in token audience") | Request `scope=openid agent-service-spiffe-aud` in password grant |
| Routes ConfigMap not deployed on OpenShift | Agent-service exchanged all tokens for `aud=document-service` instead of per-target | Applied ConfigMap and patched deployment |

## Verification

All 19 tests pass on OpenShift:

```text
Test 1:  Obtain token with client credentials                    PASS
Test 2:  Verify token authorized party                           PASS
Test 3:  Token exchange for document-service                     PASS
Test 4:  Access allowed document (DOC-001, engineering)          PASS
Test 5:  Access denied document (DOC-004, hr)                    PASS
Act:     Obtain alice's user token                               PASS
Act:     Single-hop act claim                                    PASS
Act:     Multi-hop act claim chain                               PASS
Test 6:  Verify summarizer-service AuthBridge sidecar setup      PASS
Test 7:  Token exchange proof (claim inspection)                 PASS
Test 8:  GET /documents with delegation headers (allowed)        PASS
Test 9:  GET /documents with delegation headers (denied)         PASS
Test 10: Full A2A invoke end-to-end (allowed)                    PASS
Test 11: Full A2A invoke end-to-end (denied)                     PASS
Test 12: Token exchange and delegation proof (log evidence)      PASS
Test 13: E2E act claim in JWT (via A2A invoke)                   PASS
```

Run with:

```bash
make test-openshift-authbridge
```

## What's next

| Item | Status | Notes |
| ---- | ------ | ----- |
| Dedicated service accounts for summarizer/reviewer | Not started | Both currently use `default` SA -> same SPIFFE ID in act claims |
| Document-service act claim logging | Not started | Log the received act chain for audit trail |
| OPA policy using act claims | Not started | Policy could enforce allowed delegation paths |
| Upstream client-registration fix | PR needed | The 409 fix should go upstream to kagenti |
| Upstream AuthProxy actor token | PR needed | The actor token feature should go upstream to kagenti |

## References

- [RFC 8693 - OAuth 2.0 Token Exchange][rfc8693]
- [RFC 8693 Section 4.1 - act claim][rfc8693-act]
- [ADR-0010: act claim chaining](../adr/0010-act-claim-chaining.md)
- [AuthBridge integration](../AUTHBRIDGE.md)
- [keycloak-act-claim-spi](https://github.com/redhat-et/keycloak-act-claim-spi)

[rfc8693]: https://datatracker.ietf.org/doc/html/rfc8693
[rfc8693-act]: https://datatracker.ietf.org/doc/html/rfc8693#section-4.1
