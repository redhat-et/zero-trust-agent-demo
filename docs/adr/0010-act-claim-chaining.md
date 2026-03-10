# ADR-0010: RFC 8693 act claim chaining for delegation tracking

## Status

Proposed

## Date

2026-03-09

## Context

Multi-hop delegation (user -> agent-service -> summarizer -> document-service)
currently lacks cryptographic proof of the delegation chain in JWTs. The
`X-Delegation-*` headers carry delegation context (user SPIFFE ID, agent
SPIFFE ID) but are unsigned HTTP headers that could be forged by a
compromised intermediate service.

RFC 8693 (OAuth 2.0 Token Exchange) defines an `act` (actor) claim that
records who is acting on behalf of whom. When token exchanges are chained,
`act` claims nest to form a cryptographic delegation chain:

```json
{
  "sub": "alice",
  "act": {
    "sub": "summarizer-sa",
    "act": {
      "sub": "agent-sa"
    }
  }
}
```

This JWT is signed by Keycloak, so no intermediate service can forge the
delegation chain.

### Current state

- **Keycloak SPI** (`keycloak-act-claim-spi`): already built and deployed.
  It injects nested `act` claims during token exchange when an
  `actor_token` parameter is provided.
- **AuthProxy** (Envoy ext-proc): performs RFC 8693 token exchange on
  outbound requests but never sends `actor_token`, so no `act` claims
  appear in exchanged tokens.
- **Delegation headers**: `X-Delegation-User` and `X-Delegation-Agent`
  carry context but are unsigned.

## Decision

We will modify AuthProxy to send its own identity as `actor_token` during
token exchange, producing JWTs with nested `act` claims that
cryptographically prove the delegation chain.

### Implementation approach: AuthProxy + Keycloak SPI

AuthProxy obtains its own access token via client credentials grant and
passes it as `actor_token` alongside the `subject_token` during token
exchange. The Keycloak SPI reads the actor token's `sub` claim and
injects it as the `act` claim in the exchanged token. On multi-hop
exchanges, the SPI preserves existing `act` claims by nesting them.

### Supporting changes

1. **Audience scopes**: Add `summarizer-service-aud` and
   `reviewer-service-aud` client scopes to Keycloak realm JSON so
   agent-service can request tokens scoped to AI agent audiences
   (using SPIFFE IDs as audience values).

1. **Per-target routing**: Add a `routes.yaml` ConfigMap for
   agent-service so it can exchange tokens with the correct audience
   when calling summarizer-service or reviewer-service (instead of
   always using `document-service`).

1. **Feature flag**: `ACTOR_TOKEN_ENABLED` environment variable
   (default: `true`) allows disabling act claim injection without
   redeploying.

### SPIFFE IDs as audience values

Auto-registration creates Keycloak clients with SPIFFE IDs as
`client_id`. Audience scopes use `included.custom.audience` with SPIFFE
ID strings (e.g.,
`spiffe://demo.example.com/service/summarizer-service`) to match.

## Consequences

### Positive

- **Cryptographic delegation proof**: The `act` claim chain is signed
  by Keycloak and cannot be forged by intermediate services
- **RFC compliance**: Follows RFC 8693 Section 4.1 (actor claim)
- **Backward compatible**: The `ACTOR_TOKEN_ENABLED` flag defaults to
  true but can be disabled; existing flows without actor tokens
  continue to work
- **No new dependencies**: Uses existing Keycloak SPI and AuthProxy
  infrastructure

### Negative

- **Extra token request**: Each AuthProxy instance needs a client
  credentials grant to obtain its own actor token (mitigated by
  caching with TTL)
- **Keycloak SPI dependency**: The `act` claim injection requires the
  custom SPI to be deployed in Keycloak

### Neutral

- Delegation headers (`X-Delegation-*`) remain for backward
  compatibility and for services that don't validate JWTs
- The actor token cache shares the same client credentials as the
  fallback token, so no additional secrets are needed

## Alternatives considered

### Option 1: Keycloak SPI only (no AuthProxy changes)

Modify the SPI to always inject an `act` claim based on the
`client_id` performing the exchange, without requiring an
`actor_token` parameter.

- **Pros**: No AuthProxy changes needed
- **Cons**: Violates RFC 8693 (actor should be explicitly declared);
  loses the ability to distinguish the acting party from the
  exchanging party; harder to extend for future delegation patterns

### Option 2: Custom claims via request headers

Pass delegation context as custom claims in the token exchange request
and have the SPI embed them in the JWT.

- **Pros**: More flexible claim structure
- **Cons**: Non-standard; requires SPI changes for each new claim;
  headers are still unsigned on the wire

### Option 3: Signed delegation tokens (custom format)

Create a separate signed token for delegation context, independent of
OAuth2.

- **Pros**: Full control over format
- **Cons**: Reinvents the wheel; not interoperable with standard
  OAuth2 tooling; extra key management

## References

- [RFC 8693 - OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [RFC 8693 Section 4.1 - act claim](https://datatracker.ietf.org/doc/html/rfc8693#section-4.1)
- [keycloak-act-claim-spi](https://github.com/pavelanni/keycloak-act-claim-spi)
- [ADR-0009: OpenTelemetry instrumentation](0009-otel-token-viz.md)
