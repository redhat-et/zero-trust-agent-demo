# AuthBridge outbound traffic handling proposal

**Status**: Draft for discussion
**Date**: 2026-03-18
**Context**: Problems discovered deploying auth-unaware Python agents
via Kagenti with AuthBridge sidecars on OpenShift.

## Summary

AuthBridge's current outbound interception model breaks HTTPS traffic,
creates a bootstrap deadlock with Keycloak, and offers no policy-driven
control over which outbound requests should be intercepted. This
proposal describes three architectural changes to fix these issues.

## Problems observed

### Bootstrap deadlock with Keycloak

The iptables init container captures all outbound traffic before any
sidecar starts. This creates a circular dependency:

```text
iptables init
  → captures ALL outbound traffic → routes to Envoy
  → client-registration needs Keycloak → intercepted by Envoy
  → go-processor needs credentials from client-registration → waiting
  → Envoy ext-proc can't process without go-processor → deadlock
```

The go-processor times out after 60 seconds and starts without
credentials. Token exchange never activates. The agent runs for its
entire lifetime without AuthBridge protection.

### HTTPS outbound traffic fails

The Envoy outbound listener routes all traffic through the HTTP
connection manager and ext-proc filter. When the agent makes an
HTTPS request (e.g., `httpx.get("https://example.com/doc.md")`),
the TLS handshake fails because the HTTP filter chain can't handle
raw TLS.

The go-processor code in `AuthProxy/go-processor/main.go` already
supports a TLS/HTTP split via Envoy's `tls_inspector` listener
filter — HTTPS gets `tcp_proxy` passthrough while HTTP gets ext-proc
processing. However, the Envoy configuration that Kagenti injects
does not include this split. All traffic goes through the HTTP path.

**Impact**: Any agent that fetches external HTTPS URLs (GitHub, S3,
any API) fails silently when deployed with AuthBridge. This defeats
the "bring your own agent" goal — agents work locally but break in
production.

### No policy-driven outbound control

AuthBridge currently offers all-or-nothing interception:

- Intercept everything → breaks HTTPS, blocks public access
- Passthrough everything → no security enforcement

There is no mechanism to say "pass through public URLs but intercept
requests to controlled resources." The `routes.yaml` static config
supports per-host token exchange, but unmatched hosts either all get
exchanged (default) or all get passed through. There is no way to
apply different policies (passthrough, exchange, block, redirect) to
different categories of outbound traffic.

## Proposed changes

### Change A: Exempt identity provider from iptables

**What**: The iptables init container should exempt the Keycloak/IdP
host from traffic capture. Client-registration and go-processor
can reach Keycloak directly to bootstrap credentials.

**Why**: The identity provider is the trust root for the entire
AuthBridge flow. Sidecars must reach it to establish their own
identity before they can enforce policy on other traffic. This is
the same pattern Istio uses — the control plane is exempt from mTLS
enforcement during bootstrap.

**How**: The init container already accepts configuration for port
exclusions. Add a `BYPASS_OUTBOUND_HOSTS` environment variable
(or reuse the existing mechanism if one exists) that accepts a
comma-separated list of hosts to exempt from iptables redirect.
Kagenti should populate this with the Keycloak URL from the
`authbridge-config` ConfigMap.

```text
iptables init
  → exempt: keycloak.example.com (from authbridge-config ISSUER)
  → capture: everything else → Envoy outbound listener
```

**Blast radius**: Minimal. Only the IdP host bypasses Envoy. All
other outbound traffic is still captured and processed.

### Change B: TLS-aware outbound listener

**What**: The Envoy outbound listener should use `tls_inspector` to
detect whether outbound traffic is TLS or plaintext, and route
accordingly:

- **TLS traffic**: Match against controlled routes. If matched,
  redirect to the credential gateway (or configured backend). If
  not matched, TCP passthrough preserving the original TLS
  connection.
- **Plaintext HTTP traffic**: Route through ext-proc for token
  exchange (existing behavior).

**Why**: The go-processor already implements this split in its own
embedded Envoy config (see `AuthProxy/k8s/auth-proxy-deployment.yaml`
where `tls_inspector` is used). The Kagenti-injected config simply
needs to match this pattern.

**Envoy config structure**:

```text
outbound_listener (port 15123)
  ├── listener_filter: tls_inspector
  ├── listener_filter: original_dst
  │
  ├── filter_chain_match: transport_protocol = "tls"
  │   ├── route match: *.s3.amazonaws.com → credential-gateway
  │   └── default → tcp_proxy to original_destination (passthrough)
  │
  └── filter_chain_match: transport_protocol = "raw_buffer" (HTTP)
      └── http_connection_manager + ext_proc (existing behavior)
```

**Key detail for S3**: TLS requests to `*.s3.amazonaws.com` should
not be passed through — they should be redirected to the credential
gateway service. This can be done via Envoy's `tcp_proxy` with the
credential gateway as the upstream cluster, or by terminating TLS at
Envoy and forwarding as HTTP to the credential gateway. The latter
requires Envoy to have a CA certificate for signing on-the-fly
(complex), so the simpler approach is to redirect the TCP stream to
the credential gateway which then makes its own authenticated S3
connection.

However, the TCP stream carries TLS intended for `s3.amazonaws.com`,
not the credential gateway. The cleanest solution is for the **agent
to make HTTP (not HTTPS) requests to S3**, and Envoy routes those
HTTP requests to the credential gateway. Since the agent converts
`s3://bucket/key` to `https://bucket.s3.amazonaws.com/key`, we
could instead have it convert to `http://` and rely on the network
boundary (pod-internal traffic to Envoy) being secure. The credential
gateway then makes the authenticated HTTPS call to S3.

Alternatively, the agent could make requests to a **well-known local
endpoint** (e.g., `http://localhost:15124/s3/bucket/key`) that Envoy
routes to the credential gateway. This avoids DNS and TLS issues
entirely.

### Change C: Policy-driven outbound routing

**What**: Replace the static passthrough/exchange binary with a
policy-driven decision for each outbound request. The default
outbound policy should be **passthrough** for unmatched hosts (safe
default), with explicit routes for controlled resources.

**Route categories**:

| Category | Behavior | Example |
| -------- | -------- | ------- |
| Passthrough | Forward without modification | Public URLs, LLM APIs |
| Exchange | Token exchange via ext-proc | Internal services |
| Redirect | Rewrite to credential gateway | S3, cloud storage |
| Block | Return error | Blocked destinations |

**Configuration**: Extend `routes.yaml` with a `mode` field:

```yaml
default_outbound_policy: passthrough

routes:
  - host: "*.s3.amazonaws.com"
    mode: redirect
    redirect_target: "credential-gateway.spiffe-demo.svc:8080"
    path_prefix: "/s3-proxy/"

  - host: "document-service.spiffe-demo.svc.cluster.local"
    mode: exchange
    target_audience: "document-service"
    token_scopes: "openid"

  - host: "*.internal.blocked.example.com"
    mode: block
```

**OPA integration** (future): Instead of static routes, the ext-proc
could query OPA for each outbound request to determine the routing
policy. This enables dynamic, context-aware decisions:

```json
{
  "user": "alice",
  "agent": "kagenti-summarizer",
  "outbound_host": "zt-demo-documents.s3.amazonaws.com",
  "outbound_path": "/finance/q4-report.md"
}
```

OPA returns: `{mode: "redirect", target: "credential-gateway:8080"}`.

This is more powerful but adds latency per request. The static routes
approach is sufficient for the near-term.

## Impact on the S3 demo flow

With these changes, the end-to-end flow becomes:

```text
Agent                    Envoy (outbound)         Credential GW     S3
  │                           │                        │             │
  │── GET http://bucket.s3    │                        │             │
  │   .amazonaws.com/key ───▶ │                        │             │
  │                           │ (route: redirect)      │             │
  │                           │── GET /s3-proxy/key ──▶│             │
  │                           │   + token exchange     │             │
  │                           │   (adds JWT)           │             │
  │                           │                        │── OPA ──▶   │
  │                           │                        │── STS ──▶   │
  │                           │                        │── GET ─────▶│
  │                           │                        │◀── content ─│
  │◀── document content ──────│◀── content ────────────│             │
```

The agent makes a plain HTTP request. Envoy matches the S3 host,
does token exchange (adds the delegation JWT), and redirects to the
credential gateway. The credential gateway validates the JWT, checks
OPA, gets scoped STS credentials, fetches from S3, and returns the
content. The agent receives the document without knowing any of this
happened.

Meanwhile, requests to `https://api.openai.com` or any other public
HTTPS URL pass through Envoy untouched via TLS passthrough.

## Implementation approach

| Change | Where | Complexity | Priority |
| ------ | ----- | ---------- | -------- |
| A: IdP bypass | Kagenti operator (init container config) | Low | Immediate |
| B: TLS-aware listener | Kagenti operator (Envoy config template) | Medium | High |
| C: Policy-driven routing | AuthBridge go-processor + routes.yaml | Medium | High |

Changes A and B are Kagenti operator changes (config templates).
Change C requires go-processor code changes to support the `redirect`
mode and path rewriting. All three are backward-compatible — existing
deployments continue to work with the current behavior as default.

## Questions for discussion

- **Agent HTTP vs HTTPS to S3**: Should the agent use `http://` for
  S3 URLs (simpler Envoy routing) or should Envoy handle TLS
  termination/re-origination for `https://` S3 URLs?
- **Credential gateway as proxy vs credential broker**: The current
  design has the credential gateway fetch the S3 object and return
  content. An alternative is to return pre-signed S3 URLs or scoped
  credentials to the agent, letting it fetch directly. The proxy
  approach is simpler but adds latency for large objects.
- **OPA for outbound routing**: Is static `routes.yaml` sufficient,
  or should we invest in OPA-driven outbound policy from the start?
- **Scope of changes**: Should these changes be contributed upstream
  to Kagenti/AuthBridge, or kept as project-specific patches?
