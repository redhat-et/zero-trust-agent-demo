# Bug: ext-proc cannot see inbound direction header

## Summary

The `x-authbridge-direction: inbound` header configured via
`request_headers_to_add` at the Envoy `virtual_hosts` level is
invisible to the ext-proc filter. This causes the ext-proc to treat
**all** traffic (inbound and outbound) as outbound, leading to
unwanted token exchange on inbound requests.

## Affected file

`AuthBridge/k8s/configmaps-webhook.yaml` (the `authbridge-envoy-config`
ConfigMap containing `envoy.yaml`)

## Root cause

In Envoy's HTTP processing pipeline, `request_headers_to_add` at the
`virtual_hosts` (or `route`) level is applied by the **Router filter**,
which is the last filter in the HTTP filter chain. The `ext_proc`
filter runs **before** the Router, so it never sees headers added at
the route level.

Current (broken) configuration:

```yaml
- name: inbound_listener
  # ...
  filter_chains:
  - filters:
    - name: envoy.filters.network.http_connection_manager
      typed_config:
        # ...
        route_config:
          name: inbound_routes
          virtual_hosts:
          - name: local_app
            domains: ["*"]
            # BUG: This header is added by the Router filter,
            # AFTER ext_proc has already processed the request.
            request_headers_to_add:
            - header:
                key: "x-authbridge-direction"
                value: "inbound"
              append: false
            routes:
            - match:
                prefix: "/"
              route:
                cluster: original_destination
        http_filters:
        # ext_proc runs here -- BEFORE the Router applies
        # request_headers_to_add, so it never sees the header.
        - name: envoy.filters.http.ext_proc
          # ...
        - name: envoy.filters.http.router
          # ...
```

Envoy HTTP filter execution order:

```text
Request arrives
  -> HTTP Connection Manager
    -> Filter 1: ext_proc  (processes headers -- NO direction header yet)
    -> Filter 2: router    (applies request_headers_to_add, routes upstream)
```

## Impact

The ext-proc checks for `x-authbridge-direction` to decide whether
to validate (inbound) or exchange (outbound) the token:

```go
direction := getHeaderValue(headers.Headers, "x-authbridge-direction")
if direction == "inbound" {
    resp = p.handleInbound(reqCtx, headers)
} else {
    resp = p.handleOutbound(reqCtx, headers)
}
```

Since the header is never present, **every request goes through
`handleOutbound`**. On the outbound listener this is correct. On the
inbound listener, this means:

- If an inbound request carries an `Authorization: Bearer` header,
  the ext-proc performs token exchange instead of JWT validation
- The exchanged token replaces the original, causing downstream
  services to receive a token scoped to the wrong client
- In a multi-sidecar deployment (e.g., Envoy on both user-service
  and agent-service), this causes double token exchange and Keycloak
  rejects the second exchange with `"client is not within the token
  audience"`

The bug was masked in single-sidecar deployments because:

1. Health probes don't carry `Authorization` headers, so the outbound
   handler just logs "No Authorization header found" and passes through
2. Internal service-to-service calls that bypass Envoy (via iptables
   port exclusions) never hit the inbound listener

## Fix

Replace the `request_headers_to_add` at the `virtual_hosts` level
with a **Lua HTTP filter** positioned before `ext_proc`. Lua filters
execute in the HTTP filter chain, so the header is present when
ext-proc processes the request.

```yaml
- name: inbound_listener
  # ...
  filter_chains:
  - filters:
    - name: envoy.filters.network.http_connection_manager
      typed_config:
        # ...
        route_config:
          name: inbound_routes
          virtual_hosts:
          - name: local_app
            domains: ["*"]
            # REMOVED: request_headers_to_add (was invisible to ext_proc)
            routes:
            - match:
                prefix: "/"
              route:
                cluster: original_destination
        http_filters:
        # Lua filter injects the direction header BEFORE ext_proc
        - name: envoy.filters.http.lua
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua
            inline_code: |
              function envoy_on_request(request_handle)
                request_handle:headers():add("x-authbridge-direction", "inbound")
              end
        - name: envoy.filters.http.ext_proc
          # ...
        - name: envoy.filters.http.router
          # ...
```

Execution order with the fix:

```text
Request arrives
  -> HTTP Connection Manager
    -> Filter 1: lua        (adds x-authbridge-direction: inbound)
    -> Filter 2: ext_proc   (sees header, calls handleInbound)
    -> Filter 3: router     (routes upstream)
```

## Verification

Before the fix, ext-proc logs for inbound health probes:

```text
=== Outbound Request Headers ===
[Token Exchange] No Authorization header found
```

After the fix:

```text
=== Inbound Request Headers ===
x-authbridge-direction: inbound
[Inbound] Missing Authorization header
```

## Envoy version

Tested on Envoy 1.28.7. The Lua HTTP filter extension is included in
standard Envoy builds.
