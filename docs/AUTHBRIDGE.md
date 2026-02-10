# AuthBridge integration

## Overview

AuthBridge adds production-grade OAuth2 token exchange (RFC 8693) to the
zero-trust-agent-demo. When an AI agent acts on behalf of a user, AuthBridge
transparently exchanges the caller's token for one with the correct audience
before reaching the target service.

This replaces the current approach of passing delegation context in request
bodies with standard JWT-based authentication at the service boundary.

### What AuthBridge provides

- **Automatic client registration**: Agent-service registers with Keycloak
  using its SPIFFE identity (JWT SVID)
- **Transparent token exchange**: Envoy ext-proc sidecar exchanges tokens on
  outbound requests (`aud: agent-spiffe-id` -> `aud: document-service`)
- **JWT validation**: Document-service validates incoming JWTs (signature,
  issuer, audience)
- **No code copies**: All AuthBridge components run as container images from
  `ghcr.io/kagenti/kagenti-extensions/`

## Architecture

```text
User (browser)
  |  Login via Keycloak OIDC
  v
Dashboard (:8080)
  |  JWT with groups -> user_departments
  v
User-Service (:8082)
  |  Delegation request
  v
Agent-Service Pod (:8083)
  +---------------------------------------------+
  | agent-service        (Go app)               |
  | spiffe-helper        (fetches JWT SVID)     |
  | client-registration  (registers w/ Keycloak)|
  | envoy-proxy          (ext-proc sidecar)     |
  | proxy-init           (iptables init)        |
  +-------------------+-------------------------+
                      | Envoy intercepts outbound call (HTTP)
                      | ext-proc exchanges token:
                      |   aud: agent-spiffe-id -> aud: document-service
                      v
Document-Service (:8084, plain HTTP with listen_plain_http=true)
  |  Validates JWT (aud=document-service, JWKS signature)
  |  + existing OPA policy check (mTLS to OPA)
  v
OPA-Service (:8085)
```

### Token flow

1. User logs in via Keycloak, gets JWT with `groups` claim
1. Dashboard delegates to agent-service with user's JWT
1. Agent-service makes outbound request to document-service
1. Envoy proxy-init has set up iptables to intercept outbound traffic
1. Envoy ext-proc (go-processor) exchanges the token:
   - Calls Keycloak token exchange endpoint
   - Subject token: caller's token (`aud: agent-spiffe-id`)
   - New token: `aud: document-service`
1. Document-service validates JWT signature via JWKS
1. Document-service checks `aud` claim = `document-service`
1. Document-service extracts `groups` for OPA policy evaluation
1. OPA evaluates permission intersection as before

## Prerequisites

- Kind cluster with SPIRE installed (`./scripts/setup-kind.sh`)
- Base services deployed via Kustomize (see [Kustomize overlays](#kustomize-overlays))
- `kubectl` and `kustomize` CLI tools
- Internet access to pull images from `ghcr.io`

## Kustomize overlays

All deployments use Kustomize overlays in `deploy/k8s/overlays/`. Each overlay
extends a base or another overlay and adds environment-specific configuration.

### Kind (local development)

| Overlay | Command | Description |
| ------- | ------- | ----------- |
| `mock` | `kubectl apply -k deploy/k8s/overlays/mock` | Mock SPIFFE mode, no SPIRE needed, plain HTTP between services. Fastest way to test locally. |
| `local` | `kubectl apply -k deploy/k8s/overlays/local` | Real SPIFFE/SPIRE with CSI driver, Keycloak OIDC, local images loaded via `kind load`. |
| `local-ai-agents` | `kubectl apply -k deploy/k8s/overlays/local-ai-agents` | Extends `local` with summarizer and reviewer AI agent services. |
| `authbridge` | `kubectl apply -k deploy/k8s/overlays/authbridge` | Extends `local` with AuthBridge sidecars for JWT token exchange. |
| `authbridge-remote-kc` | `kubectl apply -k deploy/k8s/overlays/authbridge-remote-kc` | Extends `authbridge`, replaces in-cluster Keycloak with an external instance. |

### OpenShift

| Overlay | Command | Description |
| ------- | ------- | ----------- |
| `ghcr` | `kubectl apply -k deploy/k8s/overlays/ghcr` | Uses pre-built images from `ghcr.io`, real SPIFFE. Base for OpenShift overlays. |
| `openshift` | `oc apply -k deploy/k8s/overlays/openshift` | Extends `ghcr` with OpenShift Routes and SELinux security contexts. |
| `openshift-oidc` | `oc apply -k deploy/k8s/overlays/openshift-oidc` | Extends `openshift` with Keycloak Route and OIDC authentication. |
| `openshift-ai-agents` | `oc apply -k deploy/k8s/overlays/openshift-ai-agents` | Extends `openshift-oidc` with AI agent services and LiteLLM. |
| `openshift-storage` | `oc apply -k deploy/k8s/overlays/openshift-storage` | Extends `openshift` with object storage (OBC) for document persistence. |

### Overlay inheritance

```text
base
├── mock
├── local
│   ├── local-ai-agents
│   └── authbridge
│       └── authbridge-remote-kc
└── ghcr
    └── openshift
        ├── openshift-oidc
        │   └── openshift-ai-agents
        └── openshift-storage
```

## Deployment

### Quick start

```bash
# Deploy with AuthBridge overlay
make deploy-authbridge

# Or manually
./scripts/setup-authbridge.sh
```

### Step by step

```bash
# Apply the authbridge kustomize overlay
kubectl apply -k deploy/k8s/overlays/authbridge

# Wait for keycloak to be ready (it needs to restart with KC_HOSTNAME)
kubectl rollout status deployment/keycloak -n spiffe-demo --timeout=180s

# Wait for agent-service (needs all sidecar containers)
kubectl rollout status deployment/agent-service -n spiffe-demo --timeout=120s

# Verify all containers are running
kubectl get pods -n spiffe-demo -l app=agent-service \
  -o jsonpath='{.items[0].spec.containers[*].name}'
# Expected: agent-service client-registration spiffe-helper envoy-proxy
```

### Set up port forwarding

```bash
# Keycloak (use localtest.me which resolves to 127.0.0.1)
kubectl port-forward svc/keycloak 8080:8080 -n spiffe-demo &

# Dashboard
kubectl port-forward svc/web-dashboard 8081:8080 -n spiffe-demo &
```

### Using a remote Keycloak (OpenShift)

Instead of running Keycloak in-cluster, you can point AuthBridge at an existing
Keycloak instance. The `authbridge-remote-kc` overlay extends `authbridge` and
overrides all Keycloak URLs while scaling the in-cluster Keycloak to 0 replicas.

#### Configure settings

Copy the example settings file and fill in your Keycloak URL and admin password:

```bash
cd deploy/k8s/overlays/authbridge-remote-kc
cp settings.yaml.example settings.yaml
vi settings.yaml
```

The settings file contains four values:

- `keycloak-url` - Base URL of your Keycloak instance
- `admin-password` - Keycloak admin password for client-registration
- `issuer-url` - Realm issuer URL (used by proxy, document-service, dashboard)
- `token-url` - Keycloak token endpoint (for Envoy token exchange)

The `settings.yaml` file is gitignored and will not be committed.

#### Deploy

```bash
make deploy-authbridge-remote-kc

# Or manually
./scripts/setup-authbridge.sh remote-kc
```

#### Port forwarding (remote Keycloak)

With remote Keycloak, you only need to forward the dashboard. Keycloak is
already accessible at its external URL.

```bash
# Dashboard only (no Keycloak port-forward needed)
kubectl port-forward svc/web-dashboard 8080:8080 -n spiffe-demo &
```

#### Test

```bash
make test-authbridge-remote-kc

# Or manually
KEYCLOAK_URL=https://keycloak.example.com \
  ./scripts/test-authbridge.sh
```

#### What the overlay changes

| Component | Local (authbridge) | Remote (authbridge-remote-kc) |
| --------- | ------------------ | ----------------------------- |
| Keycloak deployment | Running in-cluster | Scaled to 0 replicas |
| Keycloak URL | `http://keycloak:8080` | `https://keycloak.example.com` |
| Token issuer | `http://keycloak.localtest.me:8080/realms/...` | `https://keycloak.example.com/realms/...` |
| iptables exclude | Port 8080 (HTTP) | Port 443 (HTTPS) |
| Dashboard port | 8081 (8080 used by Keycloak) | 8080 (no Keycloak conflict) |

#### Customizing the remote URL

To use a different Keycloak instance, edit `settings.yaml` in
`deploy/k8s/overlays/authbridge-remote-kc/`. All four values derive from the
hostname. Kustomize `replacements` propagate them to the ConfigMap, Secret, and
Deployment env vars automatically.

## Verification

### Automated tests

```bash
make test-authbridge
# Or
./scripts/test-authbridge.sh
```

The test script verifies:

1. Token acquisition with dynamically registered client credentials
1. Token audience contains agent's SPIFFE ID
1. Token exchange produces token with `aud: document-service`
1. Access to allowed document (DOC-001, engineering) succeeds
1. Access to denied document (DOC-004, hr) is rejected by OPA

### Manual verification

```bash
# Check all agent-service containers are running
kubectl get pods -n spiffe-demo -l app=agent-service

# Verify client registration completed
kubectl logs deployment/agent-service -n spiffe-demo \
  -c client-registration | grep "Client registration complete"

# Check envoy-proxy is running
kubectl logs deployment/agent-service -n spiffe-demo \
  -c envoy-proxy | grep "Starting"

# Check spiffe-helper is fetching SVIDs
kubectl logs deployment/agent-service -n spiffe-demo \
  -c spiffe-helper | grep "jwt_svid"
```

## How components are sourced

All AuthBridge sidecar containers use pre-built images from the kagenti
project. No source code is copied into this repository.

| Component | Image | Purpose |
| --------- | ----- | ------- |
| proxy-init | `ghcr.io/kagenti/kagenti-extensions/proxy-init:latest` | iptables setup for traffic interception |
| spiffe-helper | `ghcr.io/spiffe/spiffe-helper:nightly` | Fetches JWT SVID from SPIRE agent |
| client-registration | `ghcr.io/kagenti/kagenti-extensions/client-registration:latest` | Registers with Keycloak using SPIFFE ID |
| envoy-proxy | `ghcr.io/kagenti/kagenti-extensions/envoy-with-processor:latest` | Envoy + go-processor for token exchange |

## Configuration

### Keycloak realm changes

The `realm-spiffe-demo.json` includes:

- `agent-service-spiffe-aud` client scope: adds the agent-service SPIFFE ID
  (`spiffe://demo.example.com/service/agent-service`) to access tokens
- `document-service-aud` in default optional scopes: allows dynamically
  registered clients to request document-service audience during token exchange
- `KC_HOSTNAME=keycloak.localtest.me`: ensures consistent `iss` claim in all
  tokens (browser and in-cluster)

### Document-service configuration

The AuthBridge overlay configures document-service with two key changes:

**Plain HTTP listener** (`SPIFFE_DEMO_SERVICE_LISTEN_PLAIN_HTTP=true`): The
Envoy transparent proxy intercepts outbound traffic from agent-service and
forwards it to document-service as plain HTTP. Since Envoy uses iptables-based
interception (`ORIGINAL_DST` cluster), it cannot terminate or initiate mTLS on
behalf of the caller. Document-service must therefore listen on plain HTTP
instead of its normal mTLS mode.

This flag decouples the listener mode from the SPIFFE client mode:

- **Listener**: plain HTTP (accepts connections from Envoy)
- **SPIFFE identity**: still fetched from SPIRE (used for OPA mTLS client)
- **OPA client**: still uses mTLS (SPIFFE identity for OPA calls)
- **Identity extraction**: uses `X-SPIFFE-ID` header instead of TLS peer
  certificate

**JWT validation**: Validates incoming JWT tokens (exchanged by Envoy) to
extract caller identity and group memberships for OPA policy evaluation.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `SPIFFE_DEMO_SERVICE_LISTEN_PLAIN_HTTP` | `false` | Listen on plain HTTP instead of mTLS |
| `SPIFFE_DEMO_JWT_VALIDATION_ENABLED` | `false` | Enable JWT validation |
| `SPIFFE_DEMO_JWT_ISSUER_URL` | (empty) | Keycloak realm issuer URL |
| `SPIFFE_DEMO_JWT_EXPECTED_AUDIENCE` | `document-service` | Expected `aud` claim |

When JWT validation is enabled and a request includes an `Authorization: Bearer`
header, document-service will:

1. Validate the JWT signature against Keycloak's JWKS endpoint
1. Check expiration and issuer
1. Verify the `aud` claim contains `document-service`
1. Extract `groups` claim as user departments for OPA evaluation

When no `Authorization` header is present, the existing SPIFFE-only flow is
used. This preserves backward compatibility.

### AuthBridge sidecar configuration

The Envoy ext-proc (go-processor) is configured via:

| Variable | Value | Source |
| -------- | ----- | ------ |
| `TOKEN_URL` | Keycloak token endpoint | `authbridge-proxy-config` secret |
| `ISSUER` | `http://keycloak.localtest.me:8080/realms/spiffe-demo` | `authbridge-proxy-config` secret |
| `TARGET_AUDIENCE` | `document-service` | `authbridge-proxy-config` secret |
| `TARGET_SCOPES` | `openid document-service-aud` | `authbridge-proxy-config` secret |
| `CLIENT_ID_FILE` | `/shared/client-id.txt` | Written by client-registration |
| `CLIENT_SECRET_FILE` | `/shared/client-secret.txt` | Written by client-registration |

## Troubleshooting

### Issuer mismatch errors

**Symptom**: JWT validation fails with "invalid issuer" error.

**Cause**: Keycloak issues tokens with `iss` based on the hostname it was
accessed through. If browser access uses `localhost:8080` but the envoy-proxy
config expects `keycloak.localtest.me:8080`, the issuer won't match.

**Fix**: The `KC_HOSTNAME` environment variable (set in
`keycloak-hostname-patch.yaml`) forces a consistent issuer. Make sure
port-forwarding maps to `keycloak.localtest.me`:

```bash
kubectl port-forward svc/keycloak 8080:8080 -n spiffe-demo &
# Access via http://keycloak.localtest.me:8080 (resolves to 127.0.0.1)
```

### iptables port exclusions

**Symptom**: Client-registration cannot reach Keycloak, or agent-service health
checks fail.

**Cause**: The proxy-init container sets up iptables rules that redirect all
outbound TCP traffic through Envoy. If Keycloak's port (8080) is not excluded,
the client-registration container's requests to Keycloak get intercepted.

**Fix**: The `OUTBOUND_PORTS_EXCLUDE=8080` environment variable on the
proxy-init container excludes Keycloak traffic from interception. If you add
other services that should bypass Envoy, add their ports to this
comma-separated list.

### SPIFFE helper socket path

**Symptom**: spiffe-helper cannot connect to SPIRE agent.

**Cause**: The CSI driver mounts the SPIRE agent socket at
`/run/spire/agent-sockets/spire-agent.sock`, but the default spiffe-helper
config may expect a different path.

**Fix**: The `authbridge-spiffe-helper-config` ConfigMap sets
`agent_address = "/run/spire/agent-sockets/spire-agent.sock"` to match the CSI
driver mount path.

### HTTP 400 from document-service

**Symptom**: Requests from agent-service to document-service return HTTP 400
with "Client sent an HTTP request to an HTTPS server."

**Cause**: Document-service is listening with mTLS (HTTPS) but Envoy's
transparent proxy sends plain HTTP. The `ORIGINAL_DST` cluster in Envoy
connects to the original destination IP:port using the same protocol as the
intercepted connection (HTTP), but the server expects TLS.

**Fix**: Set `SPIFFE_DEMO_SERVICE_LISTEN_PLAIN_HTTP=true` on document-service.
This is already configured in the `authbridge` overlay's
`document-service-jwt-patch.yaml`. The flag makes document-service listen on
plain HTTP while still using mTLS for its own outbound OPA calls.

### Client registration fails

**Symptom**: `client-registration` container logs show authentication errors.

**Cause**: Keycloak admin credentials in the `authbridge-environments` ConfigMap
don't match the actual admin password.

**Fix**: Check that `KEYCLOAK_ADMIN_PASSWORD` in
`authbridge-configmaps.yaml` matches the `keycloak-admin` secret in
`deploy/k8s/base/keycloak.yaml` (default: `admin123`).

### Merging realm JSON with an existing Keycloak

When using a remote Keycloak that already has a `spiffe-demo` realm configured,
you need to merge the AuthBridge-specific changes rather than importing the full
realm JSON. The required changes to the realm are:

1. **Add `agent-service-spiffe-aud` client scope** - This audience mapper adds
   the agent-service SPIFFE ID
   (`spiffe://demo.example.com/service/agent-service`) to access tokens, which
   is required for the dynamically-registered client to receive tokens with its
   own identity as audience.

1. **Add `agent-service-spiffe-aud` to default client scopes** - So all tokens
   automatically include the agent's SPIFFE ID in their audience.

1. **Add `document-service-aud` to default optional client scopes** - So the
   dynamically-registered client can request `document-service` audience during
   token exchange.

To apply these changes to an existing realm:

```bash
# Export your current realm
# Keycloak Admin > Realm Settings > Action > Partial export

# Compare with the repo version
diff <(jq '.clientScopes' your-exported-realm.json) \
     <(jq '.clientScopes' deploy/k8s/base/realm-spiffe-demo.json)

# Look for the agent-service-spiffe-aud entry and add it to your realm
# Also check defaultDefaultClientScopes and defaultOptionalClientScopes
```

Alternatively, add the scope manually via the Keycloak admin UI:

1. Go to **Client Scopes** > **Create client scope**
1. Name: `agent-service-spiffe-aud`, Protocol: `openid-connect`
1. Add a mapper: type = **Audience**, name = `agent-service-spiffe-aud`,
   included custom audience = `spiffe://demo.example.com/service/agent-service`,
   add to access token = ON
1. Go to **Realm Settings** > **Client Scopes** > **Default Client Scopes**
1. Add `agent-service-spiffe-aud` to default scopes
1. Add `document-service-aud` to optional scopes (if not already present)

## Backward compatibility

The AuthBridge overlay extends the `local` overlay. Deploying with the
existing `local` overlay (without AuthBridge) continues to work unchanged:

```bash
kubectl apply -k deploy/k8s/overlays/local
```

The JWT validation in document-service is disabled by default
(`jwt.validation_enabled=false`). It only activates when the environment
variables are set by the AuthBridge overlay.
