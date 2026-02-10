# Keycloak token exchange setup

This document describes how to configure Keycloak for RFC 8693 OAuth 2.0 Token Exchange. This enables services like `agent-service` to exchange their tokens for tokens scoped to other services like `document-service`.

## Overview

Token exchange allows a client to exchange one token for another with a different audience. This is essential for zero-trust architectures where each service requires tokens specifically scoped to it.

```text
agent-service token (aud: agent-service)
    ↓ token exchange
document-service token (aud: document-service)
```

## Prerequisites

- Keycloak 24+ (tested with 26.3.3)
- `token-exchange` feature enabled

## Configuration steps

### Step 1: Enable token exchange feature

Add the `token-exchange` feature flag to Keycloak startup:

```yaml
args:
- start-dev
- --import-realm
- --features=token-exchange
```

Or via environment variable:

```yaml
env:
- name: KC_FEATURES
  value: "token-exchange"
```

**Note**: Do NOT enable `admin-fine-grained-authz` - it activates V2 admin permissions which don't support token exchange in Keycloak 26.x.

### Step 2: Create the caller client (agent-service)

Create a client that will perform token exchanges:

```json
{
  "clientId": "agent-service",
  "name": "Agent Service",
  "enabled": true,
  "clientAuthenticatorType": "client-secret",
  "secret": "agent-service-secret",
  "publicClient": false,
  "serviceAccountsEnabled": true,
  "standardFlowEnabled": false,
  "directAccessGrantsEnabled": true,
  "protocol": "openid-connect",
  "attributes": {
    "standard.token.exchange.enabled": "true"
  },
  "defaultClientScopes": ["profile", "email", "roles", "web-origins", "acr", "basic"]
}
```

**Key settings:**

- `serviceAccountsEnabled: true` - Required for client credentials grant
- `standard.token.exchange.enabled: true` - Enables token exchange capability

### Step 3: Create the target client (document-service)

Create the client that will be the audience of exchanged tokens:

```json
{
  "clientId": "document-service",
  "name": "Document Service",
  "enabled": true,
  "clientAuthenticatorType": "client-secret",
  "secret": "document-service-secret",
  "publicClient": false,
  "serviceAccountsEnabled": true,
  "standardFlowEnabled": false,
  "protocol": "openid-connect",
  "attributes": {
    "standard.token.exchange.enabled": "true"
  },
  "defaultClientScopes": ["profile", "email", "roles", "web-origins", "acr", "basic"]
}
```

### Step 4: Create an audience scope

Create a client scope that adds `document-service` to the token's audience claim:

1. Go to **Client scopes** → **Create client scope**
2. Name: `document-service-aud`
3. Type: `Optional` (or `Default` if always needed)
4. Protocol: `OpenID Connect`
5. Save

Then add an audience mapper:

1. Go to the scope's **Mappers** tab → **Add mapper** → **By configuration** → **Audience**
2. Name: `document-service-aud`
3. Included Custom Audience: `document-service`
4. Add to access token: ON
5. Save

In realm JSON format:

```json
{
  "name": "document-service-aud",
  "protocol": "openid-connect",
  "attributes": {
    "include.in.token.scope": "true",
    "display.on.consent.screen": "false"
  },
  "protocolMappers": [
    {
      "name": "document-service-aud",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-audience-mapper",
      "consentRequired": false,
      "config": {
        "included.custom.audience": "document-service",
        "access.token.claim": "true",
        "id.token.claim": "false",
        "userinfo.token.claim": "false"
      }
    }
  ]
}
```

### Step 5: Assign the scope to the caller client

1. Go to **Clients** → **agent-service** → **Client scopes**
2. Click **Add client scope**
3. Select `document-service-aud`
4. Choose **Optional** (requires explicit `scope` parameter) or **Default** (always included)

## Default vs Optional scopes

When assigning audience scopes to a client, you choose between Default and Optional:

| Type | Behavior | Use case |
|------|----------|----------|
| Default | Automatically included in every token | Agent always calls the same target service |
| Optional | Only included when explicitly requested via `scope` parameter | Agent calls multiple target services |

### Single target service

If your agent always exchanges tokens for the same service, use **Default**:

```text
reviewer-agent → document-service (always)
```

Configuration is simpler - no need to track or request scope names.

### Multiple target services

If your agent exchanges tokens for different services based on context, use **Optional**:

```text
reviewer-agent → finance-document-service (for finance reviews)
              → engineering-document-service (for engineering reviews)
              → hr-document-service (for HR reviews)
```

This follows the principle of least privilege - tokens only contain the audience actually needed for each request. The caller explicitly declares intent by requesting the appropriate scope.

**Example configuration for multi-target agent:**

```text
Client scopes (all Optional):
├── finance-document-service-aud
├── engineering-document-service-aud
└── hr-document-service-aud

Assigned to: reviewer-agent (as Optional)
```

**Token exchange requests:**

```bash
# Finance review task
curl ... -d "audience=finance-document-service" \
         -d "scope=finance-document-service-aud"

# Engineering review task
curl ... -d "audience=engineering-document-service" \
         -d "scope=engineering-document-service-aud"
```

In a real service (like AuthBridge), scope mappings are typically configured:

```yaml
targets:
  finance-document-service:
    scope: finance-document-service-aud
  engineering-document-service:
    scope: engineering-document-service-aud
```

The proxy determines the target from the request destination and uses the corresponding scope.

## Verification

### Get an initial token

```bash
export KEYCLOAK_URL="https://your-keycloak-url"

AGENT_TOKEN=$(curl -s -X POST "$KEYCLOAK_URL/realms/spiffe-demo/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=agent-service" \
  -d "client_secret=agent-service-secret" | jq -r '.access_token')

echo $AGENT_TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq
# Should show: "aud": "account" or similar, "azp": "agent-service"
```

### Exchange the token

With Optional scope (explicit):

```bash
curl -s -X POST "$KEYCLOAK_URL/realms/spiffe-demo/protocol/openid-connect/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "client_id=agent-service" \
  -d "client_secret=agent-service-secret" \
  -d "subject_token=$AGENT_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "audience=document-service" \
  -d "scope=document-service-aud" | jq
```

With Default scope (automatic):

```bash
curl -s -X POST "$KEYCLOAK_URL/realms/spiffe-demo/protocol/openid-connect/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "client_id=agent-service" \
  -d "client_secret=agent-service-secret" \
  -d "subject_token=$AGENT_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "audience=document-service" | jq
```

### Verify the exchanged token

```bash
# Extract and decode the exchanged token
echo $EXCHANGED_TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq
```

Expected claims:

```json
{
  "aud": "document-service",
  "azp": "agent-service",
  "sub": "...",
  "preferred_username": "service-account-agent-service"
}
```

## Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| `unsupported_grant_type` | Feature not enabled | Add `--features=token-exchange` to startup |
| `invalid_client` | Wrong credentials | Check client_id and client_secret |
| `Requested audience not available` | Missing audience scope | Create and assign the audience scope |
| `Not supported in V2` | V2 admin permissions enabled | Disable admin permissions in Realm Settings |
| `access_denied` | Client not allowed | Enable `standard.token.exchange.enabled` on client |

## Configuration summary

| Component | Required Setting |
|-----------|------------------|
| Keycloak startup | `--features=token-exchange` |
| Caller client | `standard.token.exchange.enabled: true` |
| Target client | `standard.token.exchange.enabled: true` |
| Audience scope | `oidc-audience-mapper` with target client |
| Scope assignment | Assign audience scope to caller client |

## Realm export

After configuring via Admin Console, export the realm for reproducible deployments:

1. **Realm Settings** → **Action** → **Partial export**
2. Enable "Export clients" and "Export groups and roles"
3. Save to `deploy/k8s/base/realm-spiffe-demo.json`

**Note**: Client secrets are masked in exports. Set them via environment variables or regenerate after import.

## References

- [RFC 8693: OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [Keycloak Token Exchange Documentation](https://www.keycloak.org/docs/latest/securing_apps/#_token-exchange)
- [Kagenti AuthBridge](https://github.com/kagenti/kagenti-extensions/tree/main/AuthBridge)
