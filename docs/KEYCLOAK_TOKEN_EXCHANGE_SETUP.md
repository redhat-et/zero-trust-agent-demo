# Keycloak token exchange setup plan

This document outlines how to configure Keycloak for RFC 8693 token exchange, including persistent storage and proper feature flags.

## Current issues

1. **Missing feature flags**: Token exchange requires `token-exchange` and `admin-fine-grained-authz` features
2. **No persistence**: Keycloak loses data on restart (uses H2 in-memory by default in dev mode)
3. **Missing clients**: `agent-service` and `document-service` need to be in the realm config

## Solution overview

We'll update the base Keycloak configuration to:

1. Add required feature flags
2. Add `agent-service` and `document-service` clients to the realm JSON
3. Optionally add PostgreSQL for persistence (or use realm export/import)

---

## Step 1: Update Keycloak deployment with feature flags

Edit `deploy/k8s/base/keycloak.yaml`, change the args section:

```yaml
args:
- start-dev
- --import-realm
- --features=token-exchange,admin-fine-grained-authz
```

Or use environment variable (alternative):

```yaml
env:
- name: KC_FEATURES
  value: "token-exchange,admin-fine-grained-authz"
```

---

## Step 2: Add clients to realm configuration

Update the `clients` array in `deploy/k8s/base/keycloak.yaml` (the ConfigMap section) to include:

```json
{
  "clientId": "agent-service",
  "name": "Agent Service",
  "enabled": true,
  "clientAuthenticatorType": "client-secret",
  "secret": "agent-service-secret",
  "serviceAccountsEnabled": true,
  "standardFlowEnabled": false,
  "directAccessGrantsEnabled": true,
  "publicClient": false,
  "protocol": "openid-connect",
  "defaultClientScopes": ["openid", "profile", "email", "groups"]
},
{
  "clientId": "document-service",
  "name": "Document Service",
  "enabled": true,
  "clientAuthenticatorType": "client-secret",
  "secret": "document-service-secret",
  "serviceAccountsEnabled": true,
  "authorizationServicesEnabled": true,
  "standardFlowEnabled": false,
  "publicClient": false,
  "protocol": "openid-connect",
  "defaultClientScopes": ["openid", "profile", "email", "groups"]
}
```

**Important**: The `authorizationServicesEnabled: true` on `document-service` is required for fine-grained permissions.

---

## Step 3: Configure token exchange permissions (via realm JSON)

Add authorization settings to `document-service` in the realm JSON:

```json
{
  "clientId": "document-service",
  ...
  "authorizationServicesEnabled": true,
  "authorizationSettings": {
    "allowRemoteResourceManagement": true,
    "policyEnforcementMode": "ENFORCING",
    "resources": [],
    "policies": [
      {
        "name": "agent-service-policy",
        "type": "client",
        "logic": "POSITIVE",
        "decisionStrategy": "UNANIMOUS",
        "config": {
          "clients": "[\"agent-service\"]"
        }
      }
    ],
    "scopes": [
      {
        "name": "token-exchange"
      }
    ]
  }
}
```

**Note**: Full token-exchange permission configuration via realm JSON is complex. It may be easier to:

1. Deploy with features enabled
2. Configure permissions via Admin Console
3. Export the realm for future deployments

---

## Step 4: Add persistent storage (optional but recommended)

### Option A: Use PostgreSQL (production-like)

Create a new overlay `deploy/k8s/overlays/keycloak-postgres/`:

```yaml
# kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - ../../base
  - postgres.yaml

patches:
  - path: keycloak-postgres-patch.yaml
```

```yaml
# postgres.yaml
apiVersion: v1
kind: Secret
metadata:
  name: keycloak-db
  namespace: spiffe-demo
stringData:
  username: keycloak
  password: keycloak123
  database: keycloak
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak-postgres
  namespace: spiffe-demo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: keycloak-postgres
  template:
    metadata:
      labels:
        app: keycloak-postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15
        env:
        - name: POSTGRES_USER
          valueFrom:
            secretKeyRef:
              name: keycloak-db
              key: username
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: keycloak-db
              key: password
        - name: POSTGRES_DB
          valueFrom:
            secretKeyRef:
              name: keycloak-db
              key: database
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-data
          mountPath: /var/lib/postgresql/data
      volumes:
      - name: postgres-data
        emptyDir: {}  # Use PVC for real persistence
---
apiVersion: v1
kind: Service
metadata:
  name: keycloak-postgres
  namespace: spiffe-demo
spec:
  selector:
    app: keycloak-postgres
  ports:
  - port: 5432
```

```yaml
# keycloak-postgres-patch.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak
spec:
  template:
    spec:
      containers:
      - name: keycloak
        args:
        - start-dev
        - --import-realm
        - --features=token-exchange,admin-fine-grained-authz
        - --db=postgres
        - --db-url=jdbc:postgresql://keycloak-postgres:5432/keycloak
        - --db-username=$(KC_DB_USERNAME)
        - --db-password=$(KC_DB_PASSWORD)
        env:
        - name: KC_DB_USERNAME
          valueFrom:
            secretKeyRef:
              name: keycloak-db
              key: username
        - name: KC_DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: keycloak-db
              key: password
```

### Option B: Use realm export/import (simpler)

Keep H2 but always import a complete realm on startup:

1. Configure everything via Admin Console
2. Export the realm: Admin Console → Realm Settings → Action → Partial Export
3. Save to `deploy/keycloak/realm-spiffe-demo.json`
4. Keycloak will import on every restart with `--import-realm`

**Limitation**: Exported realm doesn't include client secrets, so you need to set them via environment variables or regenerate.

---

## Step 5: Quick fix for OpenShift (immediate)

For your current OpenShift deployment, do this now:

```bash
# Edit the deployment
oc edit deployment keycloak -n spiffe-demo

# Change args to:
args:
- start-dev
- --import-realm
- --features=token-exchange,admin-fine-grained-authz
```

Then update the ConfigMap with the new clients before the pod restarts:

```bash
# Get current configmap
oc get configmap keycloak-realm -n spiffe-demo -o yaml > /tmp/realm-cm.yaml

# Edit to add agent-service and document-service clients
# Then apply
oc apply -f /tmp/realm-cm.yaml

# Restart keycloak to pick up changes
oc rollout restart deployment/keycloak -n spiffe-demo
```

---

## Step 6: Verify token exchange works

After deployment:

```bash
# 1. Get agent-service token
AGENT_TOKEN=$(curl -s -X POST "$KEYCLOAK_URL/realms/spiffe-demo/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=agent-service" \
  -d "client_secret=agent-service-secret" | jq -r '.access_token')

# 2. Enable management permissions on document-service (one-time setup)
DOC_UUID=$(curl -s "$KEYCLOAK_URL/admin/realms/spiffe-demo/clients?clientId=document-service" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

curl -X PUT "$KEYCLOAK_URL/admin/realms/spiffe-demo/clients/$DOC_UUID/management/permissions" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'

# 3. Configure the token-exchange permission via Admin Console:
#    - Clients → realm-management → Authorization → Permissions
#    - Find token-exchange.permission.client.$DOC_UUID
#    - Edit and add a policy that allows agent-service

# 4. Test token exchange
curl -s -X POST "$KEYCLOAK_URL/realms/spiffe-demo/protocol/openid-connect/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "client_id=agent-service" \
  -d "client_secret=agent-service-secret" \
  -d "subject_token=$AGENT_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "audience=document-service" | jq
```

---

## Files to modify

| File | Change |
| ---- | ------ |
| `deploy/k8s/base/keycloak.yaml` | Add feature flags, add clients to realm JSON |
| `deploy/keycloak/realm-spiffe-demo.json` | Add clients (keep in sync with ConfigMap) |
| New: `deploy/k8s/overlays/keycloak-postgres/` | Optional PostgreSQL overlay |

---

## Tomorrow's checklist

1. [ ] Update `deploy/k8s/base/keycloak.yaml` with feature flags
2. [ ] Add `agent-service` and `document-service` to realm JSON
3. [ ] Apply changes to OpenShift: `oc apply -k deploy/k8s/base`
4. [ ] Enable management permissions on `document-service` via API
5. [ ] Configure token-exchange policy via Admin Console
6. [ ] Test token exchange with curl
7. [ ] Continue with sts-token-exchange Task 2 (Go implementation)
