# OpenShift deployment guide

This guide covers deploying the SPIFFE/SPIRE Zero Trust Demo on OpenShift with persistent document storage using OpenShift Data Foundation (ODF).

## Prerequisites

- OpenShift 4.12+ cluster
- `oc` CLI configured with cluster access
- OpenShift Data Foundation (ODF) installed (for persistent storage)
- SPIRE operator installed (for workload identity)

## Deployment options

| Overlay | Storage | SPIRE | OIDC | AI Agents | Use case |
| ------- | ------- | ----- | ---- | --------- | -------- |
| `openshift` | Mock (in-memory) | Real | No | No | Demo without ODF or auth |
| `openshift-storage` | S3 via OBC | Real | No | No | Full production-like setup |
| `openshift-oidc` | Mock (in-memory) | Real | Yes | No | Demo with Keycloak OAuth |
| `openshift-ai-agents` | Mock (in-memory) | Real | Yes | Yes | Full demo with AI agents |

## Quick start (with ODF storage)

```bash
# 1. Verify ODF NooBaa storage class exists
oc get storageclasses | grep noobaa

# 2. Deploy application with storage
oc apply -k deploy/k8s/overlays/openshift-storage

# 3. Wait for OBC to bind (creates ConfigMap and Secret)
oc wait --for=condition=Bound obc/doc-storage-bucket -n spiffe-demo --timeout=120s

# 4. Wait for pods to be ready
oc wait --for=condition=Ready pods -l app=document-service -n spiffe-demo --timeout=120s

# 5. Get the route URL
oc get route -n spiffe-demo
```

## Step-by-step deployment

### Verify prerequisites

```bash
# Check ODF storage class
oc get storageclasses | grep noobaa
# Expected: openshift-storage.noobaa.io

# Check SPIRE operator (if using real SPIFFE)
oc get pods -n spire-system
```

### Deploy the application

```bash
# Apply the OpenShift storage overlay
oc apply -k deploy/k8s/overlays/openshift-storage
```

This creates:

- Namespace `spiffe-demo` with privileged pod security
- ObjectBucketClaim `doc-storage-bucket`
- ConfigMap `opa-policies` with Rego policies
- Deployments for all services
- Services and Route

### Verify OBC provisioning

```bash
# Check OBC status
oc get obc -n spiffe-demo
# Expected: PHASE=Bound

# Verify ConfigMap created by OBC
oc get configmap doc-storage-bucket -n spiffe-demo -o yaml
# Should contain: BUCKET_HOST, BUCKET_PORT, BUCKET_NAME

# Verify Secret created by OBC
oc get secret doc-storage-bucket -n spiffe-demo
# Should contain: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
```

### Verify deployment

```bash
# Check all pods are running
oc get pods -n spiffe-demo

# Check init container completed (document seeding)
oc logs deployment/document-service -n spiffe-demo -c seed-documents

# Check document-service logs
oc logs deployment/document-service -n spiffe-demo -c document-service

# Test health endpoint
oc exec deployment/document-service -n spiffe-demo -- curl -s localhost:8184/health
```

### Access the dashboard

```bash
# Get route URL
ROUTE_URL=$(oc get route web-dashboard -n spiffe-demo -o jsonpath='{.spec.host}')
echo "Dashboard: https://${ROUTE_URL}"
```

## Deployment without ODF

If ODF is not available, use the basic OpenShift overlay with mock storage:

```bash
# Deploy without persistent storage
oc apply -k deploy/k8s/overlays/openshift

# Documents will use in-memory mock storage
# Documents are lost on pod restart
```

## Deployment with Keycloak OIDC

The `openshift-oidc` overlay adds Keycloak authentication to the dashboard.

### Prerequisites

- No additional prerequisites beyond the base OpenShift requirements
- Keycloak runs in the same namespace as other services

### Deploy with OIDC

```bash
# 1. Get your cluster domain
CLUSTER_DOMAIN=$(oc get ingresses.config/cluster -o jsonpath='{.spec.domain}')
echo "Cluster domain: $CLUSTER_DOMAIN"

# 2. Generate files from templates
cd deploy/k8s/overlays/openshift-oidc
sed "s/CLUSTER_DOMAIN/$CLUSTER_DOMAIN/g" oidc-urls-configmap.yaml.template > oidc-urls-configmap.yaml
sed "s/CLUSTER_DOMAIN/$CLUSTER_DOMAIN/g" keycloak-realm-patch.yaml.template > keycloak-realm-patch.yaml
cd -

# 3. Deploy
oc apply -k deploy/k8s/overlays/openshift-oidc

# 4. Wait for Keycloak to be ready (takes about 60-90 seconds)
oc wait --for=condition=Ready pods -l app=keycloak -n spiffe-demo --timeout=120s

# 5. Wait for dashboard
oc wait --for=condition=Ready pods -l app=web-dashboard -n spiffe-demo --timeout=60s

# 6. Get the URLs
echo "Dashboard: https://web-dashboard-spiffe-demo.$CLUSTER_DOMAIN"
echo "Keycloak:  https://keycloak-spiffe-demo.$CLUSTER_DOMAIN"
```

### Demo users

The following users are pre-configured in Keycloak:

| User | Password | Groups |
| ---- | -------- | ------ |
| alice | alice123 | engineering, finance |
| bob | bob123 | finance, admin |
| carol | carol123 | hr |
| david | david123 | engineering, hr |

### Keycloak admin access

```bash
# Admin console URL
echo "Admin: https://keycloak-spiffe-demo.$CLUSTER_DOMAIN/admin"
# Username: admin
# Password: admin123
```

## Deployment with AI agents

The `openshift-ai-agents` overlay extends `openshift-oidc` with AI agent services (summarizer and reviewer) and LiteLLM configuration.

### Prerequisites

- LiteLLM API key (or other OpenAI-compatible LLM provider)

### Deploy with AI agents

```bash
# 1. Get your cluster domain and generate OIDC config files
CLUSTER_DOMAIN=$(oc get ingresses.config/cluster -o jsonpath='{.spec.domain}')
cd deploy/k8s/overlays/openshift-oidc
sed "s/CLUSTER_DOMAIN/$CLUSTER_DOMAIN/g" oidc-urls-configmap.yaml.template > oidc-urls-configmap.yaml
sed "s/CLUSTER_DOMAIN/$CLUSTER_DOMAIN/g" keycloak-realm-patch.yaml.template > keycloak-realm-patch.yaml
cd -

# 2. Create the LLM secret
cd deploy/k8s/overlays/openshift-ai-agents
cp llm-secret.yaml.template llm-secret.yaml
# Edit llm-secret.yaml with your LLM API key
cd -

# 3. Apply the secret (it's not in kustomization to avoid committing secrets)
oc apply -f deploy/k8s/overlays/openshift-ai-agents/llm-secret.yaml -n spiffe-demo

# 4. Deploy the application
oc apply -k deploy/k8s/overlays/openshift-ai-agents

# 5. Wait for all pods
oc wait --for=condition=Ready pods --all -n spiffe-demo --timeout=180s

# 6. Get the dashboard URL
echo "Dashboard: https://web-dashboard-spiffe-demo.$CLUSTER_DOMAIN"
```

### LLM configuration

The overlay is configured for LiteLLM by default (via `llm-config` ConfigMap):

| Variable | Default Value |
| -------- | ------------- |
| `LLM_PROVIDER` | litellm |
| `LLM_BASE_URL` | https://litellm-prod.apps.maas.redhatworkshops.io/v1 |
| `LLM_MODEL` | qwen3-14b |

To use a different provider, modify the `configMapGenerator` in the overlay's `kustomization.yaml`.

### Testing AI agents

1. Open the dashboard and log in via Keycloak
2. Select a document (e.g., DOC-002 - Q4 Financial Report)
3. Select an agent (Summarizer or Reviewer)
4. Click "Summarize" or "Review"

The Summarizer agent only has `finance` permissions, so it can only access finance documents.
The Reviewer agent has all department permissions.

## Development workflow

For iterative development on OpenShift, use git SHA-based image tagging to ensure each deployment uses unique, traceable images.

### Prerequisites

```bash
# Verify required tools are installed
make check-deps
```

### Build and deploy

```bash
# Build x86_64 images, push to ghcr.io, update kustomization, and deploy
make deploy-openshift
```

This command:

1. Builds all service images for `linux/amd64` platform
2. Tags images with the current git SHA (e.g., `e2920fc`)
3. Pushes images to `ghcr.io/redhat-et/zero-trust-agent-demo`
4. Updates `kustomization.yaml` with new image tags
5. Applies the kustomization to OpenShift

### Quick deploy (skip rebuild)

If images are already pushed, just update tags and apply:

```bash
make deploy-openshift-quick
```

### Restart deployments

To pick up new images with the same tag (after a push):

```bash
make restart-openshift
```

### Custom tags

```bash
# Use a specific tag
make deploy-openshift DEV_TAG=my-feature

# Deploy a previous version
make deploy-openshift-quick DEV_TAG=abc1234
```

### Registry cleanup

Development creates many tagged images. Clean up old versions periodically:

```bash
# List recent tags
make ghcr-list

# Delete old versions (keeps last 10 by default)
make ghcr-cleanup

# Keep fewer versions
make ghcr-cleanup KEEP_VERSIONS=5
```

## ObjectBucketClaim details

The OBC creates resources automatically when bound:

| Resource | Name | Contents |
|----------|------|----------|
| ConfigMap | `doc-storage-bucket` | `BUCKET_HOST`, `BUCKET_PORT`, `BUCKET_NAME`, `BUCKET_REGION`, `BUCKET_SUBREGION` |
| Secret | `doc-storage-bucket` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` |

These are injected into the document-service via `envFrom`.

### Bucket structure

```text
doc-storage-xxxxx/
├── documents.json           # Metadata manifest
└── content/
    ├── DOC-001.md          # Document content
    ├── DOC-002.md
    └── ...
```

## SPIRE integration

The OpenShift overlays configure SPIRE CSI driver for workload identity:

```yaml
volumeMounts:
  - name: spire-agent-socket
    mountPath: /run/spire/agent-sockets
    readOnly: true
volumes:
  - name: spire-agent-socket
    csi:
      driver: "csi.spiffe.io"
      readOnly: true
```

SELinux context (`spc_t`) is required for CSI driver access on OpenShift.

### Verify SPIFFE identity

```bash
# Check if service has SVID
oc exec deployment/document-service -n spiffe-demo -- \
  curl -s localhost:8184/health | jq '.spiffe_id'
```

## Troubleshooting

### OBC not binding

```bash
# Check OBC events
oc describe obc doc-storage-bucket -n spiffe-demo

# Check NooBaa operator logs
oc logs deployment/noobaa-operator -n openshift-storage
```

Common issues:

- NooBaa not ready: Wait for NooBaa pods in `openshift-storage` namespace
- Storage class missing: Verify ODF installation

### Init container failing

```bash
# Check init container logs
oc logs deployment/document-service -n spiffe-demo -c seed-documents

# Check if storage credentials are available
oc exec deployment/document-service -n spiffe-demo -c document-service -- env | grep -E "(BUCKET|AWS)"
```

Common issues:

- Missing credentials: OBC not yet bound
- S3 connection failed: Check BUCKET_HOST and network policies

### Document service not starting

```bash
# Check container logs
oc logs deployment/document-service -n spiffe-demo -c document-service --previous

# Verify storage is accessible
oc exec deployment/document-service -n spiffe-demo -- \
  curl -s "http://${BUCKET_HOST}:${BUCKET_PORT}/minio/health/live"
```

### SELinux denials

```bash
# Check for SELinux denials
oc adm node-logs --role=worker --path=journal -u crio | grep denied

# Verify security context
oc get deployment document-service -n spiffe-demo -o yaml | grep -A5 securityContext
```

The `spc_t` SELinux type is required for CSI driver access.

## Cleanup

```bash
# Delete all resources
oc delete -k deploy/k8s/overlays/openshift-storage

# The OBC deletion will also delete:
# - The ObjectBucket
# - The S3 bucket and its contents
# - The ConfigMap and Secret
```

## Next steps

- [Operations runbook](../OPERATIONS.md) - Day-2 operations
- [Security documentation](../SECURITY.md) - Security model details
- [Architecture](../ARCHITECTURE.md) - System design
