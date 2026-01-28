# OpenShift deployment guide

This guide covers deploying the SPIFFE/SPIRE Zero Trust Demo on OpenShift with persistent document storage using OpenShift Data Foundation (ODF).

## Prerequisites

- OpenShift 4.12+ cluster
- `oc` CLI configured with cluster access
- OpenShift Data Foundation (ODF) installed (for persistent storage)
- SPIRE operator installed (for workload identity)

## Deployment options

| Overlay | Storage | SPIRE | Use case |
|---------|---------|-------|----------|
| `openshift` | Mock (in-memory) | Real | Demo without ODF |
| `openshift-storage` | S3 via OBC | Real | Full production-like setup |

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
