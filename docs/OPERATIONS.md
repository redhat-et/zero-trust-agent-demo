# Operations Runbook

This document provides operational guidance for deploying, monitoring, and troubleshooting the SPIFFE/SPIRE Zero Trust Demo.

## Table of Contents

1. [Deployment Procedures](#deployment-procedures)
2. [Document Storage Operations](#document-storage-operations)
3. [Monitoring and Alerting](#monitoring-and-alerting)
4. [Troubleshooting Guide](#troubleshooting-guide)
5. [SVID Rotation Verification](#svid-rotation-verification)
6. [SPIRE Server Maintenance](#spire-server-maintenance)
7. [Backup and Recovery](#backup-and-recovery)

---

## Deployment Procedures

### Prerequisites

- Kubernetes cluster (1.25+) or OpenShift (4.12+)
- kubectl configured with cluster access
- Container images available in registry

### Quick Deploy (Kind)

```bash
# Create cluster
./scripts/setup-kind.sh

# Deploy application
kubectl apply -k deploy/k8s/overlays/local

# Verify deployment
kubectl get pods -n spiffe-demo
```

### Production Deploy (Kustomize)

```bash
# Deploy with real SPIRE
kubectl apply -k deploy/k8s/overlays/spire

# Wait for SPIRE to be ready
kubectl -n spire wait --for=condition=ready pod -l app=spire-server --timeout=120s
kubectl -n spire wait --for=condition=ready pod -l app=spire-agent --timeout=120s

# Deploy application
kubectl apply -k deploy/k8s/base

# Register workload entries
./scripts/register-entries.sh
```

### OpenShift Deploy

```bash
# Option 1: Without persistent storage (mock storage)
oc apply -k deploy/k8s/overlays/openshift

# Option 2: With ODF storage (requires OpenShift Data Foundation)
oc apply -k deploy/k8s/overlays/openshift-storage

# Wait for OBC to bind (if using storage overlay)
oc wait --for=condition=Bound obc/doc-storage-bucket -n spiffe-demo --timeout=120s

# Route is created automatically by the overlay
oc get route -n spiffe-demo
```

See [OpenShift deployment guide](deployment/openshift.md) for detailed instructions.

### Rollback Procedure

```bash
# List deployment history
kubectl rollout history deployment/document-service -n spiffe-demo

# Rollback to previous version
kubectl rollout undo deployment/document-service -n spiffe-demo

# Rollback to specific revision
kubectl rollout undo deployment/document-service -n spiffe-demo --to-revision=2
```

---

## Document Storage Operations

### Storage backends

The document-service supports two storage backends:

| Backend | Use case | Configuration |
|---------|----------|---------------|
| Mock (in-memory) | Local development, testing | Default when `SPIFFE_DEMO_STORAGE_ENABLED=false` |
| S3-compatible | Production, OpenShift | Requires S3 endpoint and credentials |

### Local development with MinIO

```bash
# Start MinIO container
docker run -d --name minio-test \
  -p 9000:9000 -p 9001:9001 \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin \
  minio/minio server /data --console-address ":9001"

# Create bucket
export AWS_ACCESS_KEY_ID=minioadmin
export AWS_SECRET_ACCESS_KEY=minioadmin
aws --endpoint-url http://localhost:9000 --region us-east-1 s3 mb s3://documents

# Set environment variables
export SPIFFE_DEMO_STORAGE_ENABLED=true
export BUCKET_HOST=localhost
export BUCKET_PORT=9000
export BUCKET_NAME=documents

# Seed sample documents
./bin/document-service seed

# Start document service
./bin/document-service serve --mock-spiffe
```

Alternatively, use the provided test script:

```bash
./scripts/test-s3-storage.sh
```

### MinIO console access

- URL: http://localhost:9001
- Username: `minioadmin`
- Password: `minioadmin`

### Document CRUD operations

All CRUD operations require admin department membership. Only Bob has admin access in the demo.

#### List documents

```bash
curl http://localhost:8084/documents
```

#### Create document (JSON)

```bash
curl -X POST http://localhost:8084/documents \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://demo.example.com/user/bob" \
  -d '{
    "id": "DOC-NEW",
    "title": "New Document",
    "required_departments": ["engineering"],
    "sensitivity": "medium",
    "content": "# New Document\n\nDocument content here."
  }'
```

#### Create document (multipart file upload)

```bash
curl -X POST http://localhost:8084/documents \
  -H "X-SPIFFE-ID: spiffe://demo.example.com/user/bob" \
  -F "file=@./my-document.md" \
  -F 'metadata={"id":"DOC-NEW","title":"New Document","required_departments":["engineering"],"sensitivity":"medium"};type=application/json'
```

#### Update document

```bash
curl -X PUT http://localhost:8084/documents/DOC-NEW \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://demo.example.com/user/bob" \
  -d '{
    "title": "Updated Title",
    "required_departments": ["engineering", "finance"],
    "sensitivity": "high",
    "content": "# Updated Content"
  }'
```

#### Delete document

```bash
curl -X DELETE http://localhost:8084/documents/DOC-NEW \
  -H "X-SPIFFE-ID: spiffe://demo.example.com/user/bob"
```

#### Get raw document content

```bash
curl http://localhost:8084/documents/DOC-001/content \
  -H "X-SPIFFE-ID: spiffe://demo.example.com/user/alice"
```

### Seeding documents

The seed command populates the bucket with sample documents:

```bash
# Seed only if bucket is empty
./bin/document-service seed --if-empty

# Force seed (overwrites existing)
./bin/document-service seed
```

In Kubernetes, an init container handles seeding automatically.

### S3 bucket structure

```text
bucket/
├── documents.json           # Metadata manifest
└── content/
    ├── DOC-001.md          # Document content files
    ├── DOC-002.md
    └── ...
```

### Troubleshooting storage issues

#### Issue: Document service fails to start with S3

**Symptoms:**

- "failed to ping storage" error
- Connection refused to S3 endpoint

**Diagnosis:**

```bash
# Check S3 endpoint reachability
curl http://${BUCKET_HOST}:${BUCKET_PORT}/minio/health/live

# Verify credentials
aws --endpoint-url http://${BUCKET_HOST}:${BUCKET_PORT} \
  --region us-east-1 s3 ls s3://${BUCKET_NAME}/
```

**Resolution:**

1. Verify BUCKET_HOST and BUCKET_PORT are correct
2. Check AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set
3. Ensure bucket exists and is accessible

#### Issue: CRUD operations return 403 Forbidden

**Symptoms:**

- Create/Update/Delete returns "Management access denied"

**Diagnosis:**

```bash
# Test management authorization directly
curl -X POST http://localhost:8085/v1/data/demo/authorization/management/decision \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "caller_spiffe_id": "spiffe://demo.example.com/user/bob"
    }
  }'
```

**Resolution:**

1. Verify caller has admin department membership
2. Check OPA service has document_management.rego loaded
3. Review user_permissions.rego for correct department assignments

#### Issue: Documents not persisting after restart

**Symptoms:**

- Documents disappear after pod restart
- Bucket appears empty

**Diagnosis:**

```bash
# Check if S3 storage is enabled
kubectl exec -n spiffe-demo deploy/document-service -- env | grep STORAGE

# List bucket contents
aws --endpoint-url http://${BUCKET_HOST}:${BUCKET_PORT} \
  --region us-east-1 s3 ls s3://${BUCKET_NAME}/ --recursive
```

**Resolution:**

1. Ensure SPIFFE_DEMO_STORAGE_ENABLED=true
2. Verify init container ran successfully
3. Check bucket permissions allow read/write

### OpenShift OBC operations

On OpenShift with ODF, storage is provisioned via ObjectBucketClaim.

#### Verify OBC status

```bash
# Check OBC is bound
oc get obc -n spiffe-demo
# Expected: PHASE=Bound

# View OBC details
oc describe obc doc-storage-bucket -n spiffe-demo
```

#### Check provisioned resources

```bash
# ConfigMap with bucket endpoint info
oc get configmap doc-storage-bucket -n spiffe-demo -o yaml

# Secret with credentials
oc get secret doc-storage-bucket -n spiffe-demo -o yaml
```

#### Access bucket directly

```bash
# Get bucket details from ConfigMap
BUCKET_HOST=$(oc get configmap doc-storage-bucket -n spiffe-demo -o jsonpath='{.data.BUCKET_HOST}')
BUCKET_PORT=$(oc get configmap doc-storage-bucket -n spiffe-demo -o jsonpath='{.data.BUCKET_PORT}')
BUCKET_NAME=$(oc get configmap doc-storage-bucket -n spiffe-demo -o jsonpath='{.data.BUCKET_NAME}')

# Get credentials from Secret
AWS_ACCESS_KEY_ID=$(oc get secret doc-storage-bucket -n spiffe-demo -o jsonpath='{.data.AWS_ACCESS_KEY_ID}' | base64 -d)
AWS_SECRET_ACCESS_KEY=$(oc get secret doc-storage-bucket -n spiffe-demo -o jsonpath='{.data.AWS_SECRET_ACCESS_KEY}' | base64 -d)

# List bucket contents (from a pod with aws cli)
oc run --rm -it aws-cli --image=amazon/aws-cli --restart=Never -- \
  --endpoint-url "http://${BUCKET_HOST}:${BUCKET_PORT}" \
  s3 ls "s3://${BUCKET_NAME}/" --recursive
```

#### Issue: OBC not binding

**Symptoms:**

- OBC stuck in Pending phase
- ConfigMap/Secret not created

**Diagnosis:**

```bash
# Check OBC events
oc describe obc doc-storage-bucket -n spiffe-demo

# Check NooBaa operator
oc get pods -n openshift-storage | grep noobaa
oc logs deployment/noobaa-operator -n openshift-storage --tail=50
```

**Resolution:**

1. Verify ODF is installed and healthy
2. Check NooBaa storage class exists: `oc get sc | grep noobaa`
3. Ensure NooBaa core and endpoint pods are running

#### Issue: Document service waiting for storage

**Symptoms:**

- Document service pod stuck in Init phase
- Init container logs show connection errors

**Diagnosis:**

```bash
# Check pod status
oc get pods -n spiffe-demo -l app=document-service

# Check init container logs
oc logs deployment/document-service -n spiffe-demo -c seed-documents
```

**Resolution:**

1. Wait for OBC to bind: `oc wait --for=condition=Bound obc/doc-storage-bucket -n spiffe-demo`
2. Restart deployment after OBC binds: `oc rollout restart deployment/document-service -n spiffe-demo`

---

## Monitoring and Alerting

### Health Endpoints

Each service exposes health endpoints:

| Service | Health Endpoint | Metrics Endpoint |
|---------|----------------|------------------|
| web-dashboard | `http://localhost:8080/health` | `http://localhost:8080/metrics` |
| user-service | `http://localhost:8182/health` | `http://localhost:8182/metrics` |
| agent-service | `http://localhost:8183/health` | `http://localhost:8183/metrics` |
| document-service | `http://localhost:8184/health` | `http://localhost:8184/metrics` |
| opa-service | `http://localhost:8185/health` | `http://localhost:8185/metrics` |

### Key Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `spiffe_svid_expiration_seconds` | Seconds until SVID expires | < 300 (5 min) |
| `spiffe_svid_rotations_total` | SVID rotation count | Sudden spike |
| `http_request_duration_seconds` | Request latency | p99 > 1s |
| `opa_authorization_decisions_total{decision="deny"}` | Denied requests | > 10/min |

### Health Check Commands

```bash
# Check all pods
kubectl get pods -n spiffe-demo -o wide

# Check service health
for svc in user-service agent-service document-service opa-service; do
  echo "=== $svc ==="
  kubectl exec -n spiffe-demo deploy/$svc -- curl -s localhost:8182/health 2>/dev/null || \
  kubectl exec -n spiffe-demo deploy/$svc -- curl -s localhost:8183/health 2>/dev/null || \
  kubectl exec -n spiffe-demo deploy/$svc -- curl -s localhost:8184/health 2>/dev/null || \
  kubectl exec -n spiffe-demo deploy/$svc -- curl -s localhost:8185/health 2>/dev/null
done

# Check SPIRE agent health
kubectl exec -n spire ds/spire-agent -- /opt/spire/bin/spire-agent healthcheck
```

### Log Aggregation

Enable JSON logging for production:

```yaml
env:
  - name: SPIFFE_DEMO_LOG_FORMAT
    value: "json"
```

Example log query (Loki/Grafana):

```logql
{namespace="spiffe-demo"} |= "authorization" | json | decision="deny"
```

---

## Troubleshooting Guide

### Issue: Pod Not Getting SVID

**Symptoms:**
- Pod stuck in "ContainerCreating"
- Health endpoint reports "SVID not ready"
- Logs show "context deadline exceeded" on SPIRE connection

**Diagnosis:**
```bash
# Check if SPIRE agent is running on node
kubectl get pods -n spire -o wide | grep spire-agent

# Check agent logs
kubectl logs -n spire ds/spire-agent --tail=50

# Verify workload registration
kubectl exec -n spire deploy/spire-server -- \
  /opt/spire/bin/spire-server entry show

# Check if selectors match
kubectl get pod <pod-name> -n spiffe-demo -o yaml | grep -A5 serviceAccount
```

**Resolution:**
1. Ensure SPIRE agent is running on the same node
2. Verify entry exists with correct selectors
3. Check that serviceAccount matches registration

### Issue: mTLS Connection Failures

**Symptoms:**
- "certificate signed by unknown authority" errors
- "x509: certificate has expired" errors
- Connection refused between services

**Diagnosis:**
```bash
# Check SVID expiration
kubectl exec -n spiffe-demo deploy/user-service -- \
  curl -s localhost:8182/health | jq '.svid'

# Verify trust bundle
kubectl exec -n spiffe-demo deploy/user-service -- \
  /opt/spire/bin/spire-agent api fetch x509 -socketPath /tmp/spire-agent/public/api.sock

# Test connection manually
kubectl exec -n spiffe-demo deploy/user-service -- \
  curl -v https://document-service:8084/health
```

**Resolution:**
1. If SVID expired, restart the pod to get fresh SVID
2. Ensure all services use same trust domain
3. Verify SPIRE server is healthy

### Issue: Authorization Denied Unexpectedly

**Symptoms:**
- Valid user/agent combination getting "denied"
- Inconsistent authorization results

**Diagnosis:**
```bash
# Test policy directly
curl -X POST http://localhost:8085/v1/data/demo/authorization/decision \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "caller_spiffe_id": "spiffe://demo.example.com/user/alice",
      "document_id": "DOC-001"
    }
  }' | jq .

# Check OPA logs
kubectl logs -n spiffe-demo deploy/opa-service --tail=100

# Verify policy is loaded
kubectl exec -n spiffe-demo deploy/opa-service -- \
  curl -s localhost:8181/v1/policies | jq '.result[].id'
```

**Resolution:**
1. Verify user/agent exists in policy files
2. Check permission intersection logic
3. Review OPA decision trace for denied requests

### Issue: High Latency

**Symptoms:**
- Slow response times (> 500ms)
- Timeouts on document access

**Diagnosis:**
```bash
# Check resource usage
kubectl top pods -n spiffe-demo

# Check OPA decision time
curl -w "@curl-format.txt" -X POST http://localhost:8085/v1/data/demo/authorization/decision ...

# Profile request flow
kubectl logs -n spiffe-demo deploy/document-service --tail=100 | grep duration
```

**Resolution:**
1. Scale up OPA if CPU-bound
2. Enable OPA decision caching
3. Check network policies for bottlenecks

---

## SVID Rotation Verification

### Monitoring Rotation

SVIDs have a 1-hour TTL and rotate automatically at ~50% TTL (30 minutes).

```bash
# Monitor SVID expiration over time
watch -n 60 'for pod in $(kubectl get pods -n spiffe-demo -o name); do \
  echo "$pod:"; \
  kubectl exec -n spiffe-demo $pod -- curl -s localhost:8182/health 2>/dev/null | jq -r ".svid.ttl // \"N/A\""; \
done'
```

### Rotation Test

```bash
#!/bin/bash
# scripts/test-rotation.sh

echo "Starting SVID rotation test..."
echo "Monitoring for 2 hours (SVIDs rotate ~every 30 min)"

START_TIME=$(date +%s)

while true; do
  ELAPSED=$(($(date +%s) - START_TIME))
  if [ $ELAPSED -gt 7200 ]; then
    echo "Test complete - 2 hours elapsed"
    break
  fi

  echo "=== $(date) (${ELAPSED}s elapsed) ==="

  for svc in user-service agent-service document-service; do
    TTL=$(kubectl exec -n spiffe-demo deploy/$svc -- \
      curl -s localhost:8182/health 2>/dev/null | jq -r '.svid.ttl // "N/A"')
    ROTATIONS=$(kubectl exec -n spiffe-demo deploy/$svc -- \
      curl -s localhost:8182/metrics 2>/dev/null | grep spiffe_svid_rotations_total | awk '{print $2}')
    echo "$svc: TTL=$TTL, Rotations=${ROTATIONS:-0}"
  done

  sleep 300
done
```

### Expected Behavior

- SVIDs should refresh before expiration
- No connection errors during rotation
- `spiffe_svid_rotations_total` counter increases
- Services remain available throughout

---

## SPIRE Server Maintenance

### Viewing Registered Entries

```bash
kubectl exec -n spire deploy/spire-server -- \
  /opt/spire/bin/spire-server entry show
```

### Adding New Entry

```bash
kubectl exec -n spire deploy/spire-server -- \
  /opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://demo.example.com/service/new-service \
  -parentID spiffe://demo.example.com/spire/agent/k8s_psat/demo-cluster/... \
  -selector k8s:ns:spiffe-demo \
  -selector k8s:sa:new-service
```

### Removing Entry

```bash
# List entries to find ID
kubectl exec -n spire deploy/spire-server -- \
  /opt/spire/bin/spire-server entry show

# Delete by entry ID
kubectl exec -n spire deploy/spire-server -- \
  /opt/spire/bin/spire-server entry delete -entryID <entry-id>
```

### Rotating Server CA

```bash
# Prepare new CA (generates new key pair)
kubectl exec -n spire deploy/spire-server -- \
  /opt/spire/bin/spire-server bundle rotate -prepareOnly

# Activate new CA (starts using new key)
kubectl exec -n spire deploy/spire-server -- \
  /opt/spire/bin/spire-server bundle rotate -activateOnly

# Remove old CA from bundle (after grace period)
kubectl exec -n spire deploy/spire-server -- \
  /opt/spire/bin/spire-server bundle prune
```

---

## Backup and Recovery

### What to Back Up

| Component | Location | Frequency |
|-----------|----------|-----------|
| SPIRE Server data | `/run/spire/data` | Daily |
| OPA policies | `opa-service/policies/` | On change (GitOps) |
| Kubernetes manifests | `deploy/k8s/` | On change (GitOps) |

### SPIRE Server Backup

```bash
# Create backup
kubectl exec -n spire deploy/spire-server -- \
  tar czf /tmp/spire-backup.tar.gz /run/spire/data

# Copy to local
kubectl cp spire/spire-server-xxx:/tmp/spire-backup.tar.gz ./spire-backup.tar.gz
```

### SPIRE Server Recovery

```bash
# Copy backup to new server
kubectl cp ./spire-backup.tar.gz spire/spire-server-xxx:/tmp/

# Restore data
kubectl exec -n spire deploy/spire-server -- \
  tar xzf /tmp/spire-backup.tar.gz -C /

# Restart server
kubectl rollout restart deployment/spire-server -n spire
```

### Disaster Recovery

If SPIRE server is lost and no backup exists:

1. Deploy fresh SPIRE server
2. Re-register all workload entries (`./scripts/register-entries.sh`)
3. Restart all workloads to get new SVIDs
4. No data loss for application (stateless demo)

---

## Runbook Checklist

### Daily Checks

- [ ] All pods in Running state
- [ ] No SVID expiration warnings
- [ ] Authorization deny rate within normal range
- [ ] No error spikes in logs

### Weekly Checks

- [ ] SVID rotation metrics healthy
- [ ] SPIRE server disk usage acceptable
- [ ] Review any new authorization denials
- [ ] Verify backup jobs completed

### Monthly Checks

- [ ] Review and update OPA policies
- [ ] Check for SPIRE updates
- [ ] Audit workload registrations
- [ ] Test disaster recovery procedure
