# Phase 3: Production Readiness & Observability

## Status: 🚧 IN PROGRESS

## Overview

Phase 3 builds on the real SPIFFE/SPIRE integration from Phase 2 to add production-grade features:
- CI/CD pipeline with automated image builds
- Observability stack (metrics, logging, tracing)
- Enhanced health checks with SVID status
- Certificate rotation verification
- Security hardening

## Goals

1. **Automated CI/CD**: Build and push images on every commit
2. **Observability**: Metrics, structured logging, distributed tracing
3. **Production Health Checks**: SVID-aware health endpoints
4. **Security Hardening**: Network policies, RBAC, secret management
5. **Documentation**: Runbooks and operational guides

---

## Task Groups

### Group A: CI/CD Pipeline ✅

#### Task A1: GitHub Actions Workflow ✅

**Status**: Completed

**Objective**: Automatically build and push images to ghcr.io on every push to main.

**File**: `.github/workflows/build-push.yaml`

**Decision**: Build only on push to main (not on PRs) to conserve GitHub Actions minutes. For a demo project, local testing before merge is sufficient.

```yaml
name: Build and Push Images

on:
  push:
    branches: [main]
    paths:
      - '**/*.go'
      - '**/Dockerfile'
      - 'go.mod'
      - 'go.sum'
      - 'opa-service/policies/**'
      - '.github/workflows/build-push.yaml'

env:
  REGISTRY: ghcr.io
  IMAGE_PREFIX: ghcr.io/hardwaylabs/spiffe-spire-demo

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    strategy:
      matrix:
        service:
          - web-dashboard
          - user-service
          - agent-service
          - document-service
          - opa-service
    steps:
      - uses: actions/checkout@v4

      - name: Set up QEMU
        uses: docker/setup-qemu-action@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.IMAGE_PREFIX }}/${{ matrix.service }}
          tags: |
            type=raw,value=latest,enable={{is_default_branch}}
            type=sha,prefix=sha-,format=short

      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: ./${{ matrix.service }}
          push: ${{ github.event_name != 'pull_request' }}
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

**Estimated effort**: 2-3 hours

#### Task A2: Multi-Architecture Builds ✅

**Status**: Completed (included in Task A1)

**Objective**: Build for both amd64 and arm64 (Apple Silicon support).

The workflow already includes QEMU setup and builds for `linux/amd64,linux/arm64`.

#### Task A3: Integration Tests in CI ⏸️

**Status**: Deferred - Running tests locally for now to conserve CI minutes.

**Objective**: Run tests before merging PRs.

**New workflow**: `.github/workflows/test.yaml`

```yaml
name: Test

on:
  pull_request:
    branches: [main]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'
      - run: make test

  policy-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make test-policies

  integration-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Create Kind cluster
        uses: helm/kind-action@v1
      - name: Deploy and test
        run: |
          kubectl apply -k deploy/k8s/overlays/mock
          kubectl -n spiffe-demo wait --for=condition=ready pod --all --timeout=120s
          ./scripts/test-authorization.sh
```

**Estimated effort**: 3-4 hours

---

### Group B: Observability ✅

#### Task B1: Prometheus Metrics ✅

**Status**: Completed

**Objective**: Expose metrics for monitoring SVID health, request latency, and authorization decisions.

**Implementation**:
- Created `pkg/metrics/metrics.go` with metrics definitions
- Added `/metrics` endpoint to all services (on health port for mTLS services)
- Metrics available: SVID expiration, rotations, request duration, authorization decisions

**New package**: `pkg/metrics/metrics.go`

```go
package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    // SVID metrics
    SVIDExpirationSeconds = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "spiffe_svid_expiration_seconds",
            Help: "Seconds until SVID expires",
        },
        []string{"spiffe_id"},
    )

    SVIDRotations = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "spiffe_svid_rotations_total",
            Help: "Total number of SVID rotations",
        },
        []string{"spiffe_id"},
    )

    // Request metrics
    RequestDuration = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "http_request_duration_seconds",
            Help:    "HTTP request duration",
            Buckets: prometheus.DefBuckets,
        },
        []string{"service", "method", "path", "status"},
    )

    // Authorization metrics
    AuthorizationDecisions = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "opa_authorization_decisions_total",
            Help: "OPA authorization decisions",
        },
        []string{"decision", "document_id", "caller_type"},
    )
)
```

**Metrics endpoint**: Each service exposes `/metrics` on a separate port.

**Estimated effort**: 4-5 hours

#### Task B2: Structured JSON Logging ✅

**Status**: Completed

**Objective**: Output structured logs for aggregation in production.

**Implementation**:
- Set `SPIFFE_DEMO_LOG_FORMAT=json` for structured JSON output
- Component is included as a default attribute in JSON logs
- Useful for log aggregation in production environments

**Usage**:
```bash
SPIFFE_DEMO_LOG_FORMAT=json ./bin/user-service serve
```

**Log format**:
```json
{
  "time": "2026-01-23T10:00:00Z",
  "level": "INFO",
  "msg": "Authorization decision",
  "component": "document-service",
  "spiffe_id": "spiffe://demo.example.com/user/alice",
  "document_id": "DOC-001",
  "decision": "allow"
}
```

#### Task B3: OpenTelemetry Tracing ⏸️

**Status**: Deferred - Not needed for demo project

**Objective**: Distributed tracing across service calls.

**New dependency**:
```bash
go get go.opentelemetry.io/otel
go get go.opentelemetry.io/otel/exporters/otlp/otlptrace
```

**Trace context propagation**:
```go
// In mTLS client
func (c *WorkloadClient) CreateHTTPClient(ctx context.Context) (*http.Client, error) {
    transport := &http.Transport{TLSClientConfig: tlsConfig}

    // Wrap with OpenTelemetry
    transport = otelhttp.NewTransport(transport)

    return &http.Client{Transport: transport}, nil
}
```

**Spans created**:
- `user-service.direct-access`
- `agent-service.delegated-access`
- `document-service.authorize`
- `opa-service.evaluate-policy`

**Estimated effort**: 5-6 hours

#### Task B4: Grafana Dashboard ⏸️

**Status**: Deferred - Not needed for demo project

**Objective**: Pre-built dashboard for monitoring the demo.

**Panels** (if implemented later):
1. SVID TTL remaining (per service)
2. Request rate by service
3. Authorization allow/deny ratio
4. Request latency percentiles (p50, p95, p99)
5. Active delegations

---

### Group C: Enhanced Health Checks

#### Task C1: SVID-Aware Health Endpoints

**Objective**: Health endpoints report SVID status and expiration.

**Update health handlers** in each service:

```go
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
    health := HealthResponse{
        Status:  "healthy",
        Service: s.serviceName,
    }

    // Add SVID info if available
    if s.spiffeClient != nil {
        identity := s.spiffeClient.GetIdentity()
        if identity != nil && identity.Certificate != nil {
            health.SVID = &SVIDHealth{
                SPIFFEID:  identity.SPIFFEID,
                ExpiresAt: identity.Certificate.NotAfter,
                TTL:       time.Until(identity.Certificate.NotAfter).String(),
                Valid:     time.Now().Before(identity.Certificate.NotAfter),
            }

            if !health.SVID.Valid {
                health.Status = "unhealthy"
            }
        }
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(health)
}
```

**Response format**:
```json
{
  "status": "healthy",
  "service": "user-service",
  "svid": {
    "spiffe_id": "spiffe://demo.example.com/service/user-service",
    "expires_at": "2026-01-23T11:00:00Z",
    "ttl": "45m30s",
    "valid": true
  }
}
```

**Estimated effort**: 2-3 hours

#### Task C2: Readiness vs Liveness Probes

**Objective**: Separate logic for readiness (can serve traffic) vs liveness (should restart).

| Probe | Checks | Failure Action |
|-------|--------|----------------|
| Liveness | Process running, not deadlocked | Restart pod |
| Readiness | SVID valid, dependencies reachable | Remove from service |

**Implementation**:
```go
// /health - liveness (always healthy if process is running)
func (s *Server) handleLiveness(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("OK"))
}

// /ready - readiness (check SVID and dependencies)
func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
    if !s.hasSVID() {
        http.Error(w, "SVID not ready", http.StatusServiceUnavailable)
        return
    }
    if !s.canReachDependencies() {
        http.Error(w, "Dependencies not ready", http.StatusServiceUnavailable)
        return
    }
    w.WriteHeader(http.StatusOK)
}
```

**Estimated effort**: 2 hours

---

### Group D: Certificate Rotation

#### Task D1: Verify Automatic Rotation

**Objective**: Confirm go-spiffe's X509Source handles rotation.

**Test procedure**:
1. Deploy services with SPIRE (1-hour SVID TTL)
2. Run continuous load test
3. Monitor SVID expiration timestamps
4. Verify no connection errors during rotation
5. Confirm new SVIDs acquired automatically

**Script**: `scripts/test-rotation.sh`

```bash
#!/bin/bash
# Monitor SVID rotation over time

echo "Starting SVID rotation monitoring..."
echo "SVIDs have 1-hour TTL, rotation happens at ~50% TTL"

while true; do
    echo "=== $(date) ==="
    for pod in $(kubectl get pods -n spiffe-demo -o name); do
        kubectl exec -n spiffe-demo $pod -- \
            curl -s localhost:8182/health 2>/dev/null | jq -r '.svid.ttl // "N/A"'
    done
    sleep 300  # Check every 5 minutes
done
```

**Estimated effort**: 2-3 hours

#### Task D2: Rotation Metrics

**Objective**: Track rotation events for monitoring.

**Add to SVID watcher**:
```go
func (c *WorkloadClient) watchSVIDRotation(ctx context.Context) {
    go func() {
        for {
            select {
            case <-ctx.Done():
                return
            case <-c.x509Source.Updated():
                svid, _ := c.x509Source.GetX509SVID()
                c.log.SVID(svid.ID.String(), "SVID rotated")
                metrics.SVIDRotations.WithLabelValues(svid.ID.String()).Inc()
                metrics.SVIDExpirationSeconds.WithLabelValues(svid.ID.String()).Set(
                    time.Until(svid.Certificates[0].NotAfter).Seconds(),
                )
            }
        }
    }()
}
```

**Estimated effort**: 2 hours

---

### Group E: Security Hardening

#### Task E1: Kubernetes Network Policies

**Objective**: Restrict pod-to-pod communication to only what's needed.

**File**: `deploy/k8s/base/network-policies.yaml`

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: document-service
  namespace: spiffe-demo
spec:
  podSelector:
    matchLabels:
      app: document-service
  policyTypes:
    - Ingress
    - Egress
  ingress:
    # Only allow from user-service and agent-service
    - from:
        - podSelector:
            matchLabels:
              app: user-service
        - podSelector:
            matchLabels:
              app: agent-service
      ports:
        - port: 8084
  egress:
    # Only allow to opa-service
    - to:
        - podSelector:
            matchLabels:
              app: opa-service
      ports:
        - port: 8085
    # Allow DNS
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
```

**Estimated effort**: 3-4 hours

#### Task E2: Pod Security Standards

**Objective**: Apply Kubernetes Pod Security Standards.

**Labels for namespace**:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: spiffe-demo
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

**Update deployments**:
```yaml
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: service
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
            readOnlyRootFilesystem: true
```

**Estimated effort**: 2-3 hours

#### Task E3: SPIFFE ID Authorization

**Objective**: Restrict which SPIFFE IDs each service accepts.

**Current**: `tlsconfig.AuthorizeAny()` - accepts any valid SPIFFE ID

**Enhanced**:
```go
// document-service only accepts user-service and agent-service
authorizer := tlsconfig.AuthorizeOneOf(
    spiffeid.RequireFromString("spiffe://demo.example.com/service/user-service"),
    spiffeid.RequireFromString("spiffe://demo.example.com/service/agent-service"),
)

tlsConfig := tlsconfig.MTLSServerConfig(source, source, authorizer)
```

**Configuration**:
```yaml
# config.yaml
spiffe:
  allowed_callers:
    - spiffe://demo.example.com/service/user-service
    - spiffe://demo.example.com/service/agent-service
```

**Estimated effort**: 3-4 hours

---

### Group F: Documentation & Operational Guides ✅

#### Task F1: Operational Runbook ✅

**Status**: Completed

**File**: `docs/OPERATIONS.md`

**Contents**:
1. Deployment procedures
2. Monitoring and alerting
3. Troubleshooting common issues
4. SVID rotation verification
5. SPIRE server maintenance
6. Disaster recovery

#### Task F2: Security Documentation ✅

**Status**: Completed

**File**: `docs/SECURITY.md`

**Contents**:
1. Threat model
2. Trust boundaries
3. SPIFFE ID format and meaning
4. Network security
5. Secret management
6. Incident response

#### Task F3: Architecture Decision Records ✅

**Status**: Completed

**Directory**: `docs/adr/`

**ADRs created**:
- ADR-0001: Use SPIFFE/SPIRE for workload identity
- ADR-0002: Permission intersection for AI agent delegation
- ADR-0003: OPA for policy evaluation
- ADR-0004: Kustomize for deployment variants
- ADR-0005: Separate health ports for mTLS services

---

## Implementation Priority

### P0 - Must Have (Before Production)

| Task | Effort | Description |
|------|--------|-------------|
| A1 | 2-3h | GitHub Actions CI/CD |
| C1 | 2-3h | SVID-aware health endpoints |
| D1 | 2-3h | Verify rotation works |
| E1 | 3-4h | Network policies |

### P1 - Should Have

| Task | Effort | Description |
|------|--------|-------------|
| A2 | 1h | Multi-arch builds |
| A3 | 3-4h | Integration tests in CI |
| B1 | 4-5h | Prometheus metrics |
| B2 | 2-3h | Structured JSON logging |
| E2 | 2-3h | Pod security standards |

### P2 - Nice to Have

| Task | Effort | Description |
|------|--------|-------------|
| B3 | 5-6h | OpenTelemetry tracing |
| B4 | 3-4h | Grafana dashboard |
| E3 | 3-4h | SPIFFE ID authorization |
| ~~F1-F3~~ | ~~10-13h~~ | ~~Documentation~~ ✅ Completed |

---

## Timeline Estimate

| Priority | Total Effort | Scope |
|----------|--------------|-------|
| P0 | 10-13 hours | Minimum for production |
| P0 + P1 | 23-31 hours | Recommended |
| All | 46-60 hours | Complete Phase 3 |

---

## Success Criteria

- [x] Images automatically built and pushed on merge to main
- [x] All services expose `/metrics` endpoint
- [ ] Health endpoints report SVID expiration
- [ ] Certificate rotation verified over 2+ hour period
- [ ] Network policies restrict pod communication
- [ ] No privilege escalation in pods
- [x] Operational runbook complete
- [x] Security documentation complete
- [x] Architecture Decision Records complete

---

## Dependencies

- Phase 2 complete (mTLS working)
- GitHub repository with Actions enabled
- Container registry access (ghcr.io)
- Prometheus/Grafana for observability (optional, can use Kind addon)

---

## References

- [GitHub Actions](https://docs.github.com/en/actions)
- [Prometheus Go Client](https://github.com/prometheus/client_golang)
- [OpenTelemetry Go](https://opentelemetry.io/docs/instrumentation/go/)
- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [SPIFFE ID Authorization](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig#Authorizer)
