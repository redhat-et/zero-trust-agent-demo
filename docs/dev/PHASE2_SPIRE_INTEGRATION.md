# Phase 2: Real SPIFFE/SPIRE Integration

## Status: ✅ COMPLETED (January 22, 2026)

> **Note**: Phase 2 implementation was completed on January 22, 2026. See [SESSION_LOG_2026-01-22.md](SESSION_LOG_2026-01-22.md) for detailed implementation notes and debugging procedures.

## Overview

Phase 2 replaces the mock SPIFFE implementation with real SPIRE infrastructure, enabling:
- Cryptographic workload identity via X.509 SVIDs
- Mutual TLS (mTLS) between all services
- Automatic certificate rotation (1-hour TTL)
- Identity attestation based on Kubernetes pod attributes

## Previous State (Phase 1)

| Component              | Implementation              |
| ---------------------- | --------------------------- |
| Identity               | Hardcoded SPIFFE ID strings |
| Authentication         | `X-SPIFFE-ID` HTTP header   |
| Transport              | Plain HTTP                  |
| Certificate Management | None                        |

## Current State (Phase 2 - Implemented)

| Component              | Implementation                        |
| ---------------------- | ------------------------------------- |
| Identity               | X.509 SVIDs from SPIRE Agent          |
| Authentication         | mTLS with peer certificate validation |
| Transport              | HTTPS with mutual TLS                 |
| Certificate Management | Auto-rotation via SPIRE Workload API  |

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                        SPIRE Server                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │ Registration│  │   Built-in  │  │    Trust Bundle         │  │
│  │     API     │  │     CA      │  │    Distribution         │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
└────────────────────────────┬────────────────────────────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        ┌──────────┐   ┌──────────┐   ┌──────────┐
        │  SPIRE   │   │  SPIRE   │   │  SPIRE   │
        │  Agent   │   │  Agent   │   │  Agent   │
        │ (node 1) │   │ (node 2) │   │ (node 3) │
        └────┬─────┘   └────┬─────┘   └────┬─────┘
             │              │              │
     ┌───────┴───────┐     │      ┌───────┴───────┐
     ▼               ▼     ▼      ▼               ▼
┌─────────┐   ┌─────────┐ ┌─────────┐   ┌─────────┐
│  web    │   │  user   │ │  agent  │   │   doc   │
│dashboard│   │ service │ │ service │   │ service │
└─────────┘   └─────────┘ └─────────┘   └─────────┘
                                              │
                                              ▼
                                        ┌─────────┐
                                        │   OPA   │
                                        │ service │
                                        └─────────┘
```

### Trust Domain

```text
spiffe://demo.example.com/
├── spire-server
├── spire-agent
├── web-dashboard
├── user-service
├── agent-service
├── document-service
├── opa-service
├── user/
│   ├── alice
│   ├── bob
│   └── carol
└── agent/
    ├── gpt4
    ├── claude
    └── summarizer
```

---

## Implementation Tasks

### Task 1: Add SPIRE Helm Charts ✅

**Status**: Completed - See `scripts/setup-spire.sh`

**Objective**: Deploy SPIRE Server and Agents to the Kind cluster.

**Files to create**:
- `deploy/spire/values.yaml` - SPIRE Helm values
- `deploy/spire/registration-entries.yaml` - Workload registrations

**Steps**:
1. Add SPIRE Helm repository
2. Create custom values for Kind environment
3. Configure node attestation (k8s_psat)
4. Configure workload attestation (k8s)

**Helm installation**:
```bash
helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/
helm install spire spiffe/spire \
  --namespace spire-system \
  --create-namespace \
  --values deploy/spire/values.yaml
```

**Estimated effort**: 2-3 hours

---

### Task 2: Create Workload Registration Entries ✅

**Status**: Completed - Workloads registered via `scripts/setup-spire.sh`

**Objective**: Register each service with SPIRE so it receives the correct SPIFFE ID.

**Registration entries needed**:

| Service          | SPIFFE ID                                    | Selector                             |
| ---------------- | -------------------------------------------- | ------------------------------------ |
| web-dashboard    | `spiffe://demo.example.com/web-dashboard`    | `k8s:pod-label:app:web-dashboard`    |
| user-service     | `spiffe://demo.example.com/user-service`     | `k8s:pod-label:app:user-service`     |
| agent-service    | `spiffe://demo.example.com/agent-service`    | `k8s:pod-label:app:agent-service`    |
| document-service | `spiffe://demo.example.com/document-service` | `k8s:pod-label:app:document-service` |
| opa-service      | `spiffe://demo.example.com/opa-service`      | `k8s:pod-label:app:opa-service`      |

**Example registration**:
```bash
kubectl exec -n spire-system spire-server-0 -- \
  spire-server entry create \
    -spiffeID spiffe://demo.example.com/user-service \
    -parentID spiffe://demo.example.com/spire-agent \
    -selector k8s:ns:spiffe-demo \
    -selector k8s:pod-label:app:user-service
```

**Estimated effort**: 1-2 hours

---

### Task 3: Add go-spiffe/v2 Dependency ✅

**Status**: Completed - Added in `pkg/spiffe/workload.go`

**Objective**: Add the official SPIFFE Go library to the project.

**Steps**:
```bash
go get github.com/spiffe/go-spiffe/v2@latest
```

**Key packages**:
- `workloadapi` - Fetch SVIDs from SPIRE Agent
- `tlsconfig` - Configure mTLS easily
- `spiffeid` - Parse and validate SPIFFE IDs

**Estimated effort**: 30 minutes

---

### Task 4: Implement Real FetchIdentity() ✅

**Status**: Completed - Implemented in `pkg/spiffe/workload.go`

**Objective**: Replace mock identity with real SVID fetching from SPIRE Agent.

**File**: `pkg/spiffe/workload.go`

**Current code** (lines 52-61):
```go
func (c *WorkloadClient) FetchIdentity(ctx context.Context) (*WorkloadIdentity, error) {
    if c.config.MockMode {
        c.log.Info("Mock mode: Skipping SPIRE Agent connection")
        return nil, nil
    }
    // Placeholder
    return nil, fmt.Errorf("real SPIFFE not implemented - use mock mode")
}
```

**New implementation**:
```go
import (
    "github.com/spiffe/go-spiffe/v2/workloadapi"
)

func (c *WorkloadClient) FetchIdentity(ctx context.Context) (*WorkloadIdentity, error) {
    if c.config.MockMode {
        c.log.Info("Mock mode: Skipping SPIRE Agent connection")
        return nil, nil
    }

    c.log.Info("Connecting to SPIRE Agent", "socket", c.config.SocketPath)

    source, err := workloadapi.NewX509Source(
        ctx,
        workloadapi.WithClientOptions(workloadapi.WithAddr(c.config.SocketPath)),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to create X509Source: %w", err)
    }

    svid, err := source.GetX509SVID()
    if err != nil {
        return nil, fmt.Errorf("failed to get X509SVID: %w", err)
    }

    bundle, err := source.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
    if err != nil {
        return nil, fmt.Errorf("failed to get trust bundle: %w", err)
    }

    c.identity = &WorkloadIdentity{
        SPIFFEID:    svid.ID.String(),
        Certificate: svid.Certificates[0],
        PrivateKey:  svid.PrivateKey,
        TrustBundle: bundle.X509Authorities(),
    }

    c.log.SVID(c.identity.SPIFFEID, "Acquired X509-SVID from SPIRE Agent")

    // Store source for later use (mTLS, rotation)
    c.x509Source = source

    return c.identity, nil
}
```

**Estimated effort**: 2-3 hours

---

### Task 5: Implement mTLS HTTP Client ✅

**Status**: Completed - `CreateMTLSClient()` in `pkg/spiffe/workload.go`

**Objective**: Create HTTP client that uses SVID for mutual TLS.

**File**: `pkg/spiffe/workload.go`

**Current code** (lines 76-95):
```go
func (c *WorkloadClient) CreateMTLSClient(timeout time.Duration) *http.Client {
    if c.config.MockMode {
        return &http.Client{Timeout: timeout}
    }
    // Placeholder with InsecureSkipVerify
}
```

**New implementation**:
```go
import (
    "github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

func (c *WorkloadClient) CreateMTLSClient(timeout time.Duration) *http.Client {
    if c.config.MockMode {
        return &http.Client{Timeout: timeout}
    }

    if c.x509Source == nil {
        c.log.Error("X509Source not initialized - call FetchIdentity first")
        return &http.Client{Timeout: timeout}
    }

    // Configure mTLS: present our SVID, verify peer's SVID
    tlsConfig := tlsconfig.MTLSClientConfig(
        c.x509Source,  // Our identity
        c.x509Source,  // Trust bundle for verifying peers
        tlsconfig.AuthorizeAny(),  // Accept any SPIFFE ID in our trust domain
    )

    return &http.Client{
        Timeout: timeout,
        Transport: &http.Transport{
            TLSClientConfig: tlsConfig,
        },
    }
}
```

**For more restrictive authorization**:
```go
// Only allow specific SPIFFE IDs
tlsconfig.AuthorizeID(spiffeid.RequireFromString("spiffe://demo.example.com/document-service"))

// Allow any ID matching a pattern
tlsconfig.AuthorizeMemberOf(trustDomain)
```

**Estimated effort**: 2-3 hours

---

### Task 6: Implement mTLS HTTP Server ✅

**Status**: Completed - `CreateHTTPServer()` in `pkg/spiffe/workload.go`

**Objective**: Configure each service to require and validate client certificates.

**New function in `pkg/spiffe/workload.go`**:
```go
func (c *WorkloadClient) CreateMTLSServer(addr string, handler http.Handler) *http.Server {
    if c.config.MockMode {
        return &http.Server{
            Addr:    addr,
            Handler: handler,
        }
    }

    tlsConfig := tlsconfig.MTLSServerConfig(
        c.x509Source,
        c.x509Source,
        tlsconfig.AuthorizeAny(),
    )

    return &http.Server{
        Addr:      addr,
        Handler:   handler,
        TLSConfig: tlsConfig,
    }
}
```

**Update each service's main.go**:
```go
// Before (plain HTTP)
server := &http.Server{Addr: ":8082", Handler: router}
server.ListenAndServe()

// After (mTLS)
server := spiffeClient.CreateMTLSServer(":8082", router)
server.ListenAndServeTLS("", "")  // Certs come from TLSConfig
```

**Estimated effort**: 2-3 hours

---

### Task 7: Update Identity Middleware ✅

**Status**: Completed - `IdentityMiddleware()` in `pkg/spiffe/workload.go`

**Objective**: Extract SPIFFE ID from peer certificate instead of HTTP header.

**File**: `pkg/spiffe/workload.go` (lines 98-120)

The middleware already handles this - just needs `mockMode=false`:
```go
if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
    cert := r.TLS.PeerCertificates[0]
    if len(cert.URIs) > 0 {
        spiffeID := cert.URIs[0].String()
        r = r.WithContext(context.WithValue(r.Context(), spiffeIDKey, spiffeID))
    }
}
```

**Estimated effort**: 1 hour

---

### Task 8: Update Kubernetes Deployments ✅

**Status**: Completed - See `deploy/k8s/deployments-spire.yaml`

**Objective**: Mount SPIRE Agent socket into each pod.

**Changes to `deploy/k8s/deployments.yaml`**:
```yaml
spec:
  template:
    spec:
      containers:
        - name: user-service
          # ... existing config ...
          env:
            - name: SPIFFE_DEMO_SERVICE_MOCK_SPIFFE
              value: "false"  # Changed from "true"
            - name: SPIFFE_ENDPOINT_SOCKET
              value: "unix:///run/spire/sockets/agent.sock"
          volumeMounts:
            - name: spire-agent-socket
              mountPath: /run/spire/sockets
              readOnly: true
      volumes:
        - name: spire-agent-socket
          hostPath:
            path: /run/spire/sockets
            type: Directory
```

**Estimated effort**: 1-2 hours

---

### Task 9: Update Dockerfiles ✅

**Status**: Completed - Images built and loaded into Kind cluster

**Objective**: Ensure containers can access SPIRE socket.

**Changes needed**:
- No code changes if using hostPath mount
- Ensure user has permission to read socket
- May need to add `RUN addgroup` commands if running as non-root

**Estimated effort**: 1 hour

---

### Task 10: Add Health Checks for SVID 🔄

**Status**: Partially Completed - Using TCP probes instead of HTTP (mTLS incompatibility). SVID-aware health checks pending.

**Objective**: Health endpoint should verify SVID is valid and not expired.

**New health check logic**:
```go
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
    health := map[string]interface{}{
        "status": "healthy",
        "service": s.serviceName,
    }

    if s.spiffeClient != nil && !s.config.MockSPIFFE {
        identity := s.spiffeClient.GetIdentity()
        if identity == nil {
            health["status"] = "unhealthy"
            health["spiffe"] = "no identity"
        } else if identity.Certificate != nil {
            if time.Now().After(identity.Certificate.NotAfter) {
                health["status"] = "unhealthy"
                health["spiffe"] = "certificate expired"
            } else {
                health["spiffe"] = "valid"
                health["spiffe_id"] = identity.SPIFFEID
                health["expires"] = identity.Certificate.NotAfter
            }
        }
    }

    json.NewEncoder(w).Encode(health)
}
```

**Estimated effort**: 1-2 hours

---

### Task 11: Test Certificate Rotation ⏳

**Status**: Pending - Requires waiting for SVID TTL expiration (default 1 hour)

**Objective**: Verify that services handle SVID rotation gracefully.

**Test plan**:
1. Deploy services with real SPIRE
2. Verify initial SVID acquisition
3. Wait for rotation (default: 1 hour, can be shortened for testing)
4. Verify new SVID is picked up without restart
5. Verify in-flight requests are not dropped

**go-spiffe handles this automatically** via the X509Source watching for updates.

**Estimated effort**: 2-3 hours (mostly waiting/testing)

---

### Task 12: Create Setup Script ✅

**Status**: Completed - See `scripts/setup-spire.sh`

**Objective**: Single script to deploy SPIRE + demo with real mTLS.

**File**: `scripts/setup-spire.sh`

```bash
#!/bin/bash
set -e

echo "=== Setting up SPIRE infrastructure ==="

# Add Helm repo
helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/
helm repo update

# Install SPIRE
helm install spire spiffe/spire \
  --namespace spire-system \
  --create-namespace \
  --values deploy/spire/values.yaml \
  --wait

# Wait for SPIRE server to be ready
kubectl wait --for=condition=ready pod -l app=spire-server -n spire-system --timeout=120s

# Create registration entries
./scripts/register-workloads.sh

echo "=== SPIRE setup complete ==="
echo "=== Deploying demo application ==="

kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/opa-policies-configmap.yaml
kubectl apply -f deploy/k8s/deployments.yaml

kubectl -n spiffe-demo wait --for=condition=ready pod --all --timeout=120s

echo "=== Demo ready at http://localhost:8080 ==="
```

**Estimated effort**: 2-3 hours

---

## Testing Checklist

- [x] SPIRE Server starts successfully
- [x] SPIRE Agents connect to server
- [x] Each service acquires SVID on startup
- [x] Services can communicate via mTLS
- [x] SPIFFE ID extracted correctly from certificates
- [x] OPA receives correct SPIFFE IDs for authorization
- [x] Demo scenarios work identically to Phase 1
- [ ] Certificate rotation works without service restart (pending)
- [ ] Health endpoints report SVID status (using TCP probes currently)

### Verified Scenarios (January 22-23, 2026)

| Scenario | Expected | Actual | Status |
|----------|----------|--------|--------|
| **Direct Access - Granted** ||||
| Alice → DOC-001 (engineering) | Granted | Granted | ✅ |
| **Direct Access - Denied** ||||
| Bob → DOC-001 (Bob lacks engineering) | Denied | Denied | ✅ |
| Carol → DOC-002 (Carol lacks finance) | Denied | Denied | ✅ |
| Alice → DOC-003 (Alice lacks admin) | Denied | Denied | ✅ |
| **Delegated Access - Granted** ||||
| Alice → GPT-4 → DOC-001 | Granted | Granted | ✅ |
| Bob → Claude → DOC-003 | Granted | Granted | ✅ |
| **Delegated Access - Denied** ||||
| GPT-4 → DOC-001 (no user delegation) | Denied | Denied | ✅ |
| Alice → Summarizer → DOC-001 (Summarizer lacks engineering) | Denied | Denied | ✅ |
| Bob → GPT-4 → DOC-003 (neither has admin) | Denied | Denied | ✅ |

---

## Rollback Plan

If Phase 2 issues arise:
1. Set `SPIFFE_DEMO_SERVICE_MOCK_SPIFFE=true` in all deployments
2. Remove SPIRE socket volume mounts
3. Redeploy services
4. Services will fall back to mock mode (HTTP headers)

The code maintains backward compatibility with mock mode.

---

## Timeline Estimate

| Task                         | Effort | Dependencies |
| ---------------------------- | ------ | ------------ |
| Task 1: SPIRE Helm Charts    | 2-3h   | None         |
| Task 2: Registration Entries | 1-2h   | Task 1       |
| Task 3: go-spiffe dependency | 30m    | None         |
| Task 4: FetchIdentity()      | 2-3h   | Task 3       |
| Task 5: mTLS Client          | 2-3h   | Task 4       |
| Task 6: mTLS Server          | 2-3h   | Task 4       |
| Task 7: Identity Middleware  | 1h     | Task 6       |
| Task 8: K8s Deployments      | 1-2h   | Task 1       |
| Task 9: Dockerfiles          | 1h     | Task 8       |
| Task 10: Health Checks       | 1-2h   | Task 4       |
| Task 11: Rotation Testing    | 2-3h   | All above    |
| Task 12: Setup Script        | 2-3h   | All above    |

**Total estimated effort**: 18-28 hours

---

## Future Considerations (Phase 3+)

- **Upstream CA**: Integrate with step-ca or Vault for production CA
- **Federation**: Connect multiple trust domains
- **OIDC Federation**: Issue JWT-SVIDs for external systems
- **Audit Logging**: Log all SVID issuance and usage
- **Metrics**: Prometheus metrics for SVID health

---

## References

- [SPIFFE Concepts](https://spiffe.io/docs/latest/spiffe-about/overview/)
- [SPIRE Quick Start](https://spiffe.io/docs/latest/try/getting-started-k8s/)
- [go-spiffe Documentation](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2)
- [SPIRE Helm Charts](https://github.com/spiffe/helm-charts-hardened)
- [SPIRE on Kind](https://spiffe.io/docs/latest/try/getting-started-k8s/)
