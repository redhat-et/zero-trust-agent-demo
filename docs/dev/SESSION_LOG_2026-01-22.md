# Session Log: January 22, 2026

## Phase 2: Real SPIFFE/SPIRE Integration

### Objective
Update the demo services from mock SPIFFE mode to real SPIFFE/SPIRE with mTLS authentication between all services.

---

## Achievements

### 1. Updated All Five Services for Real SPIFFE

Each service (`web-dashboard`, `user-service`, `agent-service`, `document-service`, `opa-service`) was modified to:

- Import the `pkg/spiffe` package
- Initialize `WorkloadClient` on startup
- Fetch X509-SVID from SPIRE Agent
- Use mTLS for HTTP client calls (`CreateMTLSClient()`)
- Use mTLS for serving (`CreateHTTPServer()` + `ListenAndServeTLS()`)
- Properly close the workload client on shutdown

### 2. Updated Kubernetes Deployments

- Changed image registry from `ghcr.io` to `localhost/spiffe-demo/` for faster local iteration
- Changed `imagePullPolicy` to `Never` for Kind cluster
- Updated environment variables to match config structure
- Changed health probes from HTTP to TCP socket (mTLS servers can't respond to plain HTTP probes)

### 3. Verified End-to-End mTLS Chain

Successfully tested:
- Direct access: `Alice → DOC-001` (granted via engineering department)
- Delegated access: `Alice → GPT-4 → DOC-001` (granted via permission intersection)

---

## Debugging Journey

### Bug #1: Config Field Name Mismatch

**Symptom:**
```
cfg.SPIFFE.MockMode undefined (type config.SPIFFEConfig has no field or method MockMode)
```

**Investigation:**
Read the `pkg/config/config.go` file to check the actual struct definition.

**Root Cause:**
The mock mode setting was in `ServiceConfig.MockSPIFFE`, not `SPIFFEConfig.MockMode`.

**Fix:**
```go
// Wrong:
cfg.SPIFFE.MockMode

// Correct:
cfg.Service.MockSPIFFE
```

**Lesson:** Always verify struct definitions before assuming field names. Go's compile-time errors are helpful here.

---

### Bug #2: SPIFFE Socket Path Missing URI Scheme

**Symptom:**
```
Error: failed to fetch SPIFFE identity: failed to create X509Source:
workload endpoint socket URI must have a "tcp" or "unix" scheme
```

**Investigation:**
1. Checked the pod logs to see what socket path was being used
2. Noticed it was using `/run/spire/sockets/agent.sock` (no scheme)
3. Checked the deployment YAML - it had `SPIFFE_ENDPOINT_SOCKET` env var
4. Checked the config code - it expected `SPIFFE_DEMO_SPIFFE_SOCKET_PATH`

**Root Cause:**
Environment variable name mismatch. The deployment used `SPIFFE_ENDPOINT_SOCKET` but the Viper config expected `SPIFFE_DEMO_SPIFFE_SOCKET_PATH` (following the prefix + key pattern).

**Fix:**
Changed the env var name in deployments:
```yaml
# Wrong:
- name: SPIFFE_ENDPOINT_SOCKET
  value: "unix:///run/spire/agent-sockets/spire-agent.sock"

# Correct:
- name: SPIFFE_DEMO_SPIFFE_SOCKET_PATH
  value: "unix:///run/spire/agent-sockets/spire-agent.sock"
```

**Lesson:** Viper environment variable binding follows a specific pattern: `PREFIX_SECTION_KEY`. Always trace the config loading path.

---

### Bug #3: Health Probes Failing on mTLS Servers

**Symptom:**
Pods kept restarting. Logs showed:
```
http: TLS handshake error from 10.244.1.1:33972: client sent an HTTP request to an HTTPS server
```

**Investigation:**
1. The services were running successfully (acquired SVIDs)
2. But they were restarting due to failed health checks
3. Health probes were using `httpGet` but the servers now required mTLS

**Root Cause:**
Kubernetes HTTP health probes cannot perform mTLS handshakes. When the servers switched to HTTPS/mTLS, the plain HTTP probes failed.

**Fix:**
Changed probes from `httpGet` to `tcpSocket`:
```yaml
# Wrong (for mTLS servers):
livenessProbe:
  httpGet:
    path: /health
    port: 8085

# Correct:
livenessProbe:
  tcpSocket:
    port: 8085
```

**Note:** The `tcpSocket` probe only checks if the port is listening, not if the service is healthy. For production, consider:
- Running a separate HTTP health endpoint on a different port
- Using exec probes with `curl --cacert` for TLS verification
- Kubernetes 1.24+ supports HTTPS probes with `scheme: HTTPS`

**Lesson:** When adding TLS to services, remember that infrastructure components (load balancers, health checks, monitoring) may also need updates.

---

### Bug #4: Wrong SPIFFE ID Used for Authorization

**Symptom:**
Authorization always denied with "Insufficient permissions":
```
Evaluating policy request caller=spiffe://demo.example.com/ns/spiffe-demo/sa/default document=DOC-001
```

**Investigation:**
1. The caller SPIFFE ID was the service account's ID, not Alice's user ID
2. Traced the code path: `document-service` was extracting SPIFFE ID from mTLS certificate
3. But the user's ID was being passed in the `X-SPIFFE-ID` header

**Root Cause:**
In the demo's architecture, there are two different identities:
1. **Service identity** (from mTLS certificate): Which service is calling
2. **Subject identity** (from X-SPIFFE-ID header): Which user the request is about

The code was using the mTLS certificate's identity for authorization decisions, but the OPA policies expect the user's identity.

**Conceptual Insight:**
```
┌─────────────────────────────────────────────────────────────────┐
│  Request Flow                                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  User Service ──[mTLS]──> Document Service ──[mTLS]──> OPA      │
│                                                                  │
│  mTLS Certificate: spiffe://demo.example.com/ns/spiffe-demo/... │
│  X-SPIFFE-ID Header: spiffe://demo.example.com/user/alice       │
│                                                                  │
│  The mTLS authenticates the SERVICE                             │
│  The header carries the USER identity for authorization         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Fix:**
```go
// Wrong: Always use mTLS identity
callerSPIFFEID := spiffe.GetSPIFFEIDFromRequest(r)

// Correct: Prefer header for user identity, fall back to mTLS
callerSPIFFEID := r.Header.Get("X-SPIFFE-ID")
if callerSPIFFEID == "" {
    callerSPIFFEID = spiffe.GetSPIFFEIDFromRequest(r)
}
```

**Lesson:** In service mesh architectures, there's often a distinction between:
- **Transport authentication** (who is calling me?)
- **Request authorization** (who is this request about?)

The mTLS handles transport authentication, but application-level headers often carry authorization context.

---

## Key Debugging Techniques Used

### 1. Read the Logs First
Every debugging session started with `kubectl logs`. The error messages were informative:
- "workload endpoint socket URI must have a 'tcp' or 'unix' scheme"
- "client sent an HTTP request to an HTTPS server"

### 2. Trace the Configuration Path
When env vars weren't working, we traced:
```
Environment Variable → Viper Binding → Struct Field → Code Usage
```

### 3. Verify the Deployment Actually Changed
After fixing YAML, always verify the new pods are using the new config:
```bash
kubectl get pods -n spiffe-demo  # Check for new pod names/ages
kubectl logs <new-pod>           # Verify new behavior
```

### 4. Test Incrementally
Instead of testing the full flow immediately:
1. First verified web-dashboard health endpoint works
2. Then tested `/api/users` (web-dashboard → user-service)
3. Then tested full authorization flow

### 5. Understand the Architecture
The Bug #4 fix required understanding that mTLS identity ≠ user identity. Drawing the flow helped:
```
Browser → Dashboard → User-Service → Document-Service → OPA
                      (looks up        (needs user ID
                       Alice's ID)      for authz)
```

---

## Files Modified

### Service Code (5 files)
- `web-dashboard/cmd/serve.go`
- `user-service/cmd/serve.go`
- `agent-service/cmd/serve.go`
- `document-service/cmd/serve.go`
- `opa-service/cmd/serve.go`

### Deployment Configuration
- `deploy/k8s/deployments-spire.yaml`

### Key Changes Pattern (applied to each service)
```go
// 1. Add import
import "github.com/hardwaylabs/spiffe-spire-demo/pkg/spiffe"

// 2. Initialize workload client
spiffeCfg := spiffe.Config{
    SocketPath:  cfg.SPIFFE.SocketPath,
    TrustDomain: cfg.SPIFFE.TrustDomain,
    MockMode:    cfg.Service.MockSPIFFE,
}
workloadClient := spiffe.NewWorkloadClient(spiffeCfg, log)

// 3. Fetch identity (if not mock mode)
if !cfg.Service.MockSPIFFE {
    identity, err := workloadClient.FetchIdentity(ctx)
    // handle error, log identity
}

// 4. Create mTLS HTTP client
httpClient := workloadClient.CreateMTLSClient(10 * time.Second)

// 5. Create mTLS server
server := workloadClient.CreateHTTPServer(addr, handler)

// 6. Start with TLS if not mock
if !mockMode && server.TLSConfig != nil {
    server.ListenAndServeTLS("", "")
} else {
    server.ListenAndServe()
}

// 7. Close on shutdown
workloadClient.Close()
```

---

## Final State

All services running with real SPIFFE/SPIRE:
```
$ kubectl get pods -n spiffe-demo
NAME                                READY   STATUS    RESTARTS   AGE
agent-service-645fd6d47f-7vh5j      1/1     Running   0          5m
document-service-6fb99b67c-7bgkr    1/1     Running   0          2m
opa-service-6d4d766646-qn4k8        1/1     Running   0          5m
user-service-7877dd4768-pmj9z       1/1     Running   0          5m
web-dashboard-796c6bd79d-nv29x      1/1     Running   0          7m
```

Each service logs its SPIFFE identity:
```
📜 [SVID] Acquired X509-SVID from SPIRE Agent
         spiffe_id=spiffe://demo.example.com/ns/spiffe-demo/sa/default
```

---

## Next Steps (for tomorrow)

1. **Commit the changes** to the `phase-2-spire-integration` branch
2. **Test more scenarios**:
   - Access denial cases (wrong department)
   - Agent without user delegation (should be denied)
3. **Consider improvements**:
   - Separate health endpoint for HTTP probes
   - Per-service SPIFFE IDs via separate service accounts
   - Certificate rotation testing
4. **Update documentation** with Phase 2 instructions
5. **Push to remote** and rebuild CI images with SPIFFE support
