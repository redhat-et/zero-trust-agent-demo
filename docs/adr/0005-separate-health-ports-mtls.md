# ADR-0005: Separate Health Ports for mTLS Services

## Status

Accepted

## Date

2026-01-22

## Context

When services use mutual TLS (mTLS) for all communication, Kubernetes health probes face a challenge:

1. **Liveness/Readiness probes** are executed by the kubelet
2. **kubelet doesn't have SPIFFE SVIDs** to authenticate to our services
3. Probes to mTLS ports fail with TLS handshake errors

Options considered:
- Disable mTLS for health endpoints (security risk)
- Use exec probes (resource overhead)
- Configure kubelet with certificates (complex, not portable)
- Expose health on a separate non-mTLS port

## Decision

We will expose **health and metrics endpoints on separate non-mTLS ports** alongside the main mTLS service ports.

Port allocation:
| Service | mTLS Port | Health/Metrics Port |
|---------|-----------|---------------------|
| user-service | 8082 | 8182 |
| agent-service | 8083 | 8183 |
| document-service | 8084 | 8184 |
| opa-service | 8085 | 8185 |
| web-dashboard | 8080 | 8080 (no mTLS) |

Implementation:
```go
func (s *Server) Start(ctx context.Context) error {
    // Main mTLS server
    mux := http.NewServeMux()
    mux.HandleFunc("/users", s.handleUsers)
    // ... other handlers

    tlsConfig := s.spiffeClient.GetServerTLSConfig()
    mainServer := &http.Server{
        Addr:      ":8082",
        Handler:   mux,
        TLSConfig: tlsConfig,
    }

    // Health server (no TLS)
    healthMux := http.NewServeMux()
    healthMux.HandleFunc("/health", s.handleHealth)
    healthMux.Handle("/metrics", promhttp.Handler())

    healthServer := &http.Server{
        Addr:    ":8182",
        Handler: healthMux,
    }

    // Start both
    go mainServer.ListenAndServeTLS("", "")
    go healthServer.ListenAndServe()

    // ...
}
```

Kubernetes deployment:
```yaml
spec:
  containers:
    - name: user-service
      ports:
        - name: https
          containerPort: 8082
        - name: health
          containerPort: 8182
      livenessProbe:
        httpGet:
          path: /health
          port: health
      readinessProbe:
        httpGet:
          path: /health
          port: health
```

## Consequences

### Positive

- **Standard probes work**: No special kubelet configuration needed
- **Prometheus scraping**: Metrics endpoint accessible without mTLS setup
- **Debugging**: Can curl health endpoints from host network
- **Clear separation**: API endpoints protected, operational endpoints accessible

### Negative

- **Two ports per service**: Increases port management complexity
- **Health endpoint unprotected**: Anyone in cluster network can access
- **Potential info leak**: Health response might reveal service state

### Neutral

- Health port only exposes health/metrics, no business data
- Network policies can restrict access to health port if needed

## Security Analysis

### What's Exposed on Health Port

| Endpoint | Data | Risk |
|----------|------|------|
| `/health` | Service status, SVID expiration | Low - operational info |
| `/metrics` | Request counts, latencies | Low - no PII |

### Mitigations

1. **Network Policies**: Restrict health port access to Prometheus/kubelet IPs
2. **Minimal Response**: Health endpoint returns only status, no internal details
3. **No PII**: Metrics are aggregated, no user/agent identifiers

### Alternative: mTLS Health with Sidecar

For stricter environments, a sidecar proxy could handle mTLS termination:

```yaml
spec:
  containers:
    - name: service
      ports:
        - containerPort: 8082  # mTLS
    - name: health-proxy
      image: envoy:latest
      ports:
        - containerPort: 8182  # Proxies to 8082 with mTLS
```

We chose not to implement this due to complexity, but it's viable for production.

## Alternatives Considered

### 1. Exec Probes
```yaml
livenessProbe:
  exec:
    command:
      - /bin/sh
      - -c
      - "curl -k https://localhost:8082/health"
```
- **Pros**: No additional port, tests actual mTLS endpoint
- **Cons**: Requires curl in image, exec overhead, `-k` bypasses cert validation anyway

### 2. TCP Probes
```yaml
livenessProbe:
  tcpSocket:
    port: 8082
```
- **Pros**: Simple, no TLS negotiation needed
- **Cons**: Only confirms port is open, not that service is healthy

### 3. gRPC Health with mTLS
```yaml
livenessProbe:
  grpc:
    port: 8082
```
- **Pros**: Kubernetes 1.24+ supports gRPC probes
- **Cons**: Still requires TLS setup for kubelet, we use HTTP not gRPC

### 4. SPIFFE Helper Sidecar
Use spiffe-helper to write certificates to shared volume, configure kubelet to use them.
- **Pros**: Full mTLS including probes
- **Cons**: Complex setup, kubelet configuration not portable

## Port Numbering Convention

We chose health ports by adding 100 to the main port:
- 8082 → 8182
- 8083 → 8183
- etc.

This makes the mapping predictable and easy to remember.

## References

- [Kubernetes Probe Configuration](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/)
- [SPIFFE Workload API](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/#workload-api)
- [Prometheus Scraping with mTLS](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#tls_config)
