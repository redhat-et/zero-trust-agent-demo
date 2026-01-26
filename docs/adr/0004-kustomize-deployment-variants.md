# ADR-0004: Use Kustomize for Deployment Variants

## Status

Accepted

## Date

2026-01-21

## Context

This demo needs to run in multiple environments with different configurations:

| Environment | SPIFFE Mode | Container Images | Ingress |
|-------------|-------------|------------------|---------|
| Local dev | Mock (in-process) | Local binaries | N/A |
| Kind cluster | Mock or SPIRE | Local registry | NodePort |
| Kubernetes | Real SPIRE | ghcr.io | Ingress |
| OpenShift | Real SPIRE | ghcr.io | Route |

We need a deployment strategy that:
1. Minimizes duplication across environments
2. Allows environment-specific customizations
3. Is native to Kubernetes ecosystem
4. Doesn't require additional tooling in CI/CD

## Decision

We will use **Kustomize** with a base + overlays structure:

```
deploy/k8s/
├── base/                           # Shared manifests
│   ├── kustomization.yaml
│   ├── namespace.yaml
│   ├── configmap.yaml
│   ├── user-service.yaml
│   ├── agent-service.yaml
│   ├── document-service.yaml
│   ├── opa-service.yaml
│   └── web-dashboard.yaml
└── overlays/
    ├── mock/                       # Mock SPIFFE mode
    │   ├── kustomization.yaml
    │   └── patches/
    │       └── mock-mode.yaml
    ├── spire/                      # Real SPIRE integration
    │   ├── kustomization.yaml
    │   ├── spire-server.yaml
    │   ├── spire-agent.yaml
    │   └── patches/
    │       └── spire-volumes.yaml
    └── openshift/                  # OpenShift-specific
        ├── kustomization.yaml
        ├── routes.yaml
        └── patches/
            └── security-context.yaml
```

Usage:
```bash
# Deploy with mock SPIFFE
kubectl apply -k deploy/k8s/overlays/mock

# Deploy with real SPIRE
kubectl apply -k deploy/k8s/overlays/spire

# Deploy to OpenShift
kubectl apply -k deploy/k8s/overlays/openshift
```

Key techniques used:
- **Patches**: Strategic merge patches for environment differences
- **ConfigMapGenerator**: Environment-specific configuration
- **Images**: Override image tags per environment
- **Namespace**: Set namespace across all resources

## Consequences

### Positive

- **DRY principle**: Base manifests shared across all environments
- **Native tooling**: Built into kubectl, no additional installation
- **GitOps ready**: Declarative, deterministic output
- **Easy debugging**: `kubectl kustomize` shows rendered manifests
- **Composable**: Overlays can extend other overlays

### Negative

- **Learning curve**: Kustomize concepts (patches, transformers) take time to learn
- **Debugging patches**: Strategic merge behavior can be surprising
- **Limited templating**: No conditionals or loops (unlike Helm)
- **Verbose patches**: Simple changes may require full resource patches

### Neutral

- Output is plain YAML (can be committed if needed)
- No variable substitution (use ConfigMaps/Secrets instead)

## Alternatives Considered

### 1. Helm Charts
```yaml
# values-openshift.yaml
ingress:
  enabled: false
route:
  enabled: true
spiffe:
  mode: spire
```
- **Pros**: Powerful templating, conditionals, package management
- **Cons**: Additional tooling, template syntax obscures manifest structure, harder to debug

### 2. Plain YAML with envsubst
```bash
envsubst < deployment.yaml.template > deployment.yaml
```
- **Pros**: Simple, no special tooling
- **Cons**: No merge capability, massive duplication, error-prone

### 3. Jsonnet
- **Pros**: Full programming language, composable
- **Cons**: Steep learning curve, not Kubernetes-native, requires compilation

### 4. Multiple Directories (No Overlay)
```
deploy/
├── k8s-mock/
├── k8s-spire/
└── openshift/
```
- **Pros**: Obvious what each environment uses
- **Cons**: Massive duplication, changes require updates in multiple places

## Example: Overlay Configuration

### Base Deployment (simplified)
```yaml
# deploy/k8s/base/user-service.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-service
spec:
  template:
    spec:
      containers:
        - name: user-service
          image: user-service:latest
          env:
            - name: SPIFFE_MODE
              value: "spire"
```

### Mock Overlay Patch
```yaml
# deploy/k8s/overlays/mock/patches/mock-mode.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-service
spec:
  template:
    spec:
      containers:
        - name: user-service
          env:
            - name: SPIFFE_MODE
              value: "mock"
```

### OpenShift Overlay Patch
```yaml
# deploy/k8s/overlays/openshift/patches/security-context.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-service
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
        - name: user-service
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
```

## References

- [Kustomize Documentation](https://kustomize.io/)
- [Kubernetes SIG CLI - Kustomize](https://github.com/kubernetes-sigs/kustomize)
- [Declarative Management of Kubernetes Objects Using Kustomize](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/kustomization/)
