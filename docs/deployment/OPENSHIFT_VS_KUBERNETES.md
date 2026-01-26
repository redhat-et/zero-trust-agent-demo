# OpenShift vs Vanilla Kubernetes: Key Differences

This document captures important differences between OpenShift and vanilla Kubernetes, based on lessons learned deploying SPIFFE/SPIRE on OpenShift.

## Security Model

### Security Context Constraints (SCC) vs Pod Security Standards

**Vanilla Kubernetes** uses Pod Security Standards (PSS) with three levels:
- `privileged` - Unrestricted
- `baseline` - Minimally restrictive
- `restricted` - Heavily restricted (default)

**OpenShift** uses Security Context Constraints (SCC), a more granular RBAC-based system:

```bash
# List available SCCs
oc get scc

# Common SCCs (most to least restrictive):
# - restricted-v2 (default) - No root, no host access, no privileged
# - nonroot-v2 - Can run as non-root UID
# - anyuid - Can run as any UID including root
# - hostnetwork - Can use host networking
# - privileged - Full access (hostNetwork, hostPID, hostPath, privileged containers)
```

**Key difference**: In vanilla K8s, you label namespaces. In OpenShift, you grant SCCs to service accounts:

```bash
# Vanilla K8s - label the namespace
kubectl label namespace myns pod-security.kubernetes.io/enforce=privileged

# OpenShift - grant SCC to service account
oc adm policy add-scc-to-user privileged -z myserviceaccount -n mynamespace
```

### Timing Issues with SCCs

OpenShift validates SCC permissions when pods are created, not when deployments are created. This creates a chicken-and-egg problem:

1. Helm creates Deployment → creates ReplicaSet → tries to create Pod
2. Pod creation fails because ServiceAccount doesn't have SCC yet
3. You can't grant SCC to a ServiceAccount that doesn't exist

**Solution**: Pre-create ServiceAccounts with Helm labels before `helm install`:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-service-account
  namespace: my-namespace
  labels:
    app.kubernetes.io/managed-by: Helm
  annotations:
    meta.helm.sh/release-name: my-release
    meta.helm.sh/release-namespace: my-namespace
```

Then grant SCC before Helm install:
```bash
oc adm policy add-scc-to-user privileged -z my-service-account -n my-namespace
helm install my-release my-chart/
```

## SELinux Enforcement

**Vanilla Kubernetes**: SELinux is often disabled or permissive, especially on managed clusters and local development (kind, minikube).

**OpenShift**: SELinux is always enforcing on RHCOS (Red Hat CoreOS) nodes.

### SELinux Context Types

Containers run with SELinux labels. Common types:
- `container_t` - Standard container type
- `container_file_t` - Files accessible by containers
- `container_var_run_t` - Runtime files (sockets, PIDs)
- `spc_t` - Super Privileged Container (can access anything)

### CSI Driver Socket Access Issues

CSI drivers mount sockets with `container_var_run_t` context, but workload containers run with `container_t` context. This causes "Permission denied" errors even when file permissions look correct.

**Solutions**:

1. **Use `spc_t` context** (what we used):
```yaml
securityContext:
  seLinuxOptions:
    type: spc_t
```

2. **Relabel with init container** (requires write access):
```yaml
initContainers:
  - name: selinux-relabel
    image: ubi9/ubi
    command: ["chcon", "-Rt", "container_file_t", "/path/to/socket"]
    securityContext:
      privileged: true
```

### Debugging SELinux Denials

```bash
# Check for SELinux denials on a node
oc debug node/<node-name> -- chroot /host ausearch -m AVC -ts recent

# Check container's SELinux context
oc exec <pod> -- cat /proc/1/attr/current

# Check file SELinux context (needs coreutils, not busybox)
ls -laZ /path/to/file
```

## Kubelet Access

**Vanilla Kubernetes**: Kubelet API often accessible on `127.0.0.1:10250` or `localhost`.

**OpenShift**: Kubelet binds to the node's IP, not localhost. Components that query the kubelet (like SPIRE agent's k8s workload attestor) must:

1. Get the node name from the downward API
2. Connect to the kubelet using the node name/IP

```yaml
env:
  - name: MY_NODE_NAME
    valueFrom:
      fieldRef:
        fieldPath: spec.nodeName
```

SPIRE Helm chart has `global.openshift=true` which configures this automatically.

## CLI Differences

| Task | kubectl | oc |
|------|---------|-----|
| Login | `kubectl config use-context` | `oc login <url>` |
| Projects/Namespaces | `kubectl create namespace` | `oc new-project` |
| Grant SCC | N/A | `oc adm policy add-scc-to-user` |
| Debug node | N/A | `oc debug node/<name>` |
| Build images | N/A | `oc new-build`, `oc start-build` |
| Routes | Ingress | `oc expose svc`, Routes |

Note: `oc` is a superset of `kubectl`. All `kubectl` commands work with `oc`.

## Image Registry

**Vanilla Kubernetes**: Pull from any registry (Docker Hub, gcr.io, etc.)

**OpenShift**:
- Has built-in image registry at `image-registry.openshift-image-registry.svc:5000`
- Red Hat images from `registry.redhat.io` (requires auth) or `registry.access.redhat.com` (public)
- Prefer UBI (Universal Base Image) for OpenShift: `registry.access.redhat.com/ubi9/ubi`

## Networking

### Routes vs Ingress

**Vanilla Kubernetes**: Uses Ingress resources with an ingress controller.

**OpenShift**: Uses Routes (predates Ingress). Routes offer:
- Automatic TLS with edge termination
- Built-in HAProxy router
- Simpler configuration

```bash
# Expose a service as a route
oc expose svc/my-service

# Create HTTPS route with edge termination
oc create route edge --service=my-service
```

OpenShift 4.x also supports Ingress, which gets converted to Routes automatically.

### Network Policies

Both support NetworkPolicy, but OpenShift's default SDN (OVN-Kubernetes) has additional features:
- EgressIP
- EgressFirewall
- Multicast support

## RBAC Differences

OpenShift adds additional default roles:
- `admin` - Full access within a project
- `edit` - Create/modify most resources
- `view` - Read-only access
- `cluster-admin` - Full cluster access

```bash
# Grant project admin to user
oc adm policy add-role-to-user admin <user> -n <namespace>

# Grant cluster-admin (careful!)
oc adm policy add-cluster-role-to-user cluster-admin <user>
```

## Operators and OperatorHub

OpenShift has a built-in Operator Lifecycle Manager (OLM) and OperatorHub:

```bash
# List installed operators
oc get csv -A

# List available operators
oc get packagemanifests

# Install an operator (usually done via web console or subscription YAML)
```

## Web Console

OpenShift includes a feature-rich web console at `https://console-openshift-console.apps.<cluster-domain>/`. Use it for:
- Viewing logs and events
- Managing operators
- Monitoring and alerting
- Creating resources with forms

## Helm on OpenShift

Helm works on OpenShift but watch for:

1. **Install hooks**: May timeout if pods can't start due to SCC. Disable with:
   ```bash
   helm install --set global.installAndUpgradeHooks.enabled=false
   ```

2. **Resource adoption**: Pre-created resources need Helm labels to be adopted.

3. **Security contexts**: Many Helm charts assume they can run as root or specific UIDs. Check if the chart has OpenShift-specific values.

## Quick Reference: Common Issues

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| Pod stuck in `Pending` | No nodes match requirements | Check node selectors, taints |
| Pod stuck in `ContainerCreating` | SCC violation, CSI issues | Check events, grant SCC |
| "Permission denied" on socket/file | SELinux | Use `spc_t` or relabel |
| "connection refused" to kubelet | Wrong kubelet address | Use node IP via downward API |
| Helm install timeout | Install hooks failing | Disable hooks, pre-create SAs |
| Image pull error | Registry auth required | Create pull secret, link to SA |

## Useful Commands

```bash
# Check why pod can't be scheduled
oc describe pod <pod-name>

# Check which SCC a pod is using
oc get pod <pod-name> -o yaml | grep scc

# Check SCC permissions for a service account
oc adm policy who-can use scc privileged

# Debug a node directly
oc debug node/<node-name>

# Get events sorted by time
oc get events --sort-by='.lastTimestamp'

# Check operator status
oc get clusteroperators

# View cluster version and update status
oc get clusterversion
```

## Further Reading

- [OpenShift Security Guide](https://docs.openshift.com/container-platform/latest/security/index.html)
- [Managing SCCs](https://docs.openshift.com/container-platform/latest/authentication/managing-security-context-constraints.html)
- [OpenShift vs Kubernetes](https://www.redhat.com/en/topics/containers/what-is-the-difference-between-kubernetes-and-openshift)
- [SPIFFE/SPIRE on OpenShift](https://github.com/spiffe/spiffe-csi/issues/54)
