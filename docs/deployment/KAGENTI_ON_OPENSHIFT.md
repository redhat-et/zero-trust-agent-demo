# Deploying agents with Kagenti on OpenShift

Practical guide for deploying agents via Kagenti on an OpenShift cluster.
Covers workarounds for OpenShift-specific issues that the Kagenti team
is working on resolving upstream.

**Cluster**: OpenShift (tested on OCP 4.x with NERC)
**Kagenti version**: As of 2026-03-18
**Last updated**: 2026-03-18

## Prerequisites

Before deploying agents, verify these components are operational:

```bash
# Shipwright operator and Tekton must both be ready
oc get shipwrightbuilds -A
# Should show a "cluster-*" resource

oc get shipwrightbuilds -A -o jsonpath='{.items[0].status.conditions[0]}'
# Should show: "status":"True","type":"Ready"
# If it shows "TektonConfigMissing", Tekton needs to be installed first

# ClusterBuildStrategies available
oc get clusterbuildstrategies
# Should include: buildah, buildah-insecure-push

# SPIRE running
oc get pods -n zero-trust-workload-identity-manager | grep spire
```

## Namespace setup

Each namespace where you deploy agents needs several one-time
configurations.

### Create the namespace

```bash
NAMESPACE=zt-test
oc create namespace $NAMESPACE 2>/dev/null || true
```

### Namespace labels

Two labels are required:

- `kagenti-enabled=true` — enables the Kagenti operator's webhook
  to inject sidecars (AuthBridge, SPIRE) into pods in this namespace
- `agentcard=true` — enables the ClusterSPIFFEID controller to
  issue SPIFFE identities to agent pods in this namespace

```bash
oc label namespace $NAMESPACE kagenti-enabled=true agentcard=true \
  --overwrite
```

### AuthBridge SCC

AuthBridge sidecars require privileged init containers (iptables),
specific UIDs (1337 for Envoy, 1000 for go-processor), and CSI
volumes (SPIFFE). OpenShift's default `restricted-v2` SCC blocks
all of these. You need a custom SCC that allows them.

#### Create the SCC (cluster-wide, one-time)

If the `kagenti-authbridge` SCC doesn't exist on your cluster,
create it:

```bash
oc apply -f - <<'EOF'
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  name: kagenti-authbridge
  annotations:
    kubernetes.io/description: >-
      Custom SCC for Kagenti agents with AuthBridge sidecars.
      Allows privileged init container (iptables), RunAsAny UID
      (Envoy 1337, go-processor 1000, agent 1000), and SPIFFE
      CSI volumes.
allowHostDirVolumePlugin: false
allowHostIPC: false
allowHostNetwork: false
allowHostPID: false
allowHostPorts: false
allowPrivilegeEscalation: true
allowPrivilegedContainer: true
allowedCapabilities:
  - NET_ADMIN
  - NET_RAW
defaultAddCapabilities: []
requiredDropCapabilities: []
fsGroup:
  type: MustRunAs
runAsUser:
  type: RunAsAny
seLinuxContext:
  type: RunAsAny
supplementalGroups:
  type: RunAsAny
readOnlyRootFilesystem: false
volumes:
  - configMap
  - csi
  - downwardAPI
  - emptyDir
  - persistentVolumeClaim
  - projected
  - secret
EOF
```

Key fields explained:

- `allowPrivilegedContainer: true` — the proxy-init container runs
  privileged to set up iptables rules
- `NET_ADMIN, NET_RAW` — required by iptables for traffic capture
- `runAsUser: RunAsAny` — allows UID 0 (init), 1337 (Envoy), 1000
  (go-processor, agent)
- `csi` in volumes — required for SPIFFE CSI driver to mount the
  workload API socket

#### Grant the SCC to agent service accounts

The SCC must be granted **after** the agent is created, because the
SA doesn't exist beforehand. The SA name varies depending on how the
agent was created (UI vs API, SPIRE enabled or not). Always check
the actual SA name from the deployment:

```bash
# Check which SA the deployment uses:
oc get deployment <agent-name> -n $NAMESPACE \
  -o jsonpath='{.spec.template.spec.serviceAccountName}'

# Grant the SCC to that SA:
SA_NAME=$(oc get deployment <agent-name> -n $NAMESPACE \
  -o jsonpath='{.spec.template.spec.serviceAccountName}')
oc adm policy add-scc-to-user kagenti-authbridge \
  -z $SA_NAME -n $NAMESPACE

# Restart the deployment to pick up the SCC:
oc rollout restart deployment/<agent-name> -n $NAMESPACE
```

### AuthBridge config

The AuthBridge envoy-proxy sidecar reads Keycloak configuration
from a ConfigMap named `authbridge-config`. Create it with the
correct Keycloak URLs for your cluster:

```bash
KEYCLOAK_URL="https://keycloak-spiffe-demo.apps.ocp-beta-test.nerc.mghpcc.org"
REALM="spiffe-demo"

oc create configmap authbridge-config -n $NAMESPACE \
  --from-literal=ISSUER="${KEYCLOAK_URL}/realms/${REALM}" \
  --from-literal=TOKEN_URL="${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  --from-literal=EXPECTED_AUDIENCE="" \
  --from-literal=TARGET_AUDIENCE="" \
  --from-literal=TARGET_SCOPES="openid"
```

### Registry push secret (for build-from-source)

Shipwright builds need credentials to push to the OpenShift internal
registry. Create a secret from the `builder` SA token:

```bash
oc create secret docker-registry openshift-registry-push \
  --docker-server=image-registry.openshift-image-registry.svc:5000 \
  --docker-username=serviceaccount \
  --docker-password=$(oc create token builder -n $NAMESPACE) \
  -n $NAMESPACE
```

**Note**: The token has a default TTL of 1 hour. For long-lived
access, use a bound SA token with longer duration or create a
persistent dockercfg secret from the builder SA.

## Why CLI deployment?

The Kagenti UI is the preferred way to deploy agents. However, on
OpenShift the UI's "build from source" flow only offers four registry
options (Local/cr-system, Quay, Docker Hub, GHCR) and does not
include the OpenShift internal registry. Since the Kagenti internal
registry (`cr-system`) is not deployed on OpenShift (OpenShift has
its own), and external registries require additional secret setup,
the CLI/API path below lets you use the OpenShift internal registry
directly.

**Trade-off**: Agents created via the API may not get agent card
signing (see known issues below). They will be discovered and
functional but may show `Verified: false` in the Kagenti UI. This
needs further investigation — it may be an API limitation or a
timing issue with ConfigMap creation.

## Deploy an agent from source (CLI)

Use the Kagenti API directly to specify the OpenShift internal
registry URL.

### Step-by-step

The build-from-source flow has two phases:

1. **Create**: Submit the build (creates Shipwright Build + BuildRun)
2. **Finalize**: After build completes, create the Deployment + Service

#### Phase one: Create the agent build

```bash
KAGENTI_API="https://kagenti-api-kagenti-system.apps.ocp-beta-test.nerc.mghpcc.org"
NAMESPACE="zt-test"
AGENT_NAME="kagenti-reviewer"

curl -s -X POST "${KAGENTI_API}/api/v1/agents" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"${AGENT_NAME}\",
    \"namespace\": \"${NAMESPACE}\",
    \"protocol\": \"a2a\",
    \"framework\": \"Python\",
    \"deploymentMethod\": \"source\",
    \"gitUrl\": \"https://github.com/redhat-et/zero-trust-agent-demo\",
    \"gitBranch\": \"feature/kagenti-s3-summarizer\",
    \"gitPath\": \"kagenti-reviewer\",
    \"imageTag\": \"dev\",
    \"registryUrl\": \"image-registry.openshift-image-registry.svc:5000/${NAMESPACE}\",
    \"registrySecret\": \"openshift-registry-push\",
    \"authBridgeEnabled\": true,
    \"spireEnabled\": true,
    \"servicePorts\": [{
      \"name\": \"http\",
      \"port\": 8080,
      \"targetPort\": 8000,
      \"protocol\": \"TCP\"
    }]
  }" | python3 -m json.tool
```

#### Monitor the build

```bash
# Watch build status
oc get buildruns -n $NAMESPACE -l kagenti.io/build-name=$AGENT_NAME -w

# Or check via API
curl -s "${KAGENTI_API}/api/v1/agents/${NAMESPACE}/${AGENT_NAME}/build-status" \
  | python3 -m json.tool
```

Wait until the BuildRun shows `Succeeded: True`.

#### Phase two: Grant SCC and finalize

After the build succeeds:

```bash
# Grant SCC to the SA used by the deployment
SA_NAME=$(oc get deployment ${AGENT_NAME} -n $NAMESPACE \
  -o jsonpath='{.spec.template.spec.serviceAccountName}')
echo "Granting SCC to SA: $SA_NAME"
oc adm policy add-scc-to-user kagenti-authbridge \
  -z $SA_NAME -n $NAMESPACE

# Finalize the build (creates Deployment + Service)
curl -s -X POST \
  "${KAGENTI_API}/api/v1/agents/${NAMESPACE}/${AGENT_NAME}/finalize-shipwright-build" \
  -H "Content-Type: application/json" \
  -d '{}' | python3 -m json.tool

# Wait for rollout
oc rollout status deployment/${AGENT_NAME} -n $NAMESPACE --timeout=120s
```

#### Verify the agent

```bash
# Check pod status (should be 4/4 Running with AuthBridge)
oc get pods -n $NAMESPACE -l app.kubernetes.io/name=$AGENT_NAME

# Check agent card
oc get agentcards -n $NAMESPACE

# Test health endpoint
oc port-forward -n $NAMESPACE svc/$AGENT_NAME 8000:8080 &
curl -s http://localhost:8000/health
kill %1
```

## Deploy an agent from pre-built image (CLI)

If you've already built and pushed the image (e.g., to GHCR):

```bash
curl -s -X POST "${KAGENTI_API}/api/v1/agents" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"${AGENT_NAME}\",
    \"namespace\": \"${NAMESPACE}\",
    \"protocol\": \"a2a\",
    \"framework\": \"Python\",
    \"deploymentMethod\": \"image\",
    \"containerImage\": \"ghcr.io/redhat-et/zero-trust-agent-demo/kagenti-summarizer:dev\",
    \"authBridgeEnabled\": true,
    \"spireEnabled\": true,
    \"servicePorts\": [{
      \"name\": \"http\",
      \"port\": 8080,
      \"targetPort\": 8000,
      \"protocol\": \"TCP\"
    }]
  }" | python3 -m json.tool

# Then grant SCC and restart (same as above)
```

## Deleting an agent

Kagenti creates several resources per agent. When deleting an agent,
remove all of them to avoid orphaned resources.

### Delete a single agent

```bash
NAMESPACE=zt-test
AGENT_NAME=kagenti-reviewer

# Core workload resources
oc delete deployment $AGENT_NAME -n $NAMESPACE --ignore-not-found
oc delete svc $AGENT_NAME -n $NAMESPACE --ignore-not-found

# AgentCard (named <agent>-deployment-card by convention)
oc delete agentcard ${AGENT_NAME}-deployment-card -n $NAMESPACE \
  --ignore-not-found

# Shipwright build resources (from build-from-source)
oc delete builds.shipwright.io $AGENT_NAME -n $NAMESPACE \
  --ignore-not-found
oc delete buildruns.shipwright.io -n $NAMESPACE \
  -l kagenti.io/build-name=$AGENT_NAME

# Service account (with or without -sa suffix)
oc delete sa ${AGENT_NAME}-sa -n $NAMESPACE --ignore-not-found
oc delete sa $AGENT_NAME -n $NAMESPACE --ignore-not-found

# ConfigMaps (unsigned and signed agent cards)
oc delete cm ${AGENT_NAME}-card-unsigned -n $NAMESPACE \
  --ignore-not-found
oc delete cm ${AGENT_NAME}-card-signed -n $NAMESPACE \
  --ignore-not-found

# ImageStream (if built to OpenShift internal registry)
oc delete is $AGENT_NAME -n $NAMESPACE --ignore-not-found

# SCC binding (cluster-scoped, won't cause issues if left)
oc adm policy remove-scc-from-user kagenti-authbridge \
  -z ${AGENT_NAME}-sa -n $NAMESPACE 2>/dev/null
oc adm policy remove-scc-from-user kagenti-authbridge \
  -z $AGENT_NAME -n $NAMESPACE 2>/dev/null
```

### Clean up all failed builds

After experimenting, you may have multiple failed build attempts.
To clean them all up:

```bash
NAMESPACE=zt-test

# List what exists
echo "=== Builds ===" && oc get builds.shipwright.io -n $NAMESPACE
echo "=== BuildRuns ===" && oc get buildruns.shipwright.io -n $NAMESPACE
echo "=== AgentCards ===" && oc get agentcards -n $NAMESPACE
echo "=== Orphan SAs ===" && oc get sa -n $NAMESPACE | grep kagenti
echo "=== Orphan CMs ===" && oc get cm -n $NAMESPACE | grep kagenti

# Delete all Shipwright builds and buildruns
oc delete builds.shipwright.io --all -n $NAMESPACE
oc delete buildruns.shipwright.io --all -n $NAMESPACE

# Delete unbound/unsynced agent cards (failed deployments)
# Review the list first, then delete selectively:
oc get agentcards -n $NAMESPACE -o name | while read card; do
  synced=$(oc get $card -n $NAMESPACE -o jsonpath='{.status.synced}')
  if [ "$synced" != "True" ]; then
    echo "Deleting unsynced: $card"
    oc delete $card -n $NAMESPACE
  fi
done

# Delete orphaned SAs and ConfigMaps (review before deleting)
# Only delete if the corresponding deployment doesn't exist:
for sa in $(oc get sa -n $NAMESPACE -o name | grep kagenti); do
  name=$(echo $sa | sed 's|serviceaccount/||; s|-sa$||')
  if ! oc get deployment $name -n $NAMESPACE &>/dev/null; then
    echo "Deleting orphan SA: $sa"
    oc delete $sa -n $NAMESPACE
  fi
done

for cm in $(oc get cm -n $NAMESPACE -o name | grep kagenti); do
  echo "Deleting: $cm"
  oc delete $cm -n $NAMESPACE
done
```

### Delete via Kagenti API

If the agent was created via the API, you can also delete it there:

```bash
curl -s -X DELETE \
  "${KAGENTI_API}/api/v1/agents/${NAMESPACE}/${AGENT_NAME}" \
  | python3 -m json.tool
```

This deletes the Deployment and Service but may leave behind
Shipwright builds, ConfigMaps, and service accounts. Use the
manual cleanup steps above for a complete removal.

## Known issues and workarounds

### SCC must be granted after agent creation

**Problem**: The Kagenti operator creates the ServiceAccount as part
of agent creation. The SCC binding must happen after the SA exists
but before the pod can start. The pod fails with SCC errors until the
binding is added.

**Workaround**: Grant the SCC manually after creation (see above).

**Upstream fix**: Kagenti should either pre-create the SA before the
Deployment, or include the SCC binding as part of agent creation on
OpenShift.

### AuthBridge config ConfigMap not auto-created

**Problem**: The envoy-proxy sidecar expects `authbridge-config`
ConfigMap with Keycloak URLs, but Kagenti doesn't create it
automatically in new namespaces.

**Workaround**: Create the ConfigMap manually (see namespace setup).

**Upstream fix**: Kagenti should create `authbridge-config` when
injecting AuthBridge sidecars, or read from a cluster-wide config.

### Bootstrap deadlock with Keycloak

**Problem**: AuthBridge iptables captures all outbound traffic. The
client-registration sidecar can't reach Keycloak to register because
its traffic is intercepted. The go-processor waits 60 seconds and
starts without credentials.

**Impact**: Token exchange doesn't work for the first 60 seconds, and
may never activate if client-registration can't reach Keycloak.

**Workaround**: Wait 60+ seconds for the timeout. The agent functions
but without AuthBridge token exchange.

**Upstream fix**: See `docs/dev/AUTHBRIDGE_OUTBOUND_PROPOSAL.md`
(Change A: exempt IdP from iptables).

### HTTPS outbound traffic blocked by AuthBridge

**Problem**: Agents can't make outbound HTTPS requests because Envoy
intercepts all traffic through the HTTP filter chain, which can't
handle TLS.

**Impact**: Agents that fetch external URLs (S3, GitHub, APIs) fail
silently.

**Workaround**: None currently. Public HTTPS URLs don't work with
AuthBridge enabled.

**Upstream fix**: See `docs/dev/AUTHBRIDGE_OUTBOUND_PROPOSAL.md`
(Change B: TLS-aware outbound listener).

### OpenShift registry not in Kagenti UI

**Problem**: The Kagenti UI registry dropdown only offers Local
(cr-system), Quay, Docker Hub, and GHCR. The OpenShift internal
registry isn't an option.

**Workaround**: Use the API directly with
`registryUrl: "image-registry.openshift-image-registry.svc:5000/<namespace>"`.

**Upstream fix**: Add an "OpenShift Internal Registry" option to
`ImportAgentPage.tsx:REGISTRY_OPTIONS`.

### Agent card signing may not activate via API

**Problem**: Agents created via the Kagenti API may not get their
agent card signed with a SPIRE SVID. The agent shows
`Verified: false` and `Bound: false` in the Kagenti UI. The agent
is fully functional but not cryptographically verified.

**Root cause**: Agent card signing requires a `sign-agentcard` init
container injected by the Kagenti operator's webhook. The webhook
only injects this init container when a `<agent-name>-card-unsigned`
ConfigMap exists **at the time the Deployment is created**. In our
testing, agents created via the UI had this ConfigMap and got
signing; agents created via the API did not.

Creating the ConfigMap manually before or after the Deployment does
not trigger the webhook to inject the signing init container — the
webhook decision appears to be made only at initial pod admission.

**Status**: Needs further testing in a clean namespace to confirm
whether this is an API vs UI issue, a deployment method issue
(source vs image), or a timing issue with ConfigMap creation.

**Workaround**: If your agent shows `Verified: false`, try creating
it via the Kagenti UI instead. Agents without signing are still
discoverable and functional — this is a trust verification gap,
not a functionality issue.

**Upstream fix**: The Kagenti API should create the `card-unsigned`
ConfigMap when `spireEnabled: true`, matching the UI behavior.

### Shipwright requires Tekton

**Problem**: Shipwright depends on Tekton Pipelines. If Tekton is not
installed, the Shipwright operator shows `TektonConfigMissing` and
the Build/BuildRun CRDs are never created. The UI shows a misleading
"Agent CRD not found" error.

**Fix**: Install the OpenShift Pipelines operator (provides Tekton).

## Quick reference: complete namespace setup

One-time setup for a new namespace, including all workarounds:

```bash
NAMESPACE=my-agents
KEYCLOAK_URL="https://keycloak-spiffe-demo.apps.ocp-beta-test.nerc.mghpcc.org"
REALM="spiffe-demo"

# Create namespace with required labels
oc create namespace $NAMESPACE
oc label namespace $NAMESPACE agentcard=true kagenti-enabled=true

# AuthBridge config
oc create configmap authbridge-config -n $NAMESPACE \
  --from-literal=ISSUER="${KEYCLOAK_URL}/realms/${REALM}" \
  --from-literal=TOKEN_URL="${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  --from-literal=EXPECTED_AUDIENCE="" \
  --from-literal=TARGET_AUDIENCE="" \
  --from-literal=TARGET_SCOPES="openid"

# Registry push secret for build-from-source
oc create secret docker-registry openshift-registry-push \
  --docker-server=image-registry.openshift-image-registry.svc:5000 \
  --docker-username=serviceaccount \
  --docker-password=$(oc create token builder -n $NAMESPACE) \
  -n $NAMESPACE

echo "Namespace $NAMESPACE is ready for Kagenti agents."
echo "After creating each agent, run:"
echo "  SA=\$(oc get deployment <agent> -n $NAMESPACE -o jsonpath='{.spec.template.spec.serviceAccountName}')"
echo "  oc adm policy add-scc-to-user kagenti-authbridge -z \$SA -n $NAMESPACE"
echo "  oc rollout restart deployment/<agent> -n $NAMESPACE"
```
