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

### Label for SPIRE identity

The `agentcard=true` label enables the ClusterSPIFFEID controller
to issue SPIFFE identities to agent pods in this namespace.

```bash
oc label namespace $NAMESPACE agentcard=true --overwrite
```

### AuthBridge SCC

AuthBridge sidecars require privileged init containers (iptables)
and specific UIDs (1337 for Envoy, 1000 for go-processor). The
`openclaw-authbridge` SCC allows this.

When Kagenti creates an agent with SPIRE enabled, it creates a
service account named `<agent-name>-sa`. Without SPIRE, it uses
`<agent-name>`. You must grant the SCC **after** the agent is
created, because the SA doesn't exist beforehand.

```bash
# After creating the agent (with SPIRE enabled):
oc adm policy add-scc-to-user openclaw-authbridge \
  -z <agent-name>-sa -n $NAMESPACE

# After creating the agent (without SPIRE):
oc adm policy add-scc-to-user openclaw-authbridge \
  -z <agent-name> -n $NAMESPACE

# Then restart the deployment to pick up the SCC:
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

## Deploy an agent from source (CLI)

The Kagenti UI currently only offers four registry options and does
not include the OpenShift internal registry. Until the UI is updated,
use the Kagenti API directly.

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
# Grant SCC to the SA (created during finalize)
# With spireEnabled=true, Kagenti creates <name>-sa
oc adm policy add-scc-to-user openclaw-authbridge \
  -z ${AGENT_NAME}-sa -n $NAMESPACE 2>/dev/null || \
oc adm policy add-scc-to-user openclaw-authbridge \
  -z ${AGENT_NAME} -n $NAMESPACE

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
echo "  oc adm policy add-scc-to-user openclaw-authbridge -z <agent>-sa -n $NAMESPACE"
echo "  oc rollout restart deployment/<agent> -n $NAMESPACE"
```
