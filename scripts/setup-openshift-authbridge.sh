#!/usr/bin/env bash
#
# Deploy the AuthBridge overlay to OpenShift.
#
# This overlay extends openshift-ai-agents with AuthBridge sidecars (Envoy
# proxy, spiffe-helper, client-registration) for JWT token exchange.
#
# Prerequisites:
#   - OpenShift cluster with oc CLI logged in
#   - SPIRE installed in spire-system namespace
#   - openshift-oidc template files generated (oidc-urls-configmap.yaml,
#     keycloak-realm-patch.yaml)
#   - settings.yaml configured with Keycloak URL and admin password
#
# Usage:
#   ./scripts/setup-openshift-authbridge.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OVERLAY_DIR="$PROJECT_DIR/deploy/k8s/overlays/openshift-authbridge"
OIDC_OVERLAY_DIR="$PROJECT_DIR/deploy/k8s/overlays/openshift-oidc"
NAMESPACE="spiffe-demo"

echo "=== AuthBridge Deployment (OpenShift) ==="
echo ""

# --- Check prerequisites ---
echo "Checking prerequisites..."

if ! command -v oc &>/dev/null; then
  echo "ERROR: oc CLI not found. Install the OpenShift CLI first."
  exit 1
fi

if ! oc whoami &>/dev/null 2>&1; then
  echo "ERROR: Not logged in to OpenShift. Run 'oc login' first."
  exit 1
fi

CLUSTER_NAME=$(oc whoami --show-server 2>/dev/null || echo "unknown")
echo "  Cluster: $CLUSTER_NAME"

# Check SPIRE
if ! oc get namespace spire-system &>/dev/null 2>&1; then
  echo "WARNING: spire-system namespace not found. SPIRE may not be installed."
fi

# Check settings.yaml
SETTINGS_FILE="$OVERLAY_DIR/settings.yaml"
if [ ! -f "$SETTINGS_FILE" ]; then
  echo ""
  echo "ERROR: $SETTINGS_FILE not found."
  echo "  Copy the example and fill in your values:"
  echo "    cp $OVERLAY_DIR/settings.yaml.example $SETTINGS_FILE"
  echo ""
  exit 1
fi

if grep -q "CLUSTER_DOMAIN" "$SETTINGS_FILE"; then
  echo ""
  echo "WARNING: settings.yaml still contains CLUSTER_DOMAIN placeholder."
  echo "  Replace it with your actual cluster domain:"
  echo "    CLUSTER_DOMAIN=\$(oc get ingresses.config/cluster -o jsonpath='{.spec.domain}')"
  echo "    sed -i \"s/CLUSTER_DOMAIN/\$CLUSTER_DOMAIN/g\" $SETTINGS_FILE"
  echo ""
fi

if grep -q "CHANGE_ME" "$SETTINGS_FILE"; then
  echo ""
  echo "WARNING: settings.yaml contains CHANGE_ME placeholder."
  echo "  Edit $SETTINGS_FILE and set your Keycloak admin password."
  echo ""
fi

# Check openshift-oidc generated files
MISSING_TEMPLATES=0
for tmpl_file in oidc-urls-configmap.yaml keycloak-realm-patch.yaml; do
  if [ ! -f "$OIDC_OVERLAY_DIR/$tmpl_file" ]; then
    MISSING_TEMPLATES=1
    echo ""
    echo "WARNING: $OIDC_OVERLAY_DIR/$tmpl_file not found."
    echo "  Generate it from the template:"
    echo "    CLUSTER_DOMAIN=\$(oc get ingresses.config/cluster -o jsonpath='{.spec.domain}')"
    echo "    sed \"s/CLUSTER_DOMAIN/\$CLUSTER_DOMAIN/g\" \\"
    echo "      $OIDC_OVERLAY_DIR/${tmpl_file}.template > $OIDC_OVERLAY_DIR/$tmpl_file"
  fi
done

if [ "$MISSING_TEMPLATES" -eq 1 ]; then
  echo ""
  echo "ERROR: Missing openshift-oidc template files. Generate them first."
  exit 1
fi

echo "Prerequisites OK."
echo ""

# --- Grant privileged SCC ---
echo "Ensuring privileged SCC is granted to default ServiceAccount..."
oc adm policy add-scc-to-user privileged \
  "system:serviceaccount:${NAMESPACE}:default" \
  --namespace "$NAMESPACE" 2>/dev/null || true
echo "  Done."
echo ""

# --- Apply overlay ---
echo "Applying AuthBridge overlay from $OVERLAY_DIR..."
oc apply -k "$OVERLAY_DIR"
echo ""

# --- Wait for deployments ---
echo "Waiting for deployments to be ready..."
oc rollout status deployment/agent-service -n "$NAMESPACE" --timeout=180s || true
oc rollout status deployment/document-service -n "$NAMESPACE" --timeout=120s || true
oc rollout status deployment/user-service -n "$NAMESPACE" --timeout=120s || true
oc rollout status deployment/web-dashboard -n "$NAMESPACE" --timeout=120s || true
echo ""

# --- Verify agent-service pod ---
echo "Verifying agent-service pod containers..."
AGENT_POD=$(oc get pods -n "$NAMESPACE" -l app=agent-service \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -n "$AGENT_POD" ]; then
  CONTAINERS=$(oc get pod "$AGENT_POD" -n "$NAMESPACE" \
    -o jsonpath='{.spec.containers[*].name}')
  echo "  Pod: $AGENT_POD"
  echo "  Containers: $CONTAINERS"

  for expected in client-registration spiffe-helper envoy-proxy; do
    if echo "$CONTAINERS" | grep -q "$expected"; then
      echo "  OK: $expected container present"
    else
      echo "  MISSING: $expected container"
    fi
  done
else
  echo "  WARNING: No agent-service pod found"
fi
echo ""

# --- Check client-registration ---
echo "Checking client-registration status..."
if [ -n "$AGENT_POD" ]; then
  if oc logs "$AGENT_POD" -n "$NAMESPACE" -c client-registration --tail=10 2>/dev/null \
    | grep -q "Client registration complete"; then
    echo "  OK: Client registration completed successfully"
  else
    echo "  PENDING: Client registration still in progress (or failed)"
    echo "  Check logs: oc logs $AGENT_POD -n $NAMESPACE -c client-registration"
  fi
fi
echo ""

# --- Print summary ---
DASHBOARD_ROUTE=$(oc get route web-dashboard -n "$NAMESPACE" \
  -o jsonpath='{.spec.host}' 2>/dev/null || echo "")
KC_ROUTE=$(oc get route keycloak -n "$NAMESPACE" \
  -o jsonpath='{.spec.host}' 2>/dev/null || echo "")

echo "=== Deployment Complete ==="
echo ""
echo "Next steps:"
echo ""
if [ -n "$DASHBOARD_ROUTE" ]; then
  echo "  1. Open dashboard: https://$DASHBOARD_ROUTE"
else
  echo "  1. Dashboard Route not found. Check: oc get routes -n $NAMESPACE"
fi
echo ""
if [ -n "$KC_ROUTE" ]; then
  echo "  2. Keycloak admin: https://$KC_ROUTE/admin"
else
  echo "  2. Keycloak Route not found (using remote Keycloak)."
  echo "     Check your settings.yaml for the Keycloak URL."
fi
echo ""
echo "  3. Run AuthBridge tests:"
echo "     make test-openshift-authbridge"
echo ""
echo "Troubleshooting:"
echo "  - Agent-service logs:    oc logs deployment/agent-service -n $NAMESPACE -c agent-service"
echo "  - Client-registration:   oc logs deployment/agent-service -n $NAMESPACE -c client-registration"
echo "  - Envoy proxy:           oc logs deployment/agent-service -n $NAMESPACE -c envoy-proxy"
echo "  - Spiffe-helper:         oc logs deployment/agent-service -n $NAMESPACE -c spiffe-helper"
echo ""
echo "  If proxy-init fails with iptables errors on RHEL 9 / nftables:"
echo "  - Check: oc logs deployment/agent-service -n $NAMESPACE -c proxy-init"
echo "  - The iptables-nft compatibility layer should be available on CoreOS"
echo "  - Verify: oc debug node/<node> -- chroot /host iptables --version"
