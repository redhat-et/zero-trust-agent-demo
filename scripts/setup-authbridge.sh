#!/usr/bin/env bash
#
# Deploy the AuthBridge overlay to the Kind cluster.
#
# Prerequisites:
#   - Kind cluster running (./scripts/setup-kind.sh)
#   - SPIRE installed (included in Kind cluster setup)
#   - Base services deployed via kustomize (e.g., kubectl apply -k deploy/k8s/overlays/local)
#
# Usage:
#   ./scripts/setup-authbridge.sh              # Local Keycloak (in-cluster)
#   ./scripts/setup-authbridge.sh remote-kc    # Remote Keycloak (OpenShift)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Determine overlay variant
VARIANT="${1:-local}"
case "$VARIANT" in
  remote-kc)
    OVERLAY_DIR="$PROJECT_DIR/deploy/k8s/overlays/authbridge-remote-kc"
    echo "=== AuthBridge Deployment (Remote Keycloak) ==="
    ;;
  ai-agents)
    OVERLAY_DIR="$PROJECT_DIR/deploy/k8s/overlays/authbridge-ai-agents"
    echo "=== AuthBridge Deployment (with AI Agents) ==="
    ;;
  ai-agents-remote-kc)
    OVERLAY_DIR="$PROJECT_DIR/deploy/k8s/overlays/authbridge-ai-agents-remote-kc"
    echo "=== AuthBridge Deployment (AI Agents + Remote Keycloak) ==="
    ;;
  local|"")
    OVERLAY_DIR="$PROJECT_DIR/deploy/k8s/overlays/authbridge"
    echo "=== AuthBridge Deployment ==="
    ;;
  *)
    echo "ERROR: Unknown variant '$VARIANT'. Use 'local', 'remote-kc', 'ai-agents', or 'ai-agents-remote-kc'."
    exit 1
    ;;
esac
echo ""

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v kubectl &>/dev/null; then
  echo "ERROR: kubectl not found. Install it first."
  exit 1
fi

if ! command -v kustomize &>/dev/null; then
  echo "ERROR: kustomize not found. Install it first."
  exit 1
fi

if ! kubectl cluster-info &>/dev/null 2>&1; then
  echo "ERROR: No Kubernetes cluster available. Run './scripts/setup-kind.sh' first."
  exit 1
fi

# Check if SPIRE is installed
if ! kubectl get namespace spire-system &>/dev/null 2>&1; then
  echo "WARNING: spire-system namespace not found. SPIRE may not be installed."
  echo "  Run './scripts/setup-kind.sh' first to set up the cluster."
fi

# Check settings file for remote-kc variant
if [ "$VARIANT" = "remote-kc" ] || [ "$VARIANT" = "ai-agents-remote-kc" ]; then
  SETTINGS_FILE="$OVERLAY_DIR/settings.yaml"
  if [ ! -f "$SETTINGS_FILE" ]; then
    echo ""
    echo "ERROR: $SETTINGS_FILE not found."
    echo "  Copy the example and fill in your values:"
    echo "    cp $OVERLAY_DIR/settings.yaml.example $SETTINGS_FILE"
    echo ""
    exit 1
  fi
  if grep -q "CHANGE_ME" "$SETTINGS_FILE"; then
    echo ""
    echo "WARNING: settings.yaml contains placeholder values."
    echo "  Edit $SETTINGS_FILE and set your Keycloak URL and admin password."
    echo ""
  fi
fi

echo "Prerequisites OK."
echo ""

# Apply the authbridge kustomize overlay
echo "Applying AuthBridge overlay from $OVERLAY_DIR..."
kubectl apply -k "$OVERLAY_DIR"
echo ""

# Wait for deployments
echo "Waiting for deployments to be ready..."
if [ "$VARIANT" != "remote-kc" ] && [ "$VARIANT" != "ai-agents-remote-kc" ]; then
  kubectl rollout status deployment/keycloak -n spiffe-demo --timeout=180s || true
fi
kubectl rollout status deployment/agent-service -n spiffe-demo --timeout=120s || true
kubectl rollout status deployment/document-service -n spiffe-demo --timeout=120s || true
if [ "$VARIANT" = "ai-agents" ] || [ "$VARIANT" = "ai-agents-remote-kc" ]; then
  kubectl rollout status deployment/summarizer-service -n spiffe-demo --timeout=120s || true
  kubectl rollout status deployment/reviewer-service -n spiffe-demo --timeout=120s || true
fi
echo ""

# Check agent-service pod containers
echo "Verifying agent-service pod containers..."
AGENT_POD=$(kubectl get pods -n spiffe-demo -l app=agent-service -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [ -n "$AGENT_POD" ]; then
  CONTAINERS=$(kubectl get pod "$AGENT_POD" -n spiffe-demo -o jsonpath='{.spec.containers[*].name}')
  echo "  Pod: $AGENT_POD"
  echo "  Containers: $CONTAINERS"

  # Check for AuthBridge containers
  for expected in client-registration spiffe-helper envoy-proxy; do
    if echo "$CONTAINERS" | grep -q "$expected"; then
      echo "  ✓ $expected container present"
    else
      echo "  ✗ $expected container MISSING"
    fi
  done
else
  echo "  WARNING: No agent-service pod found"
fi
echo ""

# Check client-registration logs
echo "Checking client-registration status..."
if [ -n "$AGENT_POD" ]; then
  if kubectl logs "$AGENT_POD" -n spiffe-demo -c client-registration --tail=5 2>/dev/null | grep -q "Client registration complete"; then
    echo "  ✓ Client registration completed successfully"
  else
    echo "  ⏳ Client registration still in progress (or failed)"
    echo "  Check logs: kubectl logs $AGENT_POD -n spiffe-demo -c client-registration"
  fi
fi
echo ""

echo "=== Deployment Complete ==="
echo ""
echo "Next steps:"
if [ "$VARIANT" = "remote-kc" ]; then
  echo "  1. Set up port forwarding (dashboard only, Keycloak is remote):"
  echo "     kubectl port-forward svc/web-dashboard 8080:8080 -n spiffe-demo &"
  echo ""
  echo "  2. Access Keycloak admin:"
  echo "     https://keycloak.example.com/admin"
  echo ""
  echo "  3. Run AuthBridge tests:"
  echo "     KEYCLOAK_URL=https://keycloak.example.com \\"
  echo "       ./scripts/test-authbridge.sh"
  echo ""
  echo "  4. Open dashboard: http://localhost:8080"
else
  echo "  1. Set up port forwarding:"
  echo "     kubectl port-forward svc/keycloak 8080:8080 -n spiffe-demo &"
  echo "     kubectl port-forward svc/web-dashboard 8081:8080 -n spiffe-demo &"
  echo ""
  echo "  2. Access Keycloak admin: http://keycloak.localtest.me:8080/admin"
  echo "     (admin / admin123)"
  echo ""
  echo "  3. Run AuthBridge tests:"
  echo "     ./scripts/test-authbridge.sh"
  echo ""
  echo "  4. Open dashboard: http://localhost:8081"
fi
