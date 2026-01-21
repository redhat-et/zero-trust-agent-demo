#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== Deploying SPIFFE/SPIRE Demo Application ==="

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "Error: kubectl is not installed."
    exit 1
fi

# Check if cluster exists
if ! kubectl cluster-info &> /dev/null; then
    echo "Error: No Kubernetes cluster is available."
    echo "Please run 'make setup-kind' first."
    exit 1
fi

# Apply manifests
echo "Creating namespace..."
kubectl apply -f "$PROJECT_ROOT/deploy/k8s/namespace.yaml"

echo "Creating OPA policies ConfigMap..."
kubectl apply -f "$PROJECT_ROOT/deploy/k8s/opa-policies-configmap.yaml"

echo "Deploying services..."
kubectl apply -f "$PROJECT_ROOT/deploy/k8s/deployments.yaml"

# Wait for deployments
echo "Waiting for deployments to be ready..."
kubectl -n spiffe-demo wait --for=condition=Available deployment --all --timeout=120s

echo ""
echo "=== Deployment Complete! ==="
echo ""
echo "Services:"
kubectl -n spiffe-demo get pods
echo ""
echo "Access the dashboard at: http://localhost:8080"
echo ""
