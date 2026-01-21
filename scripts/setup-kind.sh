#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== Creating Kind Cluster for SPIFFE/SPIRE Demo ==="

# Check if kind is installed
if ! command -v kind &> /dev/null; then
    echo "Error: kind is not installed. Please install it first."
    echo "  brew install kind  # macOS"
    echo "  https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
    exit 1
fi

# Check if cluster already exists
if kind get clusters 2>/dev/null | grep -q "spiffe-demo"; then
    echo "Cluster 'spiffe-demo' already exists."
    read -p "Do you want to delete and recreate it? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Deleting existing cluster..."
        kind delete cluster --name spiffe-demo
    else
        echo "Using existing cluster."
        exit 0
    fi
fi

# Create cluster
echo "Creating Kind cluster..."
kind create cluster --config "$PROJECT_ROOT/deploy/kind/cluster.yaml"

# Verify cluster is ready
echo "Waiting for cluster to be ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=120s

echo ""
echo "=== Kind cluster 'spiffe-demo' is ready! ==="
echo ""
echo "Next steps:"
echo "  1. Build images: make docker-build"
echo "  2. Load images: make docker-load"
echo "  3. Deploy: make deploy-k8s"
echo ""
