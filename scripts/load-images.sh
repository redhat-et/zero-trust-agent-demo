#!/bin/bash
set -e

# Load Docker images into Kind cluster
# This is required for the 'local' Kustomize overlay which uses localhost/* images

CLUSTER_NAME="${KIND_CLUSTER_NAME:-spiffe-demo}"

SERVICES=(
    "opa-service"
    "document-service"
    "user-service"
    "agent-service"
    "web-dashboard"
)

IMAGE_PREFIX="localhost/spiffe-demo"

echo "=== Loading images into Kind cluster '$CLUSTER_NAME' ==="
echo ""

# Check if Kind cluster exists
if ! kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    echo "Error: Kind cluster '$CLUSTER_NAME' not found."
    echo "Run './scripts/setup-kind.sh' first."
    exit 1
fi

for service in "${SERVICES[@]}"; do
    image="${IMAGE_PREFIX}/${service}:latest"

    # Check if image exists locally
    if ! docker image inspect "$image" &>/dev/null; then
        echo "Error: Image '$image' not found locally."
        echo "Run './scripts/build-images.sh' first."
        exit 1
    fi

    echo "Loading $image..."
    kind load docker-image "$image" --name "$CLUSTER_NAME"
    echo "✓ Loaded $service"
done

echo ""
echo "=== All images loaded successfully ==="
echo ""
echo "Deploy with: kubectl apply -k deploy/k8s/overlays/local"
