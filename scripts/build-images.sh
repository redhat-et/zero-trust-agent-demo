#!/bin/bash
set -e

# Build Docker images for all services
# Images are tagged for local use with Kind: localhost/spiffe-demo/<service>:latest

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

SERVICES=(
    "opa-service"
    "document-service"
    "user-service"
    "agent-service"
    "web-dashboard"
)

IMAGE_PREFIX="localhost/spiffe-demo"

echo "=== Building Docker images ==="
echo "Project root: $PROJECT_ROOT"
echo ""

for service in "${SERVICES[@]}"; do
    echo "Building $service..."
    docker build \
        -t "${IMAGE_PREFIX}/${service}:latest" \
        -f "${service}/Dockerfile" \
        .
    echo "✓ ${IMAGE_PREFIX}/${service}:latest"
    echo ""
done

echo "=== All images built successfully ==="
echo ""
echo "Images:"
for service in "${SERVICES[@]}"; do
    echo "  - ${IMAGE_PREFIX}/${service}:latest"
done
echo ""
echo "Run './scripts/load-images.sh' to load images into Kind cluster."
