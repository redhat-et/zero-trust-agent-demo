#!/bin/bash
#
# Test S3 document storage with MinIO
#
# Prerequisites:
#   - Docker (or Podman)
#   - AWS CLI (optional, for bucket creation)
#   - Built binaries (make build)
#
# Usage:
#   ./scripts/test-s3-storage.sh
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# MinIO configuration
MINIO_CONTAINER="minio-test"
MINIO_PORT=9000
MINIO_CONSOLE_PORT=9001
MINIO_ROOT_USER="minioadmin"
MINIO_ROOT_PASSWORD="minioadmin"
BUCKET_NAME="documents"

echo "=== S3 Storage Test Setup ==="
echo ""

# Check if MinIO is already running
if docker ps --format '{{.Names}}' | grep -q "^${MINIO_CONTAINER}$"; then
    echo "MinIO container already running"
else
    echo "Starting MinIO container..."
    docker run -d \
        --name "$MINIO_CONTAINER" \
        -p ${MINIO_PORT}:9000 \
        -p ${MINIO_CONSOLE_PORT}:9001 \
        -e MINIO_ROOT_USER="$MINIO_ROOT_USER" \
        -e MINIO_ROOT_PASSWORD="$MINIO_ROOT_PASSWORD" \
        minio/minio server /data --console-address ":9001"

    echo "Waiting for MinIO to start..."
    sleep 3
fi

# Create bucket using AWS CLI or mc
echo "Creating bucket '$BUCKET_NAME'..."

# Export credentials for AWS CLI
export AWS_ACCESS_KEY_ID="$MINIO_ROOT_USER"
export AWS_SECRET_ACCESS_KEY="$MINIO_ROOT_PASSWORD"

if command -v aws &> /dev/null; then
    # Check if bucket exists first
    if aws --endpoint-url "http://localhost:${MINIO_PORT}" --region us-east-1 \
        s3api head-bucket --bucket "${BUCKET_NAME}" 2>/dev/null; then
        echo "Bucket already exists"
    else
        echo "Creating bucket with AWS CLI..."
        aws --endpoint-url "http://localhost:${MINIO_PORT}" --region us-east-1 \
            s3 mb "s3://${BUCKET_NAME}"
    fi
elif command -v mc &> /dev/null; then
    mc alias set minio "http://localhost:${MINIO_PORT}" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" 2>/dev/null || true
    mc mb "minio/${BUCKET_NAME}" 2>/dev/null || echo "Bucket already exists"
else
    echo "Neither 'aws' nor 'mc' CLI found. Creating bucket via curl..."
    # MinIO supports bucket creation via PUT with proper auth
    curl -s -X PUT "http://localhost:${MINIO_PORT}/${BUCKET_NAME}" \
        --aws-sigv4 "aws:amz:us-east-1:s3" \
        -u "${MINIO_ROOT_USER}:${MINIO_ROOT_PASSWORD}" || echo "Bucket may already exist"
fi

# Verify bucket exists
echo "Verifying bucket..."
if aws --endpoint-url "http://localhost:${MINIO_PORT}" --region us-east-1 \
    s3api head-bucket --bucket "${BUCKET_NAME}" 2>/dev/null; then
    echo "✓ Bucket '$BUCKET_NAME' is accessible"
else
    echo "✗ ERROR: Bucket '$BUCKET_NAME' is not accessible"
    echo "  Try manually: aws --endpoint-url http://localhost:${MINIO_PORT} --region us-east-1 s3 mb s3://${BUCKET_NAME}"
    exit 1
fi

echo ""
echo "=== Environment Variables ==="
echo ""
echo "Set these in your shell or use the config.yaml:"
echo ""
echo "export SPIFFE_DEMO_STORAGE_ENABLED=true"
echo "export BUCKET_HOST=localhost"
echo "export BUCKET_PORT=${MINIO_PORT}"
echo "export BUCKET_NAME=${BUCKET_NAME}"
echo "export AWS_ACCESS_KEY_ID=${MINIO_ROOT_USER}"
echo "export AWS_SECRET_ACCESS_KEY=${MINIO_ROOT_PASSWORD}"
echo ""

# Export for this script
export SPIFFE_DEMO_STORAGE_ENABLED=true
export BUCKET_HOST=localhost
export BUCKET_PORT=${MINIO_PORT}
export BUCKET_NAME=${BUCKET_NAME}
export AWS_ACCESS_KEY_ID=${MINIO_ROOT_USER}
export AWS_SECRET_ACCESS_KEY=${MINIO_ROOT_PASSWORD}

echo "=== Seeding Documents ==="
echo ""
./bin/document-service seed
echo ""

echo "=== MinIO Console ==="
echo ""
echo "Access MinIO console at: http://localhost:${MINIO_CONSOLE_PORT}"
echo "Username: ${MINIO_ROOT_USER}"
echo "Password: ${MINIO_ROOT_PASSWORD}"
echo ""

echo "=== Starting Services ==="
echo ""
echo "To start all services with S3 storage, run:"
echo ""
echo "  # Terminal 1: OPA Service"
echo "  ./bin/opa-service serve"
echo ""
echo "  # Terminal 2: Document Service (with S3)"
echo "  export SPIFFE_DEMO_STORAGE_ENABLED=true"
echo "  export BUCKET_HOST=localhost"
echo "  export BUCKET_PORT=${MINIO_PORT}"
echo "  export BUCKET_NAME=${BUCKET_NAME}"
echo "  export AWS_ACCESS_KEY_ID=${MINIO_ROOT_USER}"
echo "  export AWS_SECRET_ACCESS_KEY=${MINIO_ROOT_PASSWORD}"
echo "  ./bin/document-service serve"
echo ""
echo "  # Terminal 3: Other services (run-local.sh or individually)"
echo ""

echo "=== Test Commands ==="
echo ""
echo "# List documents"
echo "curl http://localhost:8084/documents"
echo ""
echo "# Access document (as Alice - engineering user)"
echo "curl -X POST http://localhost:8084/access \\"
echo "  -H 'Content-Type: application/json' \\"
echo "  -H 'X-SPIFFE-ID: spiffe://demo.example.com/user/alice' \\"
echo "  -d '{\"document_id\":\"DOC-001\"}'"
echo ""
echo "# Create document (as Bob - admin user)"
echo "curl -X POST http://localhost:8084/documents \\"
echo "  -H 'Content-Type: application/json' \\"
echo "  -H 'X-SPIFFE-ID: spiffe://demo.example.com/user/bob' \\"
echo "  -d '{\"id\":\"DOC-TEST\",\"title\":\"Test Doc\",\"required_departments\":[\"engineering\"],\"sensitivity\":\"low\",\"content\":\"# Test\\n\\nHello world\"}'"
echo ""
echo "# Delete document (as Bob - admin user)"
echo "curl -X DELETE http://localhost:8084/documents/DOC-TEST \\"
echo "  -H 'X-SPIFFE-ID: spiffe://demo.example.com/user/bob'"
echo ""

echo "=== Cleanup ==="
echo ""
echo "To stop and remove MinIO container:"
echo "  docker stop ${MINIO_CONTAINER} && docker rm ${MINIO_CONTAINER}"
echo ""
