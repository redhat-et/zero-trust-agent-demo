#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BIN_DIR="$PROJECT_ROOT/bin"

echo "=== Starting SPIFFE/SPIRE Zero Trust Demo (Local Mode) ==="
echo ""

# Check if binaries exist
if [ ! -d "$BIN_DIR" ]; then
    echo "Error: Binaries not found. Run 'make build' first."
    exit 1
fi

# Create a temporary directory for logs
LOG_DIR="$PROJECT_ROOT/tmp/logs"
mkdir -p "$LOG_DIR"

# Cleanup function
cleanup() {
    echo ""
    echo "Shutting down services..."
    jobs -p | xargs -r kill 2>/dev/null || true
    wait 2>/dev/null || true
    echo "All services stopped."
}
trap cleanup EXIT INT TERM

# Start services
echo "Starting OPA Service on :8085..."
cd "$PROJECT_ROOT/opa-service" && "$BIN_DIR/opa-service" serve --policy-dir=policies > "$LOG_DIR/opa-service.log" 2>&1 &
sleep 1

echo "Starting Document Service on :8084..."
"$BIN_DIR/document-service" serve > "$LOG_DIR/document-service.log" 2>&1 &
sleep 1

echo "Starting User Service on :8082..."
"$BIN_DIR/user-service" serve > "$LOG_DIR/user-service.log" 2>&1 &
sleep 1

echo "Starting Agent Service on :8083..."
"$BIN_DIR/agent-service" serve > "$LOG_DIR/agent-service.log" 2>&1 &
sleep 1

echo "Starting Web Dashboard on :8080..."
"$BIN_DIR/web-dashboard" serve > "$LOG_DIR/web-dashboard.log" 2>&1 &
sleep 1

echo ""
echo "=== All services started! ==="
echo ""
echo "Services:"
echo "  Web Dashboard:    http://localhost:8080"
echo "  User Service:     http://localhost:8082"
echo "  Agent Service:    http://localhost:8083"
echo "  Document Service: http://localhost:8084"
echo "  OPA Service:      http://localhost:8085"
echo ""
echo "Logs directory: $LOG_DIR"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Wait for services
wait
