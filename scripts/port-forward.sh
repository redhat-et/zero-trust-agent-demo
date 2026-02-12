#!/bin/bash
set -euo pipefail

echo "=== Setting up port forwarding for SPIFFE/SPIRE Demo ==="

# Kill any existing port-forward processes
pkill -f "kubectl.*port-forward.*spiffe-demo" 2>/dev/null || true

# Port forward all services
echo "Starting port forwards..."

kubectl -n spiffe-demo port-forward svc/web-dashboard 8080:8080 &
kubectl -n spiffe-demo port-forward svc/user-service 8082:8082 &
kubectl -n spiffe-demo port-forward svc/agent-service 8083:8083 &
kubectl -n spiffe-demo port-forward svc/document-service 8084:8084 &
kubectl -n spiffe-demo port-forward svc/opa-service 8085:8085 &
kubectl -n spiffe-demo port-forward svc/jaeger 16686:16686 &

echo ""
echo "=== Port forwards active ==="
echo ""
echo "  Dashboard:        http://localhost:8080"
echo "  User Service:     http://localhost:8082"
echo "  Agent Service:    http://localhost:8083"
echo "  Document Service: http://localhost:8084"
echo "  OPA Service:      http://localhost:8085"
echo "  Jaeger UI:        http://localhost:16686"
echo ""
echo "Press Ctrl+C to stop all port forwards"
echo ""

# Wait for user interrupt
wait
