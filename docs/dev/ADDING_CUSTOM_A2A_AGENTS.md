# Adding custom A2A agents

This guide explains how to add your own A2A agent to the zero-trust demo.
Agent-service discovers agents automatically from Kubernetes Deployments
labeled with `a2a-agent.demo/type: agent`.

## How discovery works

Agent-service runs a background loop (every 30 seconds by default) that:

1. Lists Deployments with label `a2a-agent.demo/type: agent`
1. Fetches each agent's card from `GET /.well-known/agent-card.json`
1. Extracts capabilities from the agent card's skill tags
1. Registers the agent so it appears in `GET /agents`
1. Removes agents whose Deployments are scaled down or deleted

## Requirements for a custom agent

Your agent must:

1. Serve an A2A agent card at `GET /.well-known/agent-card.json`
1. Accept A2A JSON-RPC `message/send` requests at `POST /`
1. Parse a `DataPart` containing delegation context
1. Return results as a `Task` with text artifacts

### Agent card

The agent card tells agent-service what your agent can do.
The `skills[].tags` field is critical -- these tags become the agent's
capabilities for OPA authorization (department-based access control).

```json
{
  "name": "my-agent",
  "description": "My custom agent",
  "url": "http://my-agent-service:9000",
  "version": "1.0.0",
  "protocolVersion": "0.3.0",
  "capabilities": {},
  "defaultInputModes": ["application/json"],
  "defaultOutputModes": ["text/plain"],
  "skills": [
    {
      "id": "analyze",
      "name": "Document Analysis",
      "description": "Analyzes documents",
      "tags": ["engineering", "finance"]
    }
  ]
}
```

The `tags` values must match department names used in OPA policies:
`engineering`, `finance`, `admin`, `hr`.

### Delegation context

When agent-service invokes your agent via `message/send`, the message
contains a `DataPart` with this structure:

```json
{
  "document_id": "DOC-002",
  "user_spiffe_id": "spiffe://demo.example.com/user/alice",
  "user_departments": ["engineering", "finance"],
  "review_type": "general"
}
```

Your agent should use `document_id` to fetch the document from
document-service and `user_spiffe_id` / `user_departments` for any
additional authorization checks.

## Deployment template

Below is a minimal Deployment and Service for a custom agent.
Save this as `my-agent.yaml` and apply it to the `spiffe-demo` namespace.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-agent-service
  namespace: spiffe-demo
  labels:
    app: my-agent-service
    a2a-agent.demo/type: agent
    a2a-agent.demo/protocol: a2a
  annotations:
    a2a-agent.demo/description: "My custom agent description"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: my-agent-service
  template:
    metadata:
      labels:
        app: my-agent-service
    spec:
      containers:
        - name: my-agent-service
          image: my-registry/my-agent-service:latest
          ports:
            - containerPort: 9000
          env:
            - name: PORT
              value: "9000"
            - name: DOCUMENT_SERVICE_URL
              value: "http://document-service:8084"
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
---
apiVersion: v1
kind: Service
metadata:
  name: my-agent-service
  namespace: spiffe-demo
  labels:
    app: my-agent-service
spec:
  selector:
    app: my-agent-service
  ports:
    - port: 9000
      targetPort: 9000
      name: http
```

### Key labels

| Label | Required | Value |
| ----- | -------- | ----- |
| `a2a-agent.demo/type` | Yes | `agent` |
| `a2a-agent.demo/protocol` | No | `a2a` (informational) |

The `a2a-agent.demo/type: agent` label on the **Deployment** is what
triggers discovery. Without it, agent-service will not find your agent.

### Port resolution

Agent-service resolves the port from the first container port in the
Deployment spec. If no port is declared, it defaults to `8080`. You can
use any port -- just make sure the Service and Deployment match.

## Deploying

### On Kind (mock mode, no mTLS)

```bash
# Build and load your image
docker build -t my-agent-service:latest .
kind load docker-image my-agent-service:latest --name spiffe-demo

# Deploy
kubectl apply -f my-agent.yaml

# Verify discovery (wait ~30 seconds)
kubectl -n spiffe-demo logs deploy/agent-service | grep -i "my-agent"

# Check agents list
curl -s http://localhost:8083/agents | jq '.[] | select(.id=="my-agent")'
```

### On Kind (with SPIRE mTLS)

Add SPIFFE CSI driver volume mounts and set `SPIFFE_DEMO_MOCK_SPIFFE=false`.
See `deploy/k8s/overlays/local-ai-agents/kustomization.yaml` for examples
of how the summarizer and reviewer services are configured for mTLS.

### On OpenShift

Build and push your image to a registry accessible from the cluster,
then apply the Deployment. If using the AuthBridge overlay, set
`DOCUMENT_SERVICE_URL` to `http://document-service:8084` (plain HTTP,
since AuthBridge handles authentication).

## Testing your agent

### Verify the agent card

```bash
kubectl -n spiffe-demo exec deploy/agent-service -- \
  curl -s http://my-agent-service:9000/.well-known/agent-card.json | jq
```

### Invoke via agent-service

```bash
curl -s -X POST http://localhost:8083/agents/my-agent/invoke \
  -H "Content-Type: application/json" \
  -d '{
    "user_spiffe_id": "spiffe://demo.example.com/user/alice",
    "document_id": "DOC-002",
    "user_departments": ["engineering", "finance"]
  }' | jq
```

### Expected response

```json
{
  "granted": true,
  "reason": "A2A invocation completed",
  "agent": "my-agent",
  "user": "alice",
  "result": "...(agent output text)...",
  "state": "completed"
}
```

If OPA denies the request (the user's departments don't intersect with
the agent's capabilities for the requested document), you get:

```json
{
  "granted": false,
  "reason": "Permission denied: ...",
  "agent": "my-agent",
  "user": "alice"
}
```

## Writing the agent in Go

If you want to build your agent using the same Go framework as the
built-in agents, use `pkg/a2abridge`. See the summarizer-service and
reviewer-service for complete examples.

The key components are:

- `a2abridge.BuildAgentCard()` - builds the agent card from parameters
- `a2abridge.DelegatedExecutor` - implements the A2A server executor
  interface, parsing delegation context from `DataPart` messages
- `a2abridge.ExtractDelegationContext()` - extracts document ID,
  user SPIFFE ID, and departments from the incoming message

A minimal executor:

```go
func (e *MyExecutor) Execute(ctx context.Context, req a2asrv.Request) a2asrv.Response {
    delegation, err := a2abridge.ExtractDelegationContext(req.Message())
    if err != nil {
        return req.Fail(err.Error())
    }
    // Use delegation.DocumentID, delegation.UserSPIFFEID, etc.
    result := doWork(ctx, delegation)
    return req.Complete(a2a.NewTextPart(result))
}
```

See `summarizer-service/cmd/serve.go` and `reviewer-service/cmd/serve.go`
for full implementations.

## Troubleshooting

### Agent not discovered

- Verify the `a2a-agent.demo/type: agent` label is on the **Deployment**
  (not just the Pod template)
- Check that the Deployment is in the `spiffe-demo` namespace
- Look at agent-service logs: `kubectl -n spiffe-demo logs deploy/agent-service`
- Verify the agent card endpoint works from inside the cluster

### Agent discovered but invoke fails

- Check that skill tags match valid department names
- Check that the document exists and the user has access
- Look at both agent-service and your agent's logs for errors

### Agent card fetch fails

- Verify the Service port matches the container port
- Test connectivity: `kubectl -n spiffe-demo exec deploy/agent-service
  -- curl -s http://my-agent-service:9000/.well-known/agent-card.json`
- If using mTLS, ensure both services have SPIFFE identities in the
  same trust domain
