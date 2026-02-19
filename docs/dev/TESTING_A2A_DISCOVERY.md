# Testing A2A agent discovery on Kind

This guide covers testing the Phase 2 A2A discovery feature using
the `local-ai-agents` overlay on a Kind cluster with SPIFFE mTLS.

## Prerequisites

- Kind cluster with SPIRE CSI driver already set up (`make setup-kind`)
- All service images built and loaded into Kind

## Step-by-step procedure

### Build images and load into Kind

```bash
make docker-build
make docker-load
```

### Deploy the base stack without AI agents

Deploy only the `local` overlay first — this gives you the core services
(opa, document, user, agent, dashboard) without summarizer/reviewer:

```bash
kubectl apply -k deploy/k8s/overlays/local
```

Wait for pods to be ready:

```bash
kubectl -n spiffe-demo wait --for=condition=ready pod \
  -l app=agent-service --timeout=60s
```

### Verify only static agents exist

Port-forward agent-service:

```bash
kubectl -n spiffe-demo port-forward svc/agent-service 8083:8083 &
```

Query agents — you should see gpt4, claude, summarizer, reviewer (all static):

```bash
curl -sk https://localhost:8083/agents | python3 -m json.tool
```

All four agents have `"source": "static"` and no `a2a_url`.
The static summarizer/reviewer entries are placeholders for the demo;
they cannot be invoked via A2A.

### Deploy the full stack with AI agents and discovery

Apply the `local-ai-agents` overlay.
This adds summarizer-service and reviewer-service with discovery labels,
enables discovery on agent-service, and creates RBAC resources:

```bash
kubectl apply -k deploy/k8s/overlays/local-ai-agents
```

This updates the existing agent-service deployment (adding discovery env
vars and ServiceAccount) and creates the new summarizer/reviewer deployments.

Wait for everything to be ready:

```bash
kubectl -n spiffe-demo wait --for=condition=ready pod \
  -l app=summarizer-service --timeout=120s
kubectl -n spiffe-demo wait --for=condition=ready pod \
  -l app=reviewer-service --timeout=120s
```

### Watch agent-service logs for discovery

The discovery loop runs every 30 seconds. Watch the logs:

```bash
kubectl -n spiffe-demo logs -f deploy/agent-service | grep -i discover
```

You should see lines like:

```text
Discovering A2A agent  deployment=summarizer-service url=https://...
Discovered A2A agent  id=summarizer name="Summarizer Agent" capabilities=[finance]
Discovering A2A agent  deployment=reviewer-service url=https://...
Discovered A2A agent  id=reviewer name="Reviewer Agent" capabilities=[engineering finance admin hr]
Registered discovered agent  id=summarizer ...
Registered discovered agent  id=reviewer ...
```

### Verify discovered agents appear in the API

Re-query the agents list (kill the old port-forward first if agent-service
pod restarted):

```bash
kubectl -n spiffe-demo port-forward svc/agent-service 8083:8083 &
curl -sk https://localhost:8083/agents | python3 -m json.tool
```

The summarizer and reviewer entries should now have:

- `"source": "discovered"` (overwriting the static entries)
- `"a2a_url"` pointing to the in-cluster A2A endpoint

### Test the invoke endpoint

Invoke the summarizer via agent-service.
This checks OPA authorization first, then forwards to the A2A agent:

```bash
curl -sk -X POST https://localhost:8083/agents/summarizer/invoke \
  -H "Content-Type: application/json" \
  -d '{
    "user_spiffe_id": "spiffe://demo.example.com/user/alice",
    "document_id": "DOC-002",
    "user_departments": ["engineering", "finance"]
  }' | python3 -m json.tool
```

Expected response (if LLM is configured):

```json
{
  "granted": true,
  "reason": "A2A invocation completed",
  "agent": "summarizer",
  "user": "alice",
  "result": "...(summary text)...",
  "state": "completed"
}
```

If no LLM is configured, you will get a response with
`"state": "failed"` and a message about the LLM not being available.
That is fine — it proves the A2A round-trip works up to the LLM call.

### Test authorization denial

Try a request that should be denied (alice does not have admin access):

```bash
curl -sk -X POST https://localhost:8083/agents/summarizer/invoke \
  -H "Content-Type: application/json" \
  -d '{
    "user_spiffe_id": "spiffe://demo.example.com/user/alice",
    "document_id": "DOC-003",
    "user_departments": ["engineering", "finance"]
  }' | python3 -m json.tool
```

Expected: `"granted": false` with a permission denied reason.

### Test static agent rejection

Try invoking a static agent (no A2A URL):

```bash
curl -sk -X POST https://localhost:8083/agents/gpt4/invoke \
  -H "Content-Type: application/json" \
  -d '{
    "user_spiffe_id": "spiffe://demo.example.com/user/alice",
    "document_id": "DOC-001",
    "user_departments": ["engineering"]
  }' | python3 -m json.tool
```

Expected: HTTP 400 with `"reason": "Agent does not support A2A invocation"`.

### Test discovery removal (optional)

Scale down the reviewer to verify it gets removed from the agent list:

```bash
kubectl -n spiffe-demo scale deploy/reviewer-service --replicas=0
```

Wait 30+ seconds for the next discovery cycle, then check:

```bash
curl -sk https://localhost:8083/agents | python3 -m json.tool
```

The reviewer should revert to its static entry (`"source": "static"`,
no `a2a_url`). Scale it back up to see it re-discovered:

```bash
kubectl -n spiffe-demo scale deploy/reviewer-service --replicas=1
```

## Troubleshooting

### Agent-service crashes with "failed to initialize agent discovery"

Check that the ServiceAccount and RBAC were created:

```bash
kubectl -n spiffe-demo get sa,role,rolebinding
```

If missing, re-apply:

```bash
kubectl apply -k deploy/k8s/overlays/local-ai-agents
```

### Discovery finds deployments but fails to fetch agent cards

- Check that summarizer/reviewer pods are ready
- Check the scheme: agent-service logs show the URL it tries.
  If services use mTLS, the scheme should be `https`
- Test the agent card directly:

```bash
kubectl -n spiffe-demo exec deploy/agent-service -- \
  curl -sk https://summarizer-service:8086/.well-known/agent-card.json
```

### Invoke returns 502 bad gateway

- The A2A `message/send` call failed. Check agent-service logs for the error
- Check summarizer/reviewer logs for incoming request errors
- Verify mTLS trust: both services need SPIFFE identities in the same
  trust domain
