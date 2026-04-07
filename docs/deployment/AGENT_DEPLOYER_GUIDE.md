# Agent deployer guide

How to deploy a new A2A agent into the zero-trust demo environment
with proper naming, OPA permissions, and Kagenti integration.

## Concepts

### Agent ID = deployment name

The agent ID used in OPA policies, the dashboard dropdown, and SPIFFE
identity is derived from the **Kubernetes deployment name**. The
Kagenti operator sets the `app.kubernetes.io/name` label to match
the deployment name, and the agent-service uses that label as the
agent ID.

### Same code, different scopes

A single agent image can be deployed multiple times with different
names and different OPA permission scopes. For example, the same
`document-summarizer` image can run as:

| Deployment name | OPA scope | Use case |
|-----------------|-----------|----------|
| `summarizer-hr` | hr | Summarizes candidate resumes and HR policies |
| `summarizer-tech` | finance, engineering | Summarizes technical papers and financial reports |
| `summarizer-legal` | admin | Summarizes compliance and legal documents |

Each deployment gets its own agent ID, SPIFFE identity, and OPA
permissions. The agent code itself is auth-unaware — it doesn't
know its own permissions. OPA decides.

### Naming scheme

Agent IDs follow the pattern `{function}-{scope}`:

- **function**: what the agent does (`summarizer`, `reviewer`,
  `classifier`, `translator`)
- **scope**: what audience or domain it serves (`hr`, `tech`,
  `ops`, `general`, `legal`)

Examples: `summarizer-hr`, `reviewer-general`, `classifier-finance`

This groups agents by function when sorted alphabetically and makes
the scope immediately visible in the dashboard.

### AgentCard content

The AgentCard (served by the agent at `/.well-known/agent-card.json`)
should describe the agent's **functionality**, not its scope:

```json
{
  "name": "Document Summarizer",
  "description": "Summarizes documents from any URL",
  "skills": [{"id": "summarization", "name": "Document Summarization"}]
}
```

The scope is an OPA policy concern, not the agent's identity. All
instances of the same agent code should use the same agent card
content. The dashboard shows: `summarizer-tech — Document Summarizer`.

## Deployment steps

### 1. Choose the agent image

Find the container image for the agent you want to deploy. It must
implement the A2A protocol (serve `/.well-known/agent-card.json`
and handle A2A `message/send` requests).

Example images from this project:

| Image | Language | Function |
|-------|----------|----------|
| `ghcr.io/.../zt-agent:dev` | Go | **Any** (ConfigMap-driven personality) |
| `ghcr.io/.../kagenti-summarizer:dev` | Python | Document summarization |
| `ghcr.io/.../kagenti-reviewer:dev` | Python | Document review |
| `ghcr.io/.../summarizer-service:dev` | Go | Document summarization |
| `ghcr.io/.../reviewer-service:dev` | Go | Document review |

The `zt-agent` image is recommended for new deployments. It reads
its personality from a ConfigMap, so one image serves all agent types.
The other images are single-purpose agents from earlier development.

### 2. Decide the scope

Determine which departments this agent instance should have access
to. Available departments in the demo: `engineering`, `finance`,
`admin`, `hr`.

The effective permissions when a user delegates to this agent are:

```text
Effective = User departments ∩ Agent departments (from OPA)
```

The agent can never access more than what OPA allows, regardless
of the user's permissions.

### 3. Pick the deployment name

Follow the `{function}-{scope}` naming scheme:

```text
summarizer-tech     # summarizer scoped to technical docs
reviewer-ops        # reviewer scoped to operations
summarizer-hr       # summarizer scoped to HR
reviewer-general    # reviewer with access to all departments
```

This name becomes the agent ID everywhere: OPA policies, dashboard
dropdown, SPIFFE identity, and Kubernetes resources.

### 4. Add the agent to OPA policies

Edit `opa-service/policies/agent_permissions.rego` and add the new
agent ID with its department list:

```rego
agent_capabilities := {
    ...
    "summarizer-tech": ["finance", "engineering"],
}
```

Run the policy tests to verify:

```bash
make test-policies
```

### 5. Update the OPA ConfigMap on the cluster

```bash
oc patch configmap opa-policies -n spiffe-demo -p "$(cat <<EOF
data:
  agent_permissions.rego: |
$(cat opa-service/policies/agent_permissions.rego | sed 's/^/    /')
EOF
)"

oc rollout restart deployment/opa-service -n spiffe-demo
```

### 6. Deploy the agent via Kagenti UI

Open the Kagenti UI and create a new agent deployment:

- **Name**: the deployment name from step 3 (e.g., `summarizer-tech`)
- **Image**: the container image from step 1
- **Port**: the agent's HTTP port (typically `8000` for Python agents,
  `8080` for Go agents)
- **Labels**: Kagenti sets these automatically:
  - `kagenti.io/type: agent`
  - `protocol.kagenti.io/a2a: ""`
  - `app.kubernetes.io/name: {deployment-name}`

Kagenti will:

1. Create the Deployment with SPIFFE sidecar injection
2. Create a Service for the agent
3. Discover the agent card and create an `AgentCard` CR
4. Sign the agent card for verification
5. Bind the SPIFFE identity

### 7. Grant SCC to the agent service account

On OpenShift, the Kagenti-injected sidecars require SCCs. Without
them, pods will fail with `unable to validate against any security
context constraint`.

**For Kagenti agents with AuthBridge** (proxy-init container runs
as root with privileged mode):

```bash
oc adm policy add-scc-to-user privileged \
  -z summarizer-tech-sa -n spiffe-demo
```

The `kagenti-authbridge` SCC alone is not sufficient — the
AuthBridge `proxy-init` init container requires the `privileged`
SCC.

**For zt-agent deployments** (no AuthBridge, mock SPIFFE):

No SCC grant needed — zt-agent runs without privileged containers,
CSI volumes, or `spc_t` SELinux type. The default `restricted`
SCC is sufficient.

```bash
# Check the SA name Kagenti created (for Kagenti-deployed agents)
oc get deployment summarizer-tech -n spiffe-demo \
  -o jsonpath='{.spec.template.spec.serviceAccountName}'
```

Pods should start automatically after granting the SCC.

### 8. Verify discovery

After deployment, the agent-service discovers the new agent within
30 seconds (the discovery poll interval). Verify:

```bash
# Check AgentCard CR was created
oc get agentcards -n spiffe-demo

# Check agent-service discovered it
curl -s http://<agent-service>/agents | jq .
```

The new agent should appear in the dashboard dropdown.

### 9. Set the agent description

The dashboard dropdown shows the agent ID and description. By
default, Kagenti sets the description to `"Agent '{name}'"`. To
show a scope-specific description (e.g., "HR document summarizer"),
annotate the AgentCard CR:

```bash
oc annotate agentcard summarizer-tech-deployment-card \
  "zero-trust-demo/description=Technical document summarizer" \
  -n spiffe-demo
```

The AgentCard CR name follows the pattern
`{deployment-name}-deployment-card`. The agent-service reads this
annotation on the next discovery cycle (within 30 seconds).

The agent's own `agent-card.json` should describe the **generic
functionality** (e.g., "Document Summarizer"), not the scope. The
annotation provides the per-deployment scope description. This
separation allows the same agent image to be deployed multiple
times with different names and descriptions.

> **Note**: This annotation is not yet supported in the Kagenti UI.
> Set it manually with `oc annotate` after deployment. A Kagenti UI
> enhancement is planned.

### 10. Grant RBAC (first time only)

The agent-service needs permission to list AgentCard CRs. If not
already done, apply the RBAC:

```bash
oc apply -n spiffe-demo -f - <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: agentcard-reader
rules:
- apiGroups: ["agent.kagenti.dev"]
  resources: ["agentcards"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: agent-service-agentcard-reader
subjects:
- kind: ServiceAccount
  name: agent-service
roleRef:
  kind: Role
  name: agentcard-reader
  apiGroup: rbac.authorization.k8s.io
EOF
```

## Deploying a zt-agent (ConfigMap-based)

The `zt-agent` is a universal runtime where the agent personality
(system prompt, agent card) comes from a ConfigMap, not from the
container image. One image serves all agent types.

### Key rule: deployment name = agent ID = OPA key

The **Kubernetes Deployment name** determines the agent ID used
everywhere:

| System | Uses deployment name as |
| ------ | ---------------------- |
| OPA | Key in `agent_capabilities` map |
| SPIFFE | `spiffe://domain/agent/{deployment-name}` |
| Dashboard | Agent ID in dropdown (`{deployment-name} — description`) |
| Agent gateway | Route target for `/agents/{deployment-name}/invoke` |

The agent card's `name` field is **display-only** — it appears in
the agent card JSON but is NOT used for authorization or routing.
If the deployment name and the agent card name differ, OPA uses
the deployment name.

### Steps for zt-agent deployment

1. **Choose the deployment name** following `{function}-{scope}`
   or `zt-agent-{function}-{scope}` convention

1. **Create a ConfigMap** with `system-prompt.txt` and
   `agent-card.json` (and optionally `prompts.json` for prompt
   variants)

1. **Create a Deployment** using the `zt-agent` image with
   `--config-dir /config/agent` and the ConfigMap mounted

1. **Add the deployment name to OPA** — the key in
   `agent_capabilities` must match the deployment name exactly

1. **Update the OPA ConfigMap on the cluster** and restart OPA

See `deploy/k8s/overlays/ai-agents/zt-agent-summarizer-hr.yaml`
for a complete example.

### Common mistake

If the agent card says `"name": "summarizer-hr-zt"` but the
Deployment is named `zt-agent-summarizer-hr`, OPA must use
`zt-agent-summarizer-hr` — the deployment name, not the card name.

## Current demo agents

| Deployment name | Image | Scope | Language |
|-----------------|-------|-------|----------|
| summarizer-hr | summarizer-service:dev | hr, engineering | Go |
| summarizer-tech | kagenti-summarizer:dev | finance, engineering | Python |
| reviewer-ops | reviewer-service:dev | engineering, admin | Go |
| reviewer-general | kagenti-reviewer:dev | all | Python |
| summarizer-tech-klaviger | kagenti-summarizer:dev | finance, engineering | Python |
| zt-agent-summarizer-hr | zt-agent:dev | hr, engineering | Go (zt-agent) |
