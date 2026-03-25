# OPA Policy Reference

This document describes the Open Policy Agent (OPA) policies used in the Zero Trust Agent Demo to implement fine-grained access control with permission intersection.

## Table of Contents

1. [Policy Structure Overview](#policy-structure-overview)
1. [Policy Evaluation Flow](#policy-evaluation-flow)
1. [Policy Modules](#policy-modules)
1. [Example Input/Output](#example-inputoutput)
1. [Policy Testing](#policy-testing)
1. [Reference Files](#reference-files)

---

## Policy Structure Overview

The demo uses three main policy modules that work together to implement permission intersection for delegated AI agent access:

| Module | File | Purpose |
| ------ | ---- | ------- |
| User Permissions | `policies/user_permissions.rego` | Maps users to department memberships |
| Agent Capabilities | `policies/agent_capabilities.rego` | Defines agent capability restrictions |
| Document Access | `policies/document_access.rego` | Main authorization logic with permission intersection |

### Core Principle: Permission Intersection

When a user delegates access to an AI agent, the effective permissions are computed as:

```
Effective Permissions = User Departments ∩ Agent Capabilities
```

This ensures agents can never exceed the permissions of either the user OR the agent's configured capabilities, implementing the **Least Privilege** principle for AI systems.

---

## Policy Evaluation Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Document Service Request                     │
│  Input: {caller_spiffe_id, document_id, delegation_context}     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     OPA Policy Evaluation                       │
│                                                                 │
│  Step 1: Parse SPIFFE ID                                        │
│  ├─ Extract: spiffe://demo.example.com/{type}/{name}            │
│  └─ Determine if caller is user, agent, or other                │
│                                                                 │
│  Step 2: Load Document Requirements                             │
│  └─ Query: documents[document_id].required_department           │
│                                                                 │
│  Step 3: Check Request Type                                     │
│  ├─ Direct User Request? → Evaluate user_permissions            │
│  ├─ Direct Agent Request? → DENY (no user context)              │
│  └─ Delegated Request? → Evaluate permission intersection       │
│                                                                 │
│  Step 4: Permission Intersection (Delegation)                   │
│  ├─ User departments: user_permissions[user]                    │
│  ├─ Agent capabilities: agent_capabilities[agent]               │
│  ├─ Intersection: user_deps ∩ agent_caps                        │
│  └─ Required: document.required_department                      │
│                                                                 │
│  Step 5: Authorization Decision                                 │
│  └─ ALLOW if required_department ∈ intersection                 │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Return Decision + Reason                     │
│  Output: {allow: true/false, reason: "...", details: {...}}     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Policy Modules

### Module 1: User Permissions

**File**: `opa-service/policies/user_permissions.rego`

Defines which departments each user belongs to. In production, this data would come from an identity provider (LDAP, Active Directory, OIDC claims).

**Key Rules**:
- `user_departments` - Map of user names to department lists
- `has_department(user_name, department)` - Check if user belongs to department
- `get_departments(user_name)` - Retrieve all departments for a user

**Example mapping**:
```rego
user_departments := {
    "alice": ["engineering", "finance"],
    "bob": ["finance", "admin"],
    "carol": ["hr"]
}
```

See `opa-service/policies/user_permissions.rego` for the complete implementation.

---

### Module 2: Agent Capabilities

**File**: `opa-service/policies/agent_capabilities.rego`

Defines which document types/departments each AI agent can access. These represent the MAXIMUM capabilities of the agent — actual access is further restricted by user permissions via intersection.

**Current agent capabilities**:
```rego
agent_capabilities := {
    "summarizer-hr": ["hr"],
    "summarizer-tech": ["finance", "engineering"],
    "reviewer-ops": ["engineering", "admin"],
    "reviewer-general": ["engineering", "finance", "admin", "hr"],
}
```

**Key Rules**:
- `agent_capabilities` - Map of agent names to capability lists
- `has_capability(agent_name, department)` - Check if agent has a specific capability
- `get_capabilities(agent_name)` - Retrieve all capabilities for an agent

See `opa-service/policies/agent_capabilities.rego` for the complete implementation.

---

### Module 3: Document Access (Main Authorization Logic)

**File**: `opa-service/policies/document_access.rego`

Implements the core authorization logic that evaluates access requests and computes permission intersection for delegated access.

**Key Components**:

1. **Document metadata** - Maps document IDs to required departments
2. **SPIFFE ID parsing** - Extracts type (user/agent) and name from SPIFFE IDs
3. **Authorization rules**:
   - Public documents are always accessible
   - Direct user access requires user has required department
   - Agent requests without delegation are denied
   - Delegated access requires intersection contains required department

**Policy evaluation endpoint**: `POST /v1/data/demo/authorization/decision`

**Example authorization rule for delegation**:
```rego
allow {
    input.delegation
    user := parse_spiffe_id(input.delegation.user_spiffe_id)
    agent := parse_spiffe_id(input.delegation.agent_spiffe_id)

    user_depts := users.get_departments(user.name)
    agent_caps := agents.get_capabilities(agent.name)
    effective_permissions := user_depts & agent_caps

    required_dept := documents[input.document_id].required_department
    required_dept in effective_permissions
}
```

See `opa-service/policies/document_access.rego` for the complete implementation.

---

## Example Input/Output

### Example 1: Alice Direct Access to Engineering Doc

**Input**:
```json
{
  "caller_spiffe_id": "spiffe://demo.example.com/user/alice",
  "document_id": "DOC-001",
  "delegation": null
}
```

**Output**:
```json
{
  "allow": true,
  "reason": "User has required department access",
  "details": {
    "document_id": "DOC-001",
    "required_department": "engineering",
    "caller_type": "user",
    "caller_name": "alice"
  }
}
```

---

### Example 2: Summarizer-Tech Agent Without Delegation

**Input**:
```json
{
  "caller_spiffe_id": "spiffe://demo.example.com/agent/summarizer-tech",
  "document_id": "DOC-002",
  "delegation": null
}
```

**Output**:
```json
{
  "allow": false,
  "reason": "Agent requests require user delegation context",
  "details": {
    "document_id": "DOC-002",
    "required_department": "finance",
    "caller_type": "agent",
    "caller_name": "summarizer-tech"
  }
}
```

**Key Observation**: Even though the agent has the finance capability, access is denied because agents cannot act autonomously in a Zero Trust architecture.

---

### Example 3: Alice Delegates to Summarizer-Tech for Engineering Doc

**Input**:
```json
{
  "caller_spiffe_id": "spiffe://demo.example.com/agent/summarizer-tech",
  "document_id": "DOC-001",
  "delegation": {
    "user_spiffe_id": "spiffe://demo.example.com/user/alice",
    "agent_spiffe_id": "spiffe://demo.example.com/agent/summarizer-tech"
  }
}
```

**Output**:
```json
{
  "allow": true,
  "reason": "Both user and agent have required access (delegation)",
  "details": {
    "document_id": "DOC-001",
    "required_department": "engineering",
    "user": "alice",
    "agent": "summarizer-tech",
    "user_departments": ["engineering", "finance"],
    "agent_capabilities": ["finance", "engineering"],
    "effective_permissions": ["engineering", "finance"]
  }
}
```

---

### Example 4: Bob + Summarizer-HR → Admin Doc (Permission Reduction)

**Input**:
```json
{
  "caller_spiffe_id": "spiffe://demo.example.com/agent/summarizer-hr",
  "document_id": "DOC-003",
  "delegation": {
    "user_spiffe_id": "spiffe://demo.example.com/user/bob",
    "agent_spiffe_id": "spiffe://demo.example.com/agent/summarizer-hr"
  }
}
```

**Output**:
```json
{
  "allow": false,
  "reason": "Insufficient permissions",
  "details": {
    "document_id": "DOC-003",
    "required_department": "admin",
    "user": "bob",
    "agent": "summarizer-hr",
    "user_departments": ["finance", "admin"],
    "agent_capabilities": ["hr"],
    "effective_permissions": ["hr"]
  }
}
```

**Key Observation**: Even though Bob has `admin` department access, the Summarizer-HR agent only has `hr` capability. The intersection is `["hr"]`, which doesn't include `admin`, so access is denied. This demonstrates **permission reduction** through delegation — agents act as capability limiters.

---

### Example 5: Alice Delegates to Reviewer-General for All Departments

**Input**:
```json
{
  "caller_spiffe_id": "spiffe://demo.example.com/agent/reviewer-general",
  "document_id": "DOC-001",
  "delegation": {
    "user_spiffe_id": "spiffe://demo.example.com/user/alice",
    "agent_spiffe_id": "spiffe://demo.example.com/agent/reviewer-general"
  }
}
```

**Output**:
```json
{
  "allow": true,
  "reason": "Both user and agent have required access (delegation)",
  "details": {
    "document_id": "DOC-001",
    "required_department": "engineering",
    "user": "alice",
    "agent": "reviewer-general",
    "user_departments": ["engineering", "finance"],
    "agent_capabilities": ["engineering", "finance", "admin", "hr"],
    "effective_permissions": ["engineering", "finance"]
  }
}
```

**Key Observation**: The Reviewer-General agent has unrestricted capabilities (all four departments), but when Alice delegates to it, the effective permissions are still limited to Alice's departments `["engineering", "finance"]`. The intersection ensures the agent cannot exceed the user's permissions.

---

## Policy Testing

The demo includes OPA policy tests to verify correct behavior.

**File**: `opa-service/policies/document_access_test.rego`

**Test categories**:

1. **Public document access** - Verify public documents are accessible to all
2. **User direct access** - Verify users can access documents matching their departments
3. **User access denial** - Verify users cannot access documents outside their departments
4. **Agent without delegation** - Verify agents are denied without user context
5. **Delegation success** - Verify delegated access works when both have permission
6. **Delegation failure** - Verify delegation fails when agent lacks capability
7. **Permission intersection** - Verify effective permissions are correctly computed

**Running tests**:

```bash
# Run all policy tests
make test-policies

# Or use OPA CLI directly
opa test opa-service/policies/
```

**Example test case**:

```rego
# Test: Delegation fails when agent lacks capability
test_delegation_agent_lacks_capability {
    not allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/agent/summarizer-hr",
        "document_id": "DOC-003",
        "delegation": {
            "user_spiffe_id": "spiffe://demo.example.com/user/bob",
            "agent_spiffe_id": "spiffe://demo.example.com/agent/summarizer-hr"
        }
    }
}
```

See `opa-service/policies/document_access_test.rego` for the complete test suite.

---

## Reference Files

The actual policy files are the source of truth. This document provides an overview and examples, but for full implementation details, refer to:

| File | Location | Description |
| ---- | -------- | ----------- |
| User Permissions | `opa-service/policies/user_permissions.rego` | User-to-department mappings |
| Agent Capabilities | `opa-service/policies/agent_capabilities.rego` | Agent capability restrictions |
| Document Access | `opa-service/policies/document_access.rego` | Main authorization logic |
| Policy Tests | `opa-service/policies/document_access_test.rego` | OPA policy test suite |
| ConfigMap | `deploy/k8s/base/opa-policies-configmap.yaml` | Kubernetes deployment of policies |

### Policy Deployment

Policies are deployed to Kubernetes via ConfigMap:

```bash
# View deployed policies
kubectl get configmap opa-policies -n spiffe-demo -o yaml

# Update policies
kubectl apply -f deploy/k8s/base/opa-policies-configmap.yaml

# Restart OPA service to reload
kubectl rollout restart deployment/opa-service -n spiffe-demo
```

---

## Mathematical Representation

The permission intersection model can be formally expressed as:

```
Given:
  U = set of user departments
  A = set of agent capabilities
  D = required department for document

Compute:
  E = U ∩ A  (effective permissions)

Decision:
  allow iff D ∈ E
```

**Example calculations**:

1. **Alice (Eng+Fin) + Summarizer-Tech (Eng+Fin) → Engineering Doc**
   - E = {Eng, Fin} ∩ {Eng, Fin} = {Eng, Fin}
   - D = Eng
   - Eng ∈ {Eng, Fin} → **ALLOW**

2. **Bob (Fin+Admin) + Summarizer-HR (HR) → Admin Doc**
   - E = {Fin, Admin} ∩ {HR} = ∅ (empty set)
   - D = Admin
   - Admin ∉ ∅ → **DENY**

3. **Carol (HR) + Reviewer-General (Eng+Fin+Admin+HR) → HR Doc**
   - E = {HR} ∩ {Eng, Fin, Admin, HR} = {HR}
   - D = HR
   - HR ∈ {HR} → **ALLOW**

This mathematical model ensures that agents always operate with the minimum of user permissions and agent capabilities, enforcing **Least Privilege** at the policy level.

---

## Summary

The OPA policy design demonstrates Zero Trust principles for AI agent systems:

1. **Never Trust, Always Verify** - Every request is evaluated by OPA
2. **Least Privilege** - Agents reduce effective permissions via intersection
3. **Explicit Authorization** - Policy logic is declarative and auditable
4. **No Autonomous Agent Access** - Agents require user delegation context

For questions or modifications, see the Architecture Decision Records in `docs/adr/` and the main architecture document at `docs/ARCHITECTURE.md`.
