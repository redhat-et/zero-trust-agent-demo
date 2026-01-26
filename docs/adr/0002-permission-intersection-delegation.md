# ADR-0002: Permission Intersection for AI Agent Delegation

## Status

Accepted

## Date

2026-01-20

## Context

AI agents acting on behalf of users present a novel security challenge. When a user delegates access to an AI agent:

1. The agent should not gain more permissions than the user has
2. The agent should be constrained by its own capability limits
3. Autonomous agent access (without user delegation) should be prevented

Traditional access control models don't address this delegation scenario well:
- **RBAC**: Roles are static, no delegation concept
- **ABAC**: Attributes can express delegation, but no standard pattern
- **OAuth scopes**: User-centric, doesn't constrain the acting party

Real-world example:
- Alice has access to: engineering, finance
- GPT-4 agent is capable of: engineering, finance
- Claude agent is capable of: engineering, finance, admin, hr

If Alice delegates to GPT-4, GPT-4 should access: engineering, finance
If Alice delegates to Claude, Claude should access: engineering, finance (NOT admin, hr)

## Decision

We will implement **Permission Intersection** as the authorization model:

```
Effective Permissions = User Departments ∩ Agent Capabilities
```

This is enforced in OPA policy (`delegation.rego`):

```rego
# Get user's departments
user_departments := data.users[user_id].departments

# Get agent's allowed departments
agent_capabilities := data.agents[agent_id].allowed_departments

# Intersection: only departments in BOTH sets
effective_permissions := user_departments & agent_capabilities

# Document access requires document's department in effective permissions
allow {
    document_departments := data.documents[document_id].required_departments
    count(document_departments - effective_permissions) == 0
}
```

Key rules:
1. Users accessing directly use their full permissions
2. Agents MUST have a `delegation.user_spiffe_id` to access anything
3. Delegated access uses the intersection of user and agent permissions
4. Agents without delegation context are denied (no autonomous access)

## Consequences

### Positive

- **Least privilege**: Agents never exceed user OR agent permissions
- **Defense in depth**: Even if agent is compromised, blast radius is limited
- **Explicit delegation**: Clear audit trail of who delegated to whom
- **Flexible agent design**: Agents can be constrained independent of users

### Negative

- **Reduced agent utility**: Highly restricted agents may be less useful
- **Configuration burden**: Must maintain both user and agent permission sets
- **Potential confusion**: Users may not understand why agent can't access something they can

### Neutral

- Need to decide how to handle edge cases (e.g., agent with no capabilities)
- Intersection could be extended to other attributes (time, location, etc.)

## Alternatives Considered

### 1. Agent Inherits User Permissions
```
Effective Permissions = User Departments
```
- **Pros**: Simple, agents are just as capable as users
- **Cons**: No agent-level restrictions, violates principle of least privilege for agents

### 2. Agent Uses Only Own Permissions (Ignoring User)
```
Effective Permissions = Agent Capabilities
```
- **Pros**: Simple agent configuration
- **Cons**: Agent could access things user cannot, violates delegation trust model

### 3. Union of Permissions
```
Effective Permissions = User Departments ∪ Agent Capabilities
```
- **Pros**: Maximum flexibility
- **Cons**: Privilege escalation - agent could grant user access to things they shouldn't have

### 4. Explicit Delegation Scopes
User specifies exactly what they're delegating:
```json
{
  "delegate_to": "gpt4",
  "scopes": ["engineering"]
}
```
- **Pros**: Fine-grained user control
- **Cons**: User burden, potential for error, complex UX

## Examples

### Example 1: Normal Delegation
- **User**: Alice (engineering, finance)
- **Agent**: GPT-4 (engineering, finance)
- **Document**: DOC-005 (engineering, finance)
- **Effective**: {engineering, finance} ∩ {engineering, finance} = {engineering, finance}
- **Result**: ALLOW

### Example 2: Agent More Restricted Than User
- **User**: Bob (finance, admin)
- **Agent**: Summarizer (finance only)
- **Document**: DOC-003 (admin)
- **Effective**: {finance, admin} ∩ {finance} = {finance}
- **Result**: DENY (admin not in effective permissions)

### Example 3: User More Restricted Than Agent
- **User**: Carol (hr only)
- **Agent**: Claude (engineering, finance, admin, hr)
- **Document**: DOC-001 (engineering)
- **Effective**: {hr} ∩ {engineering, finance, admin, hr} = {hr}
- **Result**: DENY (engineering not in effective permissions)

### Example 4: Agent Without Delegation
- **Agent**: GPT-4 (engineering, finance)
- **Document**: DOC-001 (engineering)
- **Delegation**: None
- **Result**: DENY (agents require delegation context)

## References

- [The Principle of Least Privilege](https://www.cisa.gov/uscert/bsi/articles/knowledge/principles/least-privilege)
- [OAuth 2.0 Token Exchange (RFC 8693)](https://datatracker.ietf.org/doc/html/rfc8693)
- [SPIFFE Federation](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/#federation)
