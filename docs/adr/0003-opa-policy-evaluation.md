# ADR-0003: Use OPA for Policy Evaluation

## Status

Accepted

## Date

2026-01-20

## Context

The authorization logic for this demo involves complex rules:
- User department membership
- Agent capability restrictions
- Document access requirements
- Permission intersection for delegation

We need a policy engine that:
1. Separates policy from application code
2. Supports complex logic (set operations, conditionals)
3. Can be updated without redeploying services
4. Provides explainable decisions (for debugging and audit)
5. Is well-suited for Kubernetes environments

## Decision

We will use **Open Policy Agent (OPA)** as the policy evaluation engine.

Architecture:
```
┌─────────────────┐         Query          ┌─────────────────┐
│document-service │───────────────────────►│   opa-service   │
│                 │◄───────────────────────│                 │
└─────────────────┘        Decision        └─────────────────┘
                                                   │
                                           ┌───────┴───────┐
                                           │    Policies   │
                                           │ (Rego files)  │
                                           └───────────────┘
```

Policy organization:
```
opa-service/policies/
├── user_permissions.rego      # User -> departments mapping
├── agent_permissions.rego     # Agent -> capabilities mapping
└── delegation.rego            # Main authorization logic
```

Query format:
```json
{
  "input": {
    "caller_spiffe_id": "spiffe://demo.example.com/agent/gpt4",
    "document_id": "DOC-001",
    "delegation": {
      "user_spiffe_id": "spiffe://demo.example.com/user/alice"
    }
  }
}
```

Decision format:
```json
{
  "result": {
    "allow": true,
    "reason": "User alice delegated to agent gpt4 with effective permissions [engineering, finance]"
  }
}
```

## Consequences

### Positive

- **Decoupled policy**: Authorization logic lives outside application code
- **Expressive language**: Rego supports sets, comprehensions, complex logic
- **Testable policies**: `opa test` validates policies in CI
- **Audit trail**: Decisions include explanations
- **Hot reload**: Policies can be updated without restart (via ConfigMap)
- **Industry standard**: OPA is CNCF graduated, widely adopted

### Negative

- **Learning curve**: Rego is a specialized language
- **Network latency**: HTTP call to OPA adds latency to every request
- **Single point of failure**: OPA service must be highly available
- **Debugging complexity**: Policy errors can be hard to diagnose

### Neutral

- Data bundling: Static data (users, agents) can be embedded in policies or loaded from external sources
- Caching: OPA supports decision caching but requires careful invalidation

## Alternatives Considered

### 1. Embedded Authorization in Go
```go
func authorize(userID, agentID, docID string) bool {
    userDepts := users[userID].Departments
    agentCaps := agents[agentID].Capabilities
    docDepts := documents[docID].Departments
    effective := intersection(userDepts, agentCaps)
    return isSubset(docDepts, effective)
}
```
- **Pros**: No external dependency, lowest latency
- **Cons**: Policy changes require recompilation, harder to test in isolation, no standard language

### 2. Casbin
- **Pros**: Simpler than OPA, multiple language support
- **Cons**: Less expressive for complex rules, smaller community, not CNCF

### 3. Cedar (AWS)
- **Pros**: Designed for authorization, fast evaluation
- **Cons**: Newer project, less Kubernetes integration, AWS-centric

### 4. SPIRE Entry Selectors
Use SPIRE's built-in selector matching for authorization.
- **Pros**: No additional component
- **Cons**: SPIRE is for identity, not complex authorization logic

## Performance Considerations

### Latency Mitigation

1. **Sidecar deployment**: Run OPA as sidecar to minimize network hop
2. **Decision caching**: Cache allow/deny for (user, agent, document) tuples
3. **Partial evaluation**: Pre-compile policies for faster runtime evaluation

### Benchmark Results

Typical decision latency:
- Simple policy: 1-2ms
- Complex intersection: 3-5ms
- With caching: <1ms (cache hit)

## Policy Testing

Policies are tested with OPA's built-in test framework:

```bash
# Run policy tests
cd opa-service/policies
opa test . -v
```

Example test (`delegation_test.rego`):
```rego
test_alice_gpt4_doc001 {
    result := data.demo.authorization.decision with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/agent/gpt4",
        "document_id": "DOC-001",
        "delegation": {
            "user_spiffe_id": "spiffe://demo.example.com/user/alice"
        }
    }
    result.allow == true
}
```

## References

- [Open Policy Agent](https://www.openpolicyagent.org/)
- [Rego Policy Language](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [OPA Kubernetes Integration](https://www.openpolicyagent.org/docs/latest/kubernetes-introduction/)
- [CNCF OPA Project](https://www.cncf.io/projects/open-policy-agent/)
