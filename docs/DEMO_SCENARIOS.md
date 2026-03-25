# Demo Scenarios — Zero Trust Agent Access Control

This document describes the demo scenarios for the SPIFFE/SPIRE Zero Trust
Agent Demo. It shows how users, AI agents, and documents interact through
policy-based access control with permission intersection.

## Table of Contents

1. [Overview](#overview)
2. [Users](#users)
3. [AI Agents](#ai-agents)
4. [Documents](#documents)
5. [Permission Matrices](#permission-matrices)
6. [Scenario Examples](#scenario-examples)

---

## Overview

The demo simulates a document management system where:

- **Users** have department-based access rights
- **AI Agents** have capability-based restrictions (dynamically discovered from Kagenti AgentCard CRs)
- **Delegation** requires permission intersection (user AND agent must both have access)
- **Every request** is authenticated via mTLS and authorized via OPA policies

**Core Principle**: When a user delegates access to an AI agent:

```text
Effective Permissions = User Departments ∩ Agent Capabilities
```

This ensures agents can never exceed the permissions of either the user OR the agent's configured capabilities.

---

## Users

| User  | Departments          | SPIFFE ID                              |
| ----- | -------------------- | -------------------------------------- |
| Alice | Engineering, Finance | `spiffe://demo.example.com/user/alice` |
| Bob   | Finance, Admin       | `spiffe://demo.example.com/user/bob`   |
| Carol | HR                   | `spiffe://demo.example.com/user/carol` |

---

## AI Agents

Agents are dynamically discovered from Kagenti AgentCard CRs. The naming
scheme is `{function}-{scope}`.

| Agent            | Scope                | Description                   | SPIFFE ID                                          |
| ---------------- | -------------------- | ----------------------------- | -------------------------------------------------- |
| summarizer-hr    | hr                   | HR document summarizer        | `spiffe://demo.example.com/agent/summarizer-hr`    |
| summarizer-tech  | finance, engineering | Technical document summarizer | `spiffe://demo.example.com/agent/summarizer-tech`  |
| reviewer-ops     | engineering, admin   | Operations document reviewer  | `spiffe://demo.example.com/agent/reviewer-ops`     |
| reviewer-general | all                  | General document reviewer     | `spiffe://demo.example.com/agent/reviewer-general` |

**Notes**:

- The actual agents deployed may vary based on available AgentCard
  CRs in the cluster. These are representative examples.
- The trust domain `demo.example.com` is used in local/mock mode.
  In a real cluster the trust domain is derived from the cluster
  domain name (e.g., `apps.ocp-beta-test.nerc.mghpcc.org`). SPIFFE
  IDs will follow the cluster's format accordingly.

---

## Documents

Documents are identified by ID (e.g., DOC-001) and stored either in-memory
or in S3. Each document requires specific department access.

| Document ID | Title               | Required Department(s) | Sensitivity |
| ----------- | ------------------- | ---------------------- | ----------- |
| DOC-001     | Engineering Roadmap | engineering            | Medium      |
| DOC-002     | Q4 Financial Report | finance                | High        |
| DOC-003     | Admin Policies      | admin                  | Critical    |
| DOC-004     | HR Guidelines       | hr                     | Medium      |
| DOC-005     | Budget Projections  | finance, engineering   | High        |
| DOC-006     | Compliance Audit    | admin, finance         | Critical    |
| DOC-007     | All-Hands Summary   | (public)               | Public      |

---

## Permission Matrices

### Direct User Access (No Agent)

|       | DOC-001 (Eng) | DOC-002 (Fin) | DOC-003 (Admin) | DOC-004 (HR) | DOC-007 (Public) |
| ----- | ------------- | ------------- | --------------- | ------------ | ---------------- |
| Alice | ✅ Has Eng     | ✅ Has Fin     | ❌ No Admin      | ❌ No HR      | ✅ Public         |
| Bob   | ❌ No Eng      | ✅ Has Fin     | ✅ Has Admin     | ❌ No HR      | ✅ Public         |
| Carol | ❌ No Eng      | ❌ No Fin      | ❌ No Admin      | ✅ Has HR     | ✅ Public         |

### Agent Direct Access (No User Delegation)

All agents require user delegation context. Autonomous agent access is denied.

|                  | DOC-001 | DOC-002 | DOC-003 | DOC-004 | DOC-007 |
| ---------------- | ------- | ------- | ------- | ------- | ------- |
| summarizer-hr    | ❌       | ❌       | ❌       | ❌       | ❌       |
| summarizer-tech  | ❌       | ❌       | ❌       | ❌       | ❌       |
| reviewer-ops     | ❌       | ❌       | ❌       | ❌       | ❌       |
| reviewer-general | ❌       | ❌       | ❌       | ❌       | ❌       |

**Key Principle**: Agents CANNOT access resources without user delegation context.

### Delegated Access: Alice + Agent

|                          | DOC-001 (Eng) | DOC-002 (Fin) | DOC-003 (Admin) | DOC-004 (HR)  | DOC-007 (Public) |
| ------------------------ | ------------- | ------------- | --------------- | ------------- | ---------------- |
| Alice + summarizer-hr    | ❌ Agent lacks | ❌ Agent lacks | ❌ Both lack     | ❌ Alice lacks | ✅ Public         |
| Alice + summarizer-tech  | ✅ Both allow  | ✅ Both allow  | ❌ Both lack     | ❌ Both lack   | ✅ Public         |
| Alice + reviewer-ops     | ✅ Both allow  | ❌ Agent lacks | ❌ Agent lacks   | ❌ Both lack   | ✅ Public         |
| Alice + reviewer-general | ✅ Both allow  | ✅ Both allow  | ❌ Alice lacks   | ❌ Alice lacks | ✅ Public         |

### Delegated Access: Bob + Agent

|                        | DOC-001 (Eng) | DOC-002 (Fin) | DOC-003 (Admin) | DOC-004 (HR) | DOC-007 (Public) |
| ---------------------- | ------------- | ------------- | --------------- | ------------ | ---------------- |
| Bob + summarizer-hr    | ❌ Both lack   | ❌ Agent lacks | ❌ Agent lacks   | ❌ Bob lacks  | ✅ Public         |
| Bob + summarizer-tech  | ❌ Bob lacks   | ✅ Both allow  | ❌ Agent lacks   | ❌ Both lack  | ✅ Public         |
| Bob + reviewer-ops     | ❌ Bob lacks   | ❌ Agent lacks | ✅ Both allow    | ❌ Both lack  | ✅ Public         |
| Bob + reviewer-general | ❌ Bob lacks   | ✅ Both allow  | ✅ Both allow    | ❌ Bob lacks  | ✅ Public         |

### Delegated Access: Carol + Agent

|                          | DOC-001 (Eng) | DOC-002 (Fin) | DOC-003 (Admin) | DOC-004 (HR)  | DOC-007 (Public) |
| ------------------------ | ------------- | ------------- | --------------- | ------------- | ---------------- |
| Carol + summarizer-hr    | ❌ Both lack   | ❌ Both lack   | ❌ Both lack     | ✅ Both allow  | ✅ Public         |
| Carol + summarizer-tech  | ❌ Both lack   | ❌ Carol lacks | ❌ Both lack     | ❌ Agent lacks | ✅ Public         |
| Carol + reviewer-ops     | ❌ Both lack   | ❌ Both lack   | ❌ Carol lacks   | ❌ Agent lacks | ✅ Public         |
| Carol + reviewer-general | ❌ Carol lacks | ❌ Carol lacks | ❌ Carol lacks   | ✅ Both allow  | ✅ Public         |

---

## Scenario Examples

### Scenario 1: Alice Direct Access (No Agent)

**Action**: Alice accesses DOC-001 (Engineering Roadmap) directly

**Expected Outcome**: ✅ **SUCCESS**

- Alice has Engineering department permissions
- Document requires Engineering
- No agent involved, so no permission intersection needed
- OPA evaluates: `user_has_department("alice", "engineering")` → true

**Console Output**:

```text
[USER-SERVICE] Alice fetching SVID from SPIRE Agent...
[SPIRE-AGENT] Issued SVID: spiffe://demo.example.com/user/alice
[USER-SERVICE] Initiating mTLS connection to Document Service...
[mTLS] Handshake successful - Peer: spiffe://demo.example.com/service/document-service
[DOCUMENT-SERVICE] Received request for DOC-001 from alice
[OPA-QUERY] Evaluating policy for user=alice, document=DOC-001, agent=none
[OPA-DECISION] ALLOW: User has Engineering department access
[DOCUMENT-SERVICE] Returning document content to alice
```

---

### Scenario 2: Agent Without User Delegation

**Action**: summarizer-tech attempts to access DOC-002 (Q4 Financial Report) without user context

**Expected Outcome**: ❌ **DENIED**

- Agent has finance and engineering capabilities
- But no user delegation context provided
- OPA policy requires user context for agent requests
- Demonstrates "agents cannot act autonomously"

**Console Output**:

```text
[AGENT-SERVICE] summarizer-tech fetching SVID from SPIRE Agent...
[SPIRE-AGENT] Issued SVID: spiffe://demo.example.com/agent/summarizer-tech
[AGENT-SERVICE] Initiating mTLS connection to Document Service...
[mTLS-HANDSHAKE] Handshake complete
[DOCUMENT-SERVICE] Received request for DOC-002 from agent/summarizer-tech
[OPA-QUERY] Evaluating policy for agent=summarizer-tech, document=DOC-002, user=NONE
[OPA-DECISION] DENY: Agent requests require user delegation context
[DOCUMENT-SERVICE] Access denied: 403 Forbidden

ZERO TRUST PRINCIPLE: AI agents CANNOT access resources autonomously.
They must operate within the context of a delegating user.
```

---

### Scenario 3: Alice Delegates to summarizer-tech

**Action**: Alice delegates to summarizer-tech to access DOC-001 (Engineering Roadmap)

**Expected Outcome**: ✅ **SUCCESS**

- Alice has Engineering department (✓)
- summarizer-tech has Engineering capability (✓)
- Permission intersection: [Engineering, Finance] ∩ [Engineering, Finance] = [Engineering, Finance] (✓)
- Document requires Engineering (✓)
- OPA evaluates: `alice.allow AND summarizer-tech.allow` → true

**Console Output**:

```text
[USER-SERVICE] Alice initiating delegation to summarizer-tech...
[USER-SERVICE] Fetched SVID for alice: spiffe://demo.example.com/user/alice
[AGENT-SERVICE] summarizer-tech accepting delegation from alice...
[AGENT-SERVICE] Fetched SVID for summarizer-tech: spiffe://demo.example.com/agent/summarizer-tech
[AGENT-SERVICE] Making delegated request to Document Service...
[mTLS] Handshake successful - Peer: spiffe://demo.example.com/service/document-service
[DOCUMENT-SERVICE] Received delegated request:
    User: alice (spiffe://demo.example.com/user/alice)
    Agent: summarizer-tech (spiffe://demo.example.com/agent/summarizer-tech)
    Document: DOC-001
[OPA-QUERY] Evaluating delegation policy...
    User permissions: [engineering, finance]
    Agent capabilities: [engineering, finance]
    Effective permissions: [engineering, finance]  (intersection)
    Document requirement: engineering
[OPA-DECISION] ALLOW: Both user and agent have Engineering access
[DOCUMENT-SERVICE] Returning document content

PERMISSION INTERSECTION: Both Alice and summarizer-tech have Engineering access.
Effective permissions = User ∩ Agent = [engineering, finance]
```

---

### Scenario 4: Alice + summarizer-tech → Admin Document

**Action**: Alice delegates to summarizer-tech to access DOC-003 (Admin Policies)

**Expected Outcome**: ❌ **DENIED**

- Alice does NOT have Admin department (✗)
- summarizer-tech does NOT have Admin capability (✗)
- Permission intersection: [Engineering, Finance] ∩ [Engineering, Finance] = [Engineering, Finance]
- Document requires Admin
- Demonstrates "neither user nor agent has permission"

**Console Output**:

```text
[USER-SERVICE] Alice initiating delegation to summarizer-tech...
[USER-SERVICE] Fetched SVID for alice
[AGENT-SERVICE] summarizer-tech accepting delegation from alice...
[AGENT-SERVICE] Fetched SVID for summarizer-tech
[AGENT-SERVICE] Making delegated request to Document Service...
[mTLS-HANDSHAKE] Handshake complete
[DOCUMENT-SERVICE] Received delegated request for DOC-003
[OPA-QUERY] Evaluating delegation policy...
    User permissions: [engineering, finance]
    Agent capabilities: [engineering, finance]
    Effective permissions: [engineering, finance]
    Document requirement: admin
[OPA-DECISION] DENY: Neither user nor agent has Admin access
[DOCUMENT-SERVICE] Access denied: 403 Forbidden
```

---

### Scenario 5: Bob + summarizer-tech (Permission Reduction)

**Action**: Bob delegates to summarizer-tech to scan multiple documents

**Expected Outcome**: **PARTIAL ACCESS** (demonstrates permission reduction)

- Bob has Finance + Admin departments (2 departments)
- summarizer-tech has Finance + Engineering capabilities (2 departments)
- Permission intersection: [Finance, Admin] ∩ [Finance, Engineering] = [Finance] only
- Bob could access 3 documents alone (DOC-002, DOC-003, DOC-007)
- With summarizer-tech, can only access 2 documents (DOC-002, DOC-007)
- Demonstrates "agent acts as capability limiter"

**Console Output**:

```text
[USER-SERVICE] Bob initiating delegation to summarizer-tech...
[USER-SERVICE] Bob's permissions: [finance, admin] → Could access 3 documents alone
[AGENT-SERVICE] summarizer-tech accepting delegation from Bob...
[AGENT-SERVICE] summarizer-tech capabilities: [finance, engineering]
[OPA-QUERY] Permission intersection: [finance, admin] ∩ [finance, engineering] = [finance]
[AGENT-SERVICE] Scanning documents...

Checking DOC-001 (Engineering Roadmap)...
DENY: Effective permissions [finance] lacks engineering (even though agent has it!)

Checking DOC-002 (Q4 Financial Report)...
ALLOW: Effective permissions [finance] includes finance

Checking DOC-003 (Admin Policies)...
DENY: Effective permissions [finance] lacks admin (even though Bob has it!)

Checking DOC-004 (HR Guidelines)...
DENY: Effective permissions [finance] lacks hr

Checking DOC-007 (All-Hands Summary)...
ALLOW: Public document

[SUMMARY] Agent accessed 2/5 documents (vs Bob's 3/5 direct access)
[PRINCIPLE] Agent capabilities REDUCE effective permissions (Least Privilege)

Permission Comparison:
┌────────────────┬──────────────┬────────────────────┐
│ Document       │ Bob Direct   │ Bob + summarizer   │
├────────────────┼──────────────┼────────────────────┤
│ DOC-001 (Eng)  │ ❌ No Eng     │ ❌ Not in ∩       │
│ DOC-002 (Fin)  │ ✅ Has Fin    │ ✅ Both have Fin  │
│ DOC-003 (Admin)│ ✅ Has Admin  │ ❌ Not in ∩       │
│ DOC-004 (HR)   │ ❌ No HR      │ ❌ Neither has HR │
│ DOC-007 (Pub)  │ ✅ Public     │ ✅ Public         │
├────────────────┼──────────────┼────────────────────┤
│ TOTAL ACCESS   │ 3/5 docs     │ 2/5 docs (REDUCED) │
└────────────────┴──────────────┴────────────────────┘

LEAST PRIVILEGE PRINCIPLE:
Bob has 'admin' access directly, but summarizer-tech does not.
When Bob delegates to summarizer-tech, the effective permissions are REDUCED
to only the intersection of their capabilities ([finance]).

This demonstrates that agents act as CAPABILITY LIMITERS, enforcing
least privilege even when users have broader permissions.
```

---

## Key Takeaways

1. **No Autonomous Agent Access**: All agent requests require user delegation
2. **Permission Intersection**: Effective permissions = User ∩ Agent
3. **Capability Limiting**: Agents can reduce user permissions, never expand them
4. **Every Request Verified**: mTLS authentication + OPA authorization on every call
5. **Zero Trust**: Never trust, always verify — no implicit trust based on network location

---

## Related Documentation

- **Architecture**: `/docs/ARCHITECTURE.md` — Full system design
- **OPA Policies**: `/opa-service/policies/delegation.rego` — Policy implementation
- **Kagenti Integration**: `/docs/dev/KAGENTI_S3_AGENTS_DESIGN.md` — Dynamic agent discovery
