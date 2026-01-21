package demo.authorization

import data.demo.users
import data.demo.agents
import future.keywords.in
import future.keywords.if

# Document metadata - 7 sample documents
documents := {
    "DOC-001": {
        "title": "Engineering Roadmap",
        "required_department": "engineering",
        "sensitivity": "medium"
    },
    "DOC-002": {
        "title": "Q4 Financial Report",
        "required_department": "finance",
        "sensitivity": "high"
    },
    "DOC-003": {
        "title": "Admin Policies",
        "required_department": "admin",
        "sensitivity": "critical"
    },
    "DOC-004": {
        "title": "HR Guidelines",
        "required_department": "hr",
        "sensitivity": "medium"
    },
    "DOC-005": {
        "title": "Budget Projections",
        "required_departments": ["finance", "engineering"],
        "sensitivity": "high"
    },
    "DOC-006": {
        "title": "Compliance Audit",
        "required_departments": ["admin", "finance"],
        "sensitivity": "critical"
    },
    "DOC-007": {
        "title": "All-Hands Summary",
        "required_department": "",  # No requirement - public
        "sensitivity": "public"
    }
}

# Parse SPIFFE ID to extract type and name
# Example: spiffe://demo.example.com/user/alice -> {type: "user", name: "alice"}
parse_spiffe_id(spiffe_id) := result if {
    parts := split(spiffe_id, "/")
    count(parts) >= 2
    result := {
        "type": parts[count(parts) - 2],
        "name": parts[count(parts) - 1]
    }
}

# Get required departments for a document (handles both single and multiple)
get_required_departments(doc_id) := deps if {
    doc := documents[doc_id]
    deps := doc.required_departments
} else := [dep] if {
    doc := documents[doc_id]
    dep := doc.required_department
    dep != ""
} else := []

# Helper: Check if document is public (no required departments)
is_public_document(doc_id) if {
    required := get_required_departments(doc_id)
    count(required) == 0
}

# Check if a set of permissions satisfies document requirements
has_any_required_department(permissions, doc_id) if {
    is_public_document(doc_id)
}

has_any_required_department(permissions, doc_id) if {
    required := get_required_departments(doc_id)
    some dept in required
    dept in permissions
}

# MAIN DECISION RULE: Allow access based on request type

default allow := false

# Rule 1: Public documents are always accessible
allow if {
    doc := documents[input.document_id]
    doc.required_department == ""
}

# Rule 2: Direct user access (no agent delegation)
allow if {
    # No delegation context provided
    not input.delegation

    # Parse caller SPIFFE ID
    caller := parse_spiffe_id(input.caller_spiffe_id)
    caller.type == "user"

    # Get user departments
    user_depts := users.get_departments(caller.name)

    # Check if user has any required department
    has_any_required_department(user_depts, input.document_id)
}

# Rule 3: Delegated access (user delegates to agent)
allow if {
    # Delegation context is provided
    input.delegation

    # Parse identities
    user := parse_spiffe_id(input.delegation.user_spiffe_id)
    agent := parse_spiffe_id(input.delegation.agent_spiffe_id)

    user.type == "user"
    agent.type == "agent"

    # Get user departments and agent capabilities
    user_depts := users.get_departments(user.name)
    agent_caps := agents.get_capabilities(agent.name)

    # Compute intersection (effective permissions)
    effective := {d | some d in user_depts; d in agent_caps}

    # Check if effective permissions satisfy document requirements
    has_any_required_department(effective, input.document_id)
}

# Explicit deny reason for agents without delegation
deny_reason := "Agent requests require user delegation context" if {
    not input.delegation
    caller := parse_spiffe_id(input.caller_spiffe_id)
    caller.type == "agent"
}

# Helper rule: Compute effective permissions for delegation
effective_permissions := result if {
    input.delegation
    user := parse_spiffe_id(input.delegation.user_spiffe_id)
    agent := parse_spiffe_id(input.delegation.agent_spiffe_id)

    user_depts := users.get_departments(user.name)
    agent_caps := agents.get_capabilities(agent.name)

    result := [d | some d in user_depts; d in agent_caps]
}

# Detailed decision with reasoning
decision := {
    "allow": allow,
    "reason": reason,
    "details": details
}

# Reason for public access
reason := "Public document accessible to all" if {
    allow
    is_public_document(input.document_id)
}

# Reason for direct user access (but not for public documents)
reason := "User has required department access" if {
    allow
    not input.delegation
    caller := parse_spiffe_id(input.caller_spiffe_id)
    caller.type == "user"
    not is_public_document(input.document_id)
}

# Reason for delegated access (but not for public documents)
reason := "Both user and agent have required access (delegation)" if {
    allow
    input.delegation
    not is_public_document(input.document_id)
}

# Reason for denial
reason := deny_reason if {
    not allow
    deny_reason
}

reason := "Insufficient permissions" if {
    not allow
    not deny_reason
}

# Details for non-delegated requests
details := {
    "document_id": input.document_id,
    "required_departments": get_required_departments(input.document_id),
    "caller_type": parse_spiffe_id(input.caller_spiffe_id).type,
    "caller_name": parse_spiffe_id(input.caller_spiffe_id).name
} if {
    not input.delegation
}

# Details for delegated requests
details := {
    "document_id": input.document_id,
    "required_departments": get_required_departments(input.document_id),
    "user": parse_spiffe_id(input.delegation.user_spiffe_id).name,
    "agent": parse_spiffe_id(input.delegation.agent_spiffe_id).name,
    "user_departments": users.get_departments(parse_spiffe_id(input.delegation.user_spiffe_id).name),
    "agent_capabilities": agents.get_capabilities(parse_spiffe_id(input.delegation.agent_spiffe_id).name),
    "effective_permissions": effective_permissions
} if {
    input.delegation
}
