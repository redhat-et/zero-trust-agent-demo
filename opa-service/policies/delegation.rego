package demo.authorization

import rego.v1

import data.demo.agents
import data.demo.users

# Document metadata is now passed in input.document_metadata
# Expected structure:
# {
#   "required_department": "engineering",      # Single department OR
#   "required_departments": ["finance", "hr"], # Multiple departments
#   "sensitivity": "medium"
# }

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

# Get required departments from document metadata (handles both single and multiple)
get_required_departments := deps if {
    deps := input.document_metadata.required_departments
} else := [dep] if {
    dep := input.document_metadata.required_department
    dep != ""
} else := []

# Helper: Check if document is public (no required departments)
is_public_document if {
    required := get_required_departments
    count(required) == 0
}

# Check if a set of permissions satisfies document requirements
has_any_required_department(permissions) if {
    is_public_document
}

has_any_required_department(permissions) if {
    required := get_required_departments
    some dept in required
    dept in permissions
}

# MAIN DECISION RULE: Allow access based on request type

default allow := false

# Rule 1: Public documents are always accessible
allow if {
    is_public_document
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
    has_any_required_department(user_depts)
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
    has_any_required_department(effective)
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
    is_public_document
}

# Reason for direct user access (but not for public documents)
reason := "User has required department access" if {
    allow
    not input.delegation
    caller := parse_spiffe_id(input.caller_spiffe_id)
    caller.type == "user"
    not is_public_document
}

# Reason for delegated access (but not for public documents)
reason := "Both user and agent have required access (delegation)" if {
    allow
    input.delegation
    not is_public_document
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
    "required_departments": get_required_departments,
    "caller_type": parse_spiffe_id(input.caller_spiffe_id).type,
    "caller_name": parse_spiffe_id(input.caller_spiffe_id).name
} if {
    not input.delegation
}

# Details for delegated requests
details := {
    "document_id": input.document_id,
    "required_departments": get_required_departments,
    "user": parse_spiffe_id(input.delegation.user_spiffe_id).name,
    "agent": parse_spiffe_id(input.delegation.agent_spiffe_id).name,
    "user_departments": users.get_departments(parse_spiffe_id(input.delegation.user_spiffe_id).name),
    "agent_capabilities": agents.get_capabilities(parse_spiffe_id(input.delegation.agent_spiffe_id).name),
    "effective_permissions": effective_permissions
} if {
    input.delegation
}
