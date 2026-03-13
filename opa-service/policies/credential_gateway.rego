package demo.credential_gateway

import rego.v1

import data.demo.agents
import data.demo.users

# Credential Gateway policy: compute permission permission_intersection for
# service-specific credential scoping.
#
# Input:
#   {
#     "user": "alice",
#     "agent": "summarizer",
#     "target_service": "s3",
#     "action": "read"
#   }
#
# Output:
#   {
#     "allow": true,
#     "allowed_departments": ["finance"],
#     "reason": "..."
#   }

default allow := false

# Compute the permission_intersection of user departments and agent capabilities
permission_intersection := result if {
	user_depts := users.user_departments_fallback[input.user]
	agent_caps := agents.agent_capabilities[input.agent]
	result := [d | some d in user_depts; d in agent_caps]
}

# Allow if permission_intersection is non-empty
allow if {
	count(permission_intersection) > 0
}

# Decision result
decision := {
	"allow": allow,
	"allowed_departments": allowed_departments,
	"reason": reason,
}

# Allowed departments from the permission_intersection
allowed_departments := permission_intersection if {
	allow
}

allowed_departments := [] if {
	not allow
}

# Reason messages
reason := sprintf("Intersection of %s's departments and %s's capabilities: %v", [input.user, input.agent, permission_intersection]) if {
	allow
}

reason := sprintf("No overlapping permissions between %s and %s", [input.user, input.agent]) if {
	not allow
	users.user_departments_fallback[input.user]
	agents.agent_capabilities[input.agent]
}

reason := sprintf("Unknown user: %s", [input.user]) if {
	not allow
	not users.user_departments_fallback[input.user]
}

reason := sprintf("Unknown agent: %s", [input.agent]) if {
	not allow
	users.user_departments_fallback[input.user]
	not agents.agent_capabilities[input.agent]
}
