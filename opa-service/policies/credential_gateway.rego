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
	user_depts := users.get_departments(input.user)
	agent_caps := agents.get_capabilities(input.agent)
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
	count(users.get_departments(input.user)) > 0
	count(agents.get_capabilities(input.agent)) > 0
}

reason := sprintf("Unknown user: %s", [input.user]) if {
	not allow
	count(users.get_departments(input.user)) == 0
}

reason := sprintf("Unknown agent: %s", [input.agent]) if {
	not allow
	count(users.get_departments(input.user)) > 0
	count(agents.get_capabilities(input.agent)) == 0
}

# --- S3 proxy per-object decision ---
# Used by the credential gateway proxy endpoint.
# Looks up document departments from manifest data and checks
# whether any department is in the user-agent permission intersection.

s3_doc_departments(key) := depts if {
	some doc in data.demo.s3_documents
	doc.key == key
	depts := doc.departments
}

proxy_decision := {"allow": true, "reason": reason} if {
	depts := s3_doc_departments(input.s3_key)
	_any_dept_in_intersection(depts)
	reason := sprintf("S3 access allowed: %s (departments %v, intersection %v)",
		[input.s3_key, depts, permission_intersection])
}

proxy_decision := {"allow": false, "reason": reason} if {
	depts := s3_doc_departments(input.s3_key)
	not _any_dept_in_intersection(depts)
	reason := sprintf("S3 access denied: %s departments %v not in intersection %v",
		[input.s3_key, depts, permission_intersection])
}

proxy_decision := {"allow": false, "reason": reason} if {
	not s3_doc_departments(input.s3_key)
	reason := sprintf("Unknown S3 key: %s", [input.s3_key])
}

_any_dept_in_intersection(depts) if {
	some dept in depts
	dept in permission_intersection
}
