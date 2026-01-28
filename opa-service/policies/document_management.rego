package demo.authorization.management

import rego.v1

import data.demo.users

# Document management (CRUD) operations require admin department
# Only users with admin department can create, update, or delete documents

# Parse SPIFFE ID to extract type and name
parse_spiffe_id(spiffe_id) := result if {
    parts := split(spiffe_id, "/")
    count(parts) >= 2
    result := {
        "type": parts[count(parts) - 2],
        "name": parts[count(parts) - 1]
    }
}

# Default deny
default allow_manage := false

# Allow management operations for admin users
allow_manage if {
    caller := parse_spiffe_id(input.caller_spiffe_id)
    caller.type == "user"
    user_depts := users.get_departments(caller.name)
    "admin" in user_depts
}

# Reason for management decision
reason := "User has admin department access" if {
    allow_manage
}

reason := "Management operations require admin department" if {
    not allow_manage
}

# Decision with reasoning
decision := {
    "allow": allow_manage,
    "reason": reason
}
