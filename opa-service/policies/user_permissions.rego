package demo.users

import rego.v1

# User-to-department mappings (fallback)
# In production, prefer JWT claims from OIDC provider
user_departments_fallback := {
    "alice": ["engineering", "finance"],
    "bob": ["finance", "admin"],
    "carol": ["hr"],
    "david": ["engineering", "hr"]
}

# Helper rule: Check if a user belongs to a specific department
has_department(user_name, department) if {
    department_list := get_departments(user_name)
    department in department_list
}

# Helper rule: Get all departments for a user
# Priority:
# 1. input.user_departments (direct JWT claims from dashboard)
# 2. input.delegation.user_departments (JWT claims via delegation)
# 3. Fallback to hardcoded mappings (for local/mock mode)

# Rule 1: Use JWT claims from direct access request
get_departments(_) := departments if {
    not input.delegation
    departments := input.user_departments
    count(departments) > 0
}

# Rule 2: Use JWT claims from delegation context
get_departments(_) := departments if {
    input.delegation
    departments := input.delegation.user_departments
    count(departments) > 0
}

# Rule 3: Use top-level user_departments even with delegation (fallback)
get_departments(_) := departments if {
    input.delegation
    not input.delegation.user_departments
    departments := input.user_departments
    count(departments) > 0
}

# Rule 4: Fallback to hardcoded mappings
get_departments(user_name) := departments if {
    # Only use fallback if no JWT claims provided
    not jwt_claims_provided
    departments := user_departments_fallback[user_name]
}

# Rule 5: Default for unknown users (no JWT claims, not in fallback)
get_departments(user_name) := [] if {
    not jwt_claims_provided
    not user_departments_fallback[user_name]
}

# Helper: Check if JWT claims were provided
jwt_claims_provided if {
    input.user_departments
    count(input.user_departments) > 0
}

jwt_claims_provided if {
    input.delegation.user_departments
    count(input.delegation.user_departments) > 0
}
