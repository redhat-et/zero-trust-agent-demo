package demo.users

import future.keywords.in
import future.keywords.if

# User-to-department mappings
# In production, this would come from an identity provider (LDAP, AD, OIDC claims)

user_departments := {
    "alice": ["engineering", "finance"],
    "bob": ["finance", "admin"],
    "carol": ["hr"]
}

# Helper rule: Check if a user belongs to a specific department
has_department(user_name, department) if {
    department_list := user_departments[user_name]
    department in department_list
}

# Helper rule: Get all departments for a user
get_departments(user_name) := departments if {
    departments := user_departments[user_name]
}

# Default: unknown users have no departments
get_departments(user_name) := [] if {
    not user_departments[user_name]
}
