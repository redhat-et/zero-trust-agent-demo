package demo.authorization

import rego.v1

# Test document metadata fixtures
doc_engineering := {"required_department": "engineering", "sensitivity": "medium"}
doc_finance := {"required_department": "finance", "sensitivity": "high"}
doc_admin := {"required_department": "admin", "sensitivity": "critical"}
doc_hr := {"required_department": "hr", "sensitivity": "medium"}
doc_public := {"required_department": "", "sensitivity": "public"}
doc_finance_engineering := {"required_departments": ["finance", "engineering"], "sensitivity": "high"}

# Test: Public documents are always accessible
test_public_document_access if {
    allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/user/alice",
        "document_id": "DOC-007",
        "document_metadata": doc_public
    }
}

# Test: User with correct department can access
test_user_direct_access_allowed if {
    allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/user/alice",
        "document_id": "DOC-001",
        "document_metadata": doc_engineering
    }
}

# Test: User without correct department cannot access
test_user_direct_access_denied if {
    not allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/user/alice",
        "document_id": "DOC-003",
        "document_metadata": doc_admin
    }
}

# Test: Agent without user delegation is denied
test_agent_without_delegation_denied if {
    not allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/agent/summarizer-tech",
        "document_id": "DOC-002",
        "document_metadata": doc_finance
    }
}

# Test: Alice + summarizer-tech can access engineering (both have eng)
test_delegation_both_allowed if {
    allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/agent/summarizer-tech",
        "document_id": "DOC-001",
        "document_metadata": doc_engineering,
        "delegation": {
            "user_spiffe_id": "spiffe://demo.example.com/user/alice",
            "agent_spiffe_id": "spiffe://demo.example.com/agent/summarizer-tech"
        }
    }
}

# Test: Delegation fails when agent lacks capability (summarizer-hr is hr-only)
test_delegation_agent_lacks_capability if {
    not allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/agent/summarizer-hr",
        "document_id": "DOC-003",
        "document_metadata": doc_admin,
        "delegation": {
            "user_spiffe_id": "spiffe://demo.example.com/user/bob",
            "agent_spiffe_id": "spiffe://demo.example.com/agent/summarizer-hr"
        }
    }
}

# Test: Bob can access admin directly
test_bob_admin_direct if {
    allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/user/bob",
        "document_id": "DOC-003",
        "document_metadata": doc_admin
    }
}

# Test: Carol can access HR
test_carol_hr_access if {
    allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/user/carol",
        "document_id": "DOC-004",
        "document_metadata": doc_hr
    }
}

# Test: Bob + reviewer-ops can access admin (both have admin)
test_bob_reviewer_admin if {
    allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/agent/reviewer-ops",
        "document_id": "DOC-003",
        "document_metadata": doc_admin,
        "delegation": {
            "user_spiffe_id": "spiffe://demo.example.com/user/bob",
            "agent_spiffe_id": "spiffe://demo.example.com/agent/reviewer-ops"
        }
    }
}

# Test: Carol + summarizer-hr CAN access HR (both have hr)
test_carol_summarizer_hr if {
    allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/agent/summarizer-hr",
        "document_id": "DOC-004",
        "document_metadata": doc_hr,
        "delegation": {
            "user_spiffe_id": "spiffe://demo.example.com/user/carol",
            "agent_spiffe_id": "spiffe://demo.example.com/agent/summarizer-hr"
        }
    }
}

# Test: Alice + summarizer-hr cannot access engineering (summarizer-hr is hr-only)
test_alice_summarizer_no_engineering if {
    not allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/agent/summarizer-hr",
        "document_id": "DOC-001",
        "document_metadata": doc_engineering,
        "delegation": {
            "user_spiffe_id": "spiffe://demo.example.com/user/alice",
            "agent_spiffe_id": "spiffe://demo.example.com/agent/summarizer-hr"
        }
    }
}

# Test: reviewer-general with Bob can access finance (reviewer-general has all depts)
test_bob_reviewer_general_finance if {
    allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/agent/reviewer-general",
        "document_id": "DOC-002",
        "document_metadata": doc_finance,
        "delegation": {
            "user_spiffe_id": "spiffe://demo.example.com/user/bob",
            "agent_spiffe_id": "spiffe://demo.example.com/agent/reviewer-general"
        }
    }
}

# Test: Multi-department document - user with one matching dept can access
test_multi_dept_document_one_match if {
    allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/user/alice",
        "document_id": "DOC-005",
        "document_metadata": doc_finance_engineering
    }
}
