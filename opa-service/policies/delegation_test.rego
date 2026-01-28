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
        "caller_spiffe_id": "spiffe://demo.example.com/agent/gpt4",
        "document_id": "DOC-002",
        "document_metadata": doc_finance
    }
}

# Test: Delegation with both having access succeeds
test_delegation_both_allowed if {
    allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/agent/gpt4",
        "document_id": "DOC-001",
        "document_metadata": doc_engineering,
        "delegation": {
            "user_spiffe_id": "spiffe://demo.example.com/user/alice",
            "agent_spiffe_id": "spiffe://demo.example.com/agent/gpt4"
        }
    }
}

# Test: Delegation fails when agent lacks capability
test_delegation_agent_lacks_capability if {
    not allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/agent/summarizer",
        "document_id": "DOC-003",
        "document_metadata": doc_admin,
        "delegation": {
            "user_spiffe_id": "spiffe://demo.example.com/user/bob",
            "agent_spiffe_id": "spiffe://demo.example.com/agent/summarizer"
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

# Test: Claude agent with delegation to Bob can access admin
test_bob_claude_admin if {
    allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/agent/claude",
        "document_id": "DOC-003",
        "document_metadata": doc_admin,
        "delegation": {
            "user_spiffe_id": "spiffe://demo.example.com/user/bob",
            "agent_spiffe_id": "spiffe://demo.example.com/agent/claude"
        }
    }
}

# Test: Alice + Summarizer cannot access engineering (summarizer lacks eng)
test_alice_summarizer_no_engineering if {
    not allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/agent/summarizer",
        "document_id": "DOC-001",
        "document_metadata": doc_engineering,
        "delegation": {
            "user_spiffe_id": "spiffe://demo.example.com/user/alice",
            "agent_spiffe_id": "spiffe://demo.example.com/agent/summarizer"
        }
    }
}

# Test: Alice + Summarizer CAN access finance
test_alice_summarizer_finance if {
    allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/agent/summarizer",
        "document_id": "DOC-002",
        "document_metadata": doc_finance,
        "delegation": {
            "user_spiffe_id": "spiffe://demo.example.com/user/alice",
            "agent_spiffe_id": "spiffe://demo.example.com/agent/summarizer"
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
