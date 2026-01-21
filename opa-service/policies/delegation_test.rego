package demo.authorization

import future.keywords.in

# Test: Public documents are always accessible
test_public_document_access if {
    allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/user/alice",
        "document_id": "DOC-007",
        "delegation": null
    }
}

# Test: User with correct department can access
test_user_direct_access_allowed if {
    allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/user/alice",
        "document_id": "DOC-001",
        "delegation": null
    }
}

# Test: User without correct department cannot access
test_user_direct_access_denied if {
    not allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/user/alice",
        "document_id": "DOC-003",
        "delegation": null
    }
}

# Test: Agent without user delegation is denied
test_agent_without_delegation_denied if {
    not allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/agent/gpt4",
        "document_id": "DOC-002",
        "delegation": null
    }
}

# Test: Delegation with both having access succeeds
test_delegation_both_allowed if {
    allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/agent/gpt4",
        "document_id": "DOC-001",
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
        "delegation": null
    }
}

# Test: Carol can access HR
test_carol_hr_access if {
    allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/user/carol",
        "document_id": "DOC-004",
        "delegation": null
    }
}

# Test: Claude agent with delegation to Bob can access admin
test_bob_claude_admin if {
    allow with input as {
        "caller_spiffe_id": "spiffe://demo.example.com/agent/claude",
        "document_id": "DOC-003",
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
        "delegation": {
            "user_spiffe_id": "spiffe://demo.example.com/user/alice",
            "agent_spiffe_id": "spiffe://demo.example.com/agent/summarizer"
        }
    }
}
