package demo.credential_gateway

import rego.v1

# Test: alice + kagenti-summarizer can access finance doc
test_proxy_alice_summarizer_finance if {
    result := proxy_decision with input as {
        "user": "alice",
        "agent": "kagenti-summarizer",
        "target_service": "s3",
        "action": "read",
        "s3_key": "finance/q4-report.md"
    }
    result.allow == true
}

# Test: alice + kagenti-summarizer denied engineering doc
test_proxy_alice_summarizer_engineering_denied if {
    not proxy_decision.allow with input as {
        "user": "alice",
        "agent": "kagenti-summarizer",
        "target_service": "s3",
        "action": "read",
        "s3_key": "engineering/roadmap.md"
    }
}

# Test: alice + kagenti-summarizer can access multi-dept doc (budget has finance+engineering)
test_proxy_alice_summarizer_budget_allowed if {
    result := proxy_decision with input as {
        "user": "alice",
        "agent": "kagenti-summarizer",
        "target_service": "s3",
        "action": "read",
        "s3_key": "engineering/budget.md"
    }
    result.allow == true
}

# Test: carol + kagenti-summarizer denied (hr ∩ finance = empty)
test_proxy_carol_summarizer_denied if {
    not proxy_decision.allow with input as {
        "user": "carol",
        "agent": "kagenti-summarizer",
        "target_service": "s3",
        "action": "read",
        "s3_key": "finance/q4-report.md"
    }
}

# Test: alice + kagenti-reviewer can access engineering doc
test_proxy_alice_reviewer_engineering if {
    result := proxy_decision with input as {
        "user": "alice",
        "agent": "kagenti-reviewer",
        "target_service": "s3",
        "action": "read",
        "s3_key": "engineering/roadmap.md"
    }
    result.allow == true
}

# Test: carol + kagenti-reviewer can access hr doc
test_proxy_carol_reviewer_hr if {
    result := proxy_decision with input as {
        "user": "carol",
        "agent": "kagenti-reviewer",
        "target_service": "s3",
        "action": "read",
        "s3_key": "hr/guidelines.md"
    }
    result.allow == true
}

# Test: unknown S3 key is denied
test_proxy_unknown_key_denied if {
    result := proxy_decision with input as {
        "user": "alice",
        "agent": "kagenti-reviewer",
        "target_service": "s3",
        "action": "read",
        "s3_key": "nonexistent/file.md"
    }
    result.allow == false
}
