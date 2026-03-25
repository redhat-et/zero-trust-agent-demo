package demo.credential_gateway

import rego.v1

# Test: alice + summarizer-tech can access finance doc
test_proxy_alice_summarizer_finance if {
    result := proxy_decision with input as {
        "user": "alice",
        "agent": "summarizer-tech",
        "target_service": "s3",
        "action": "read",
        "s3_key": "finance/q4-report.md"
    }
    result.allow == true
}

# Test: alice + summarizer-hr denied engineering doc (summarizer-hr is hr-only)
test_proxy_alice_summarizer_engineering_denied if {
    not proxy_decision.allow with input as {
        "user": "alice",
        "agent": "summarizer-hr",
        "target_service": "s3",
        "action": "read",
        "s3_key": "engineering/roadmap.md"
    }
}

# Test: alice + summarizer-tech can access multi-dept doc (budget has finance+engineering)
test_proxy_alice_summarizer_budget_allowed if {
    result := proxy_decision with input as {
        "user": "alice",
        "agent": "summarizer-tech",
        "target_service": "s3",
        "action": "read",
        "s3_key": "engineering/budget.md"
    }
    result.allow == true
}

# Test: carol + summarizer-tech denied (hr ∩ {finance,engineering} = empty)
test_proxy_carol_summarizer_denied if {
    not proxy_decision.allow with input as {
        "user": "carol",
        "agent": "summarizer-tech",
        "target_service": "s3",
        "action": "read",
        "s3_key": "finance/q4-report.md"
    }
}

# Test: alice + reviewer-general can access engineering doc
test_proxy_alice_reviewer_engineering if {
    result := proxy_decision with input as {
        "user": "alice",
        "agent": "reviewer-general",
        "target_service": "s3",
        "action": "read",
        "s3_key": "engineering/roadmap.md"
    }
    result.allow == true
}

# Test: carol + reviewer-general can access hr doc
test_proxy_carol_reviewer_hr if {
    result := proxy_decision with input as {
        "user": "carol",
        "agent": "reviewer-general",
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
        "agent": "reviewer-general",
        "target_service": "s3",
        "action": "read",
        "s3_key": "nonexistent/file.md"
    }
    result.allow == false
}
