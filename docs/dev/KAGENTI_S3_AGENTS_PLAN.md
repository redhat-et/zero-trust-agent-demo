# Kagenti S3 agents implementation plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development
> (if subagents available) or superpowers:executing-plans to implement this plan.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build two auth-unaware Python A2A agents (summarizer + reviewer)
that fetch documents from URLs, extend the credential gateway with an S3
proxy endpoint, and update OPA policies for per-object access control.

**Architecture:** Python agents receive URLs via A2A, fetch content via
plain HTTP GET, and process with LLM. When deployed in Kagenti, AuthBridge
intercepts outbound S3 requests, does token exchange, and routes to the
credential gateway which proxies S3 fetches after OPA policy evaluation.

**Tech Stack:** Python 3.12, uv, Google a2a-python SDK v1.0, httpx,
anthropic/openai SDKs, Go (credential gateway), OPA/Rego

**Spec:** `docs/dev/KAGENTI_S3_AGENTS_DESIGN.md`

---

## File structure

### New files

```text
kagenti-summarizer/
├── pyproject.toml              # uv project: a2a-python, httpx, anthropic, openai
├── Dockerfile                  # python:3.12-slim + uv
├── agent.py                    # A2A server setup, agent card, health endpoint
├── summarizer.py               # URL extraction, fetch, LLM summarization
├── llm.py                      # Multi-provider LLM (anthropic/openai/litellm/mock)
├── agent-card.json             # Static A2A agent card
└── tests/
    ├── test_summarizer.py      # URL extraction, S3 conversion, mock fetch
    └── test_llm.py             # Provider selection, mock mode

kagenti-reviewer/
├── pyproject.toml
├── Dockerfile
├── agent.py
├── reviewer.py                 # URL fetch + LLM review (3 review types)
├── llm.py                      # Same abstraction, independent copy
├── agent-card.json
└── tests/
    ├── test_reviewer.py
    └── test_llm.py

opa-service/policies/
├── credential_gateway_test.rego  # Tests for new proxy_decision rule
└── s3_documents.json             # Manifest data for OPA
```

### Modified files

```text
credential-gateway/cmd/serve.go          # Add S3 proxy handler + OPA input extension
opa-service/policies/credential_gateway.rego  # Add proxy_decision rule
opa-service/policies/agent_permissions.rego   # Add kagenti-* agent entries
document-service/internal/store/documents.go  # Add S3URL field + values
```

---

### Task 1: kagenti-summarizer — project scaffolding

**Files:**

- Create: `kagenti-summarizer/pyproject.toml`
- Create: `kagenti-summarizer/agent-card.json`

- [ ] **Step 1: Initialize uv project**

```bash
cd /Users/panni/work/zero-trust-agent-demo
mkdir -p kagenti-summarizer
cd kagenti-summarizer
uv init --no-readme
```

- [ ] **Step 2: Add dependencies**

```bash
cd /Users/panni/work/zero-trust-agent-demo/kagenti-summarizer
uv add a2a-python httpx anthropic openai
uv add --dev pytest pytest-asyncio
```

- [ ] **Step 3: Verify pyproject.toml was created**

```bash
cat kagenti-summarizer/pyproject.toml
```

Expected: project with dependencies listed.

- [ ] **Step 4: Create agent-card.json**

Write `kagenti-summarizer/agent-card.json`:

```json
{
  "name": "S3 Document Summarizer",
  "description": "Summarizes documents from any URL. Auth-unaware.",
  "url": "http://kagenti-summarizer:8000",
  "version": "1.0.0",
  "defaultInputModes": ["application/json"],
  "defaultOutputModes": ["text/plain"],
  "skills": [{
    "id": "url-summarization",
    "name": "URL Document Summarization",
    "description": "Fetches a document from any URL and summarizes it",
    "tags": ["summarization", "s3"]
  }]
}
```

- [ ] **Step 5: Commit**

```bash
git add kagenti-summarizer/
git commit -s -m "feat(kagenti-summarizer): scaffold uv project with agent card"
```

---

### Task 2: kagenti-summarizer — LLM abstraction

**Files:**

- Create: `kagenti-summarizer/llm.py`
- Create: `kagenti-summarizer/tests/test_llm.py`

- [ ] **Step 1: Write failing tests**

Write `kagenti-summarizer/tests/test_llm.py`:

```python
import os
import pytest
from llm import get_provider, MockProvider, SUMMARIZER_SYSTEM_PROMPT


def test_mock_provider_returns_canned_response():
    provider = MockProvider()
    result = provider.complete("system", "user content")
    assert "Mock summary" in result
    assert "user content" in result


def test_get_provider_defaults_to_mock_when_no_key():
    os.environ.pop("LLM_API_KEY", None)
    os.environ.pop("LLM_PROVIDER", None)
    provider = get_provider()
    assert isinstance(provider, MockProvider)


def test_summarizer_system_prompt_exists():
    assert "summarize" in SUMMARIZER_SYSTEM_PROMPT.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/panni/work/zero-trust-agent-demo/kagenti-summarizer
uv run pytest tests/test_llm.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'llm'`

- [ ] **Step 3: Implement llm.py**

Write `kagenti-summarizer/llm.py` with:

- `SUMMARIZER_SYSTEM_PROMPT` constant
- `MockProvider` class with `complete(system_prompt, user_prompt) -> str`
- `AnthropicProvider` class wrapping `anthropic.Anthropic`
- `OpenAIProvider` class wrapping `openai.OpenAI` (used for openai
  and litellm)
- `get_provider()` factory that reads `LLM_PROVIDER`, `LLM_API_KEY`,
  `LLM_BASE_URL`, `LLM_MODEL` from env. Returns `MockProvider` when
  `LLM_API_KEY` is not set.

Default models: `claude-sonnet-4-20250514` (anthropic),
`gpt-4o` (openai), `qwen3-14b` (litellm).

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/panni/work/zero-trust-agent-demo/kagenti-summarizer
uv run pytest tests/test_llm.py -v
```

Expected: 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add kagenti-summarizer/llm.py kagenti-summarizer/tests/
git commit -s -m "feat(kagenti-summarizer): multi-provider LLM abstraction with mock mode"
```

---

### Task 3: kagenti-summarizer — URL fetch and summarization

**Files:**

- Create: `kagenti-summarizer/summarizer.py`
- Create: `kagenti-summarizer/tests/test_summarizer.py`

- [ ] **Step 1: Write failing tests**

Write `kagenti-summarizer/tests/test_summarizer.py`:

```python
import pytest
from summarizer import extract_url, s3_to_https, fetch_and_summarize


def test_extract_s3_url():
    msg = "Please summarize s3://my-bucket/docs/report.md"
    assert extract_url(msg) == "s3://my-bucket/docs/report.md"


def test_extract_https_url():
    msg = "Summarize https://example.com/doc.md please"
    assert extract_url(msg) == "https://example.com/doc.md"


def test_extract_url_none():
    assert extract_url("no url here") is None


def test_s3_to_https():
    result = s3_to_https("s3://my-bucket/path/doc.md")
    assert result == "https://my-bucket.s3.amazonaws.com/path/doc.md"


def test_s3_to_https_passthrough():
    url = "https://example.com/doc.md"
    assert s3_to_https(url) == url


@pytest.mark.asyncio
async def test_fetch_and_summarize_mock():
    """Test with mock LLM — verifies the full pipeline."""
    # This test needs a mock HTTP server or httpx mock
    # For now, test the URL processing path
    pass
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/panni/work/zero-trust-agent-demo/kagenti-summarizer
uv run pytest tests/test_summarizer.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'summarizer'`

- [ ] **Step 3: Implement summarizer.py**

Write `kagenti-summarizer/summarizer.py` with:

- `extract_url(text: str) -> str | None` — regex for `s3://...` or
  `https://...` URLs
- `s3_to_https(url: str) -> str` — converts `s3://bucket/key` to
  `https://bucket.s3.amazonaws.com/key`, passes through other URLs
- `fetch_document(url: str) -> str` — async httpx GET, returns
  response text
- `fetch_and_summarize(message: str) -> str` — extracts URL, converts,
  fetches, sends to LLM, returns summary

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/panni/work/zero-trust-agent-demo/kagenti-summarizer
uv run pytest tests/test_summarizer.py -v
```

Expected: 5 tests PASS (the async one can be a placeholder).

- [ ] **Step 5: Commit**

```bash
git add kagenti-summarizer/summarizer.py kagenti-summarizer/tests/test_summarizer.py
git commit -s -m "feat(kagenti-summarizer): URL extraction, S3 conversion, fetch and summarize"
```

---

### Task 4: kagenti-summarizer — A2A agent server

**Files:**

- Create: `kagenti-summarizer/agent.py`

- [ ] **Step 1: Implement agent.py**

Write `kagenti-summarizer/agent.py` using Google's `a2a-python` SDK v1.0.
This is the main entry point (`uv run python agent.py`).

Key elements:

- Load `agent-card.json` and serve at `/.well-known/agent-card.json`
- Implement A2A `AgentExecutor` that:
  - Extracts text from incoming A2A message parts
  - Calls `fetch_and_summarize(text)` from `summarizer.py`
  - Returns result as a text artifact
- Expose `/health` endpoint returning `{"status": "healthy"}`
- Bind to `HOST:PORT` from env vars (defaults: `0.0.0.0:8000`)

Refer to the Google a2a-python SDK v1.0 documentation for the correct
server setup pattern. The SDK provides `A2AServer` or similar entrypoint.

- [ ] **Step 2: Test manually**

```bash
cd /Users/panni/work/zero-trust-agent-demo/kagenti-summarizer
uv run python agent.py &
curl http://localhost:8000/health
curl http://localhost:8000/.well-known/agent-card.json
kill %1
```

Expected: health returns `{"status": "healthy"}`, agent card returns
the JSON from `agent-card.json`.

- [ ] **Step 3: Commit**

```bash
git add kagenti-summarizer/agent.py
git commit -s -m "feat(kagenti-summarizer): A2A agent server with health and agent card"
```

---

### Task 5: kagenti-summarizer — Dockerfile

**Files:**

- Create: `kagenti-summarizer/Dockerfile`

- [ ] **Step 1: Write Dockerfile**

Write `kagenti-summarizer/Dockerfile`:

```dockerfile
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
COPY *.py agent-card.json ./

EXPOSE 8000
USER 1000
CMD ["uv", "run", "python", "agent.py"]
```

- [ ] **Step 2: Build and test**

```bash
cd /Users/panni/work/zero-trust-agent-demo
podman build -t kagenti-summarizer:test kagenti-summarizer/
podman run --rm -p 8000:8000 kagenti-summarizer:test &
curl http://localhost:8000/health
podman stop -l
```

Expected: health endpoint responds.

- [ ] **Step 3: Commit**

```bash
git add kagenti-summarizer/Dockerfile
git commit -s -m "feat(kagenti-summarizer): container image with uv"
```

---

### Task 6: kagenti-reviewer — complete agent

**Files:**

- Create: `kagenti-reviewer/` (all files)

This task mirrors tasks 1-5 but for the reviewer agent. Key differences
from kagenti-summarizer:

- `llm.py`: Has `REVIEWER_SYSTEM_PROMPT`, `REVIEWER_COMPLIANCE_PROMPT`,
  and `REVIEWER_SECURITY_PROMPT` constants instead of
  `SUMMARIZER_SYSTEM_PROMPT`. See existing Go prompts in
  `pkg/llm/prompts.go` for the text.
- `reviewer.py`: Same URL extraction and fetch logic. Adds
  `extract_review_type(text) -> str` that looks for keywords
  `compliance` or `security` in the message, defaults to `general`.
  The `fetch_and_review(message)` function selects the system prompt
  based on review type.
- `agent.py`: Same A2A server pattern, different agent card, extracts
  `review_type` from A2A DataPart if present.
- `agent-card.json`: Name is `"S3 Document Reviewer"`, skill id is
  `"url-review"`, tags are `["review", "compliance", "s3"]`.
- `tests/test_reviewer.py`: Tests for URL extraction (shared logic),
  review type extraction, and mock review.
- `tests/test_llm.py`: Same tests but verifying reviewer prompts.

- [ ] **Step 1: Create kagenti-reviewer directory and scaffold**

```bash
mkdir -p kagenti-reviewer/tests
cd kagenti-reviewer
uv init --no-readme
uv add a2a-python httpx anthropic openai
uv add --dev pytest pytest-asyncio
```

- [ ] **Step 2: Write all source files**

Copy the structure from kagenti-summarizer, adapting:

- `llm.py` — reviewer system prompts
- `reviewer.py` — review type extraction + fetch_and_review
- `agent.py` — different agent card, review_type support
- `agent-card.json` — reviewer identity
- `Dockerfile` — same pattern

- [ ] **Step 3: Write and run tests**

```bash
cd /Users/panni/work/zero-trust-agent-demo/kagenti-reviewer
uv run pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 4: Test manually**

```bash
uv run python agent.py &
curl http://localhost:8000/health
curl http://localhost:8000/.well-known/agent-card.json
kill %1
```

- [ ] **Step 5: Commit**

```bash
git add kagenti-reviewer/
git commit -s -m "feat(kagenti-reviewer): self-contained Python A2A review agent"
```

---

### Task 7: OPA policy — manifest data and proxy decision rule

**Files:**

- Create: `opa-service/policies/s3_documents.json`
- Create: `opa-service/policies/credential_gateway_test.rego`
- Modify: `opa-service/policies/credential_gateway.rego`
- Modify: `opa-service/policies/agent_permissions.rego:10-15`

- [ ] **Step 1: Create S3 manifest data file**

Write `opa-service/policies/s3_documents.json`. This is the manifest
data loaded into OPA as `data.demo.s3_documents`. Use the structure
from `scripts/seed-s3.sh` output:

```json
{
  "demo": {
    "s3_documents": [
      {"id": "DOC-001", "key": "engineering/roadmap.md", "departments": ["engineering"]},
      {"id": "DOC-002", "key": "finance/q4-report.md", "departments": ["finance"]},
      {"id": "DOC-003", "key": "admin/policies.md", "departments": ["admin"]},
      {"id": "DOC-004", "key": "hr/guidelines.md", "departments": ["hr"]},
      {"id": "DOC-005", "key": "engineering/budget.md", "departments": ["finance", "engineering"]},
      {"id": "DOC-006", "key": "admin/compliance-audit.md", "departments": ["admin", "finance"]},
      {"id": "DOC-007", "key": "public/all-hands.md", "departments": []}
    ]
  }
}
```

- [ ] **Step 2: Write failing OPA tests**

Write `opa-service/policies/credential_gateway_test.rego`:

```rego
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
    not proxy_decision with input as {
        "user": "alice",
        "agent": "kagenti-summarizer",
        "target_service": "s3",
        "action": "read",
        "s3_key": "engineering/roadmap.md"
    }
}

# Test: alice + kagenti-summarizer can access multi-dept doc
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
    not proxy_decision with input as {
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

# Test: existing decision rule still works
test_existing_decision_alice_summarizer if {
    result := decision with input as {
        "user": "alice",
        "agent": "summarizer",
        "target_service": "s3",
        "action": "read"
    }
    result.allow == true
    result.allowed_departments == ["finance"]
}
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
cd /Users/panni/work/zero-trust-agent-demo
opa test opa-service/policies/ -v
```

Expected: new proxy tests FAIL (rule `proxy_decision` not defined),
existing tests still PASS.

- [ ] **Step 4: Add kagenti agent entries to agent_permissions.rego**

Edit `opa-service/policies/agent_permissions.rego` — add to the
`agent_capabilities` map (after the existing `reviewer` entry on
line 14):

```rego
    "kagenti-summarizer": ["finance"],
    "kagenti-reviewer": ["engineering", "finance", "admin", "hr"]
```

- [ ] **Step 5: Add proxy_decision rule to credential_gateway.rego**

Append to `opa-service/policies/credential_gateway.rego` after
line 76:

```rego
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
    some dept in depts
    dept in permission_intersection
    reason := sprintf("S3 access allowed: %s (department %s in intersection %v)",
        [input.s3_key, dept, permission_intersection])
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
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
opa test opa-service/policies/ -v
```

Expected: all tests (existing + new) PASS.

- [ ] **Step 7: Commit**

```bash
git add opa-service/policies/
git commit -s -m "feat(opa): proxy_decision rule and kagenti agent capabilities"
```

---

### Task 8: Credential gateway — S3 proxy endpoint

**Files:**

- Modify: `credential-gateway/cmd/serve.go:82-87` (OPA input struct)
- Modify: `credential-gateway/cmd/serve.go:180-203` (mux + gateway)

- [ ] **Step 1: Add S3Key to OPA input struct**

Edit `credential-gateway/cmd/serve.go`. Add `S3Key` field to
`OPAIntersectionInput` (after line 86):

```go
type OPAIntersectionInput struct {
    User          string `json:"user"`
    Agent         string `json:"agent"`
    TargetService string `json:"target_service"`
    Action        string `json:"action"`
    S3Key         string `json:"s3_key,omitempty"`
}
```

- [ ] **Step 2: Add OPA proxy response type**

Add after `OPAIntersectionResponse` (after line 96):

```go
// OPAProxyResponse is the response from OPA for proxy decisions
type OPAProxyResponse struct {
    Result struct {
        Allow  bool   `json:"allow"`
        Reason string `json:"reason"`
    } `json:"result"`
}
```

- [ ] **Step 3: Extend Gateway struct with proxy fields**

Add two fields to the existing `Gateway` struct (do not replace it):

```go
proxyOPAURL  string       // OPA endpoint for proxy decisions
s3Client     *s3.Client   // S3 client for GetObject
```

In `runServe`, create the S3 client alongside the existing STS client
and set both new fields in the Gateway initializer:

```go
s3Client := s3.NewFromConfig(awsCfg)
```

```go
proxyOPAURL: fmt.Sprintf("%s://%s:%d/v1/data/demo/credential_gateway/proxy_decision",
    opaScheme, cfg.OPA.Host, cfg.OPA.Port),
s3Client: s3Client,
```

Add the import: `"github.com/aws/aws-sdk-go-v2/service/s3"`

- [ ] **Step 4: Register the proxy handler**

Add to the mux setup (after line 203):

```go
mux.HandleFunc("/s3-proxy/", gw.handleS3Proxy)
```

- [ ] **Step 5: Implement handleS3Proxy**

Add the handler method to `serve.go`. It should:

1. Accept only GET requests
1. Strip `/s3-proxy/` prefix to get S3 key
1. Validate empty key (400)
1. Extract and validate JWT (reuse `extractClaims`)
1. Extract delegation chain (reuse `extractDelegationChain`)
1. Query OPA proxy_decision endpoint with `s3_key` in input
1. If denied: return 403 with reason
1. If allowed: use AWS SDK S3 client to `GetObject` from the
   configured bucket
1. Stream the object body to the response with
   `Content-Type: text/markdown`

**Important**: The S3 GetObject call must use **scoped STS
credentials**, not the gateway's base credentials. The handler should:

1. Call `assumeRoleWithSessionPolicy` to get temporary credentials
   scoped to the allowed departments
1. Create a new `s3.Client` using those temporary credentials
   (via `aws.NewCredentialsCache` with static credentials)
1. Use that scoped client for `GetObject`

This ensures the S3 access is restricted by the session policy,
matching the security model.

The `queryOPAProxy` method is similar to `queryOPAIntersection` but
sends to `proxyOPAURL` and includes `S3Key` in the input. It returns
`(bool, string, error)` — allow, reason, error.

- [ ] **Step 6: Run go vet and build**

```bash
cd /Users/panni/work/zero-trust-agent-demo
go vet ./credential-gateway/...
make build-credential-gateway
```

Expected: no errors, binary produced.

- [ ] **Step 7: Test locally with mock SPIFFE**

```bash
# Start OPA with the new policies
make run-opa &

# Start credential gateway in dev mode
AWS_ROLE_ARN=arn:aws:iam::123:role/test \
  SPIFFE_DEMO_AWS_S3_BUCKET=zt-demo-documents \
  ./bin/credential-gateway serve \
    --mock-spiffe \
    --jwt-validation-enabled=false &

# Create test JWT
mk_jwt() {
  local h=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
  local b=$(echo -n "$1" | base64 | tr -d '=' | tr '+/' '-_')
  echo "${h}.${b}."
}

JWT=$(mk_jwt '{"sub":"alice","preferred_username":"alice","azp":"kagenti-summarizer","exp":9999999999}')

# Test proxy endpoint (will fail at S3 fetch but should pass OPA)
curl -v http://localhost:8080/s3-proxy/finance/q4-report.md \
  -H "Authorization: Bearer $JWT"

# Clean up
kill %1 %2
```

Expected: OPA allows the request (finance in intersection). S3 fetch
may fail without real AWS credentials, but the OPA + JWT path works.

- [ ] **Step 8: Commit**

```bash
git add credential-gateway/
git commit -s -m "feat(credential-gateway): S3 proxy endpoint with per-object OPA policy"
```

---

### Task 9: Document store — add S3URL field

**Files:**

- Modify: `document-service/internal/store/documents.go:4-11`

- [ ] **Step 1: Add S3URL field to Document struct**

Edit `document-service/internal/store/documents.go`. Add field after
`Sensitivity`:

```go
type Document struct {
    ID                  string   `json:"id"`
    Title               string   `json:"title"`
    Content             string   `json:"content"`
    RequiredDepartment  string   `json:"required_department,omitempty"`
    RequiredDepartments []string `json:"required_departments,omitempty"`
    Sensitivity         string   `json:"sensitivity"`
    S3URL               string   `json:"s3_url,omitempty"`
}
```

- [ ] **Step 2: Add S3URL to each document in loadSampleDocuments**

Add `S3URL` to each document initialization. The S3 bucket name
should come from an env var with a default:

```go
bucket := os.Getenv("S3_BUCKET")
if bucket == "" {
    bucket = "zt-demo-documents"
}
```

Then for each document, add the field. For example, DOC-001:

```go
S3URL: fmt.Sprintf("s3://%s/engineering/roadmap.md", bucket),
```

Full mapping:

| Doc ID  | S3 key                          |
| ------- | ------------------------------- |
| DOC-001 | `engineering/roadmap.md`        |
| DOC-002 | `finance/q4-report.md`          |
| DOC-003 | `admin/policies.md`             |
| DOC-004 | `hr/guidelines.md`              |
| DOC-005 | `engineering/budget.md`         |
| DOC-006 | `admin/compliance-audit.md`     |
| DOC-007 | `public/all-hands.md`           |

- [ ] **Step 3: Include S3URL in List response**

Edit the `List()` method (line 206-218) to include `S3URL` in the
returned metadata:

```go
docs = append(docs, &Document{
    ID:                  doc.ID,
    Title:               doc.Title,
    RequiredDepartment:  doc.RequiredDepartment,
    RequiredDepartments: doc.RequiredDepartments,
    Sensitivity:         doc.Sensitivity,
    S3URL:               doc.S3URL,
})
```

- [ ] **Step 4: Build and verify**

```bash
make build-document
make vet
```

Expected: builds without errors.

- [ ] **Step 5: Commit**

```bash
git add document-service/
git commit -s -m "feat(document-service): add S3URL field to document metadata"
```

---

### Task 10: Run full lint and test suite

- [ ] **Step 1: Run Go linter**

```bash
make lint
```

Expected: no new lint errors.

- [ ] **Step 2: Run Go tests**

```bash
make test
```

Expected: all existing tests pass.

- [ ] **Step 3: Run OPA policy tests**

```bash
make test-policies
```

Expected: all policy tests pass (existing + new credential gateway tests).

- [ ] **Step 4: Run Python tests**

```bash
cd kagenti-summarizer && uv run pytest tests/ -v && cd ..
cd kagenti-reviewer && uv run pytest tests/ -v && cd ..
```

Expected: all Python tests pass.

- [ ] **Step 5: Fix any issues and commit**

Stage only the specific files that were fixed, then commit:

```bash
git add <fixed-files>
git commit -s -m "fix: address lint and test issues"
```

Only commit if there were fixes needed.

---

### Task 11: Web dashboard — send S3 URL for kagenti agents

**Files:**

- Modify: `web-dashboard/cmd/serve.go`
- Modify: `web-dashboard/internal/assets/templates/` (if needed)

The dashboard currently sends `document_id` to Go-based summarizer
and reviewer agents. For kagenti agents, it needs to send the `s3_url`
from the document metadata in the A2A message.

- [ ] **Step 1: Read the dashboard code**

Read `web-dashboard/cmd/serve.go` to understand how `handleSummarize`
and `handleReview` work. Check how the dashboard discovers agents
and how it sends requests.

- [ ] **Step 2: Add kagenti agent awareness**

The dashboard needs to distinguish between Go-based agents
(send `document_id`) and kagenti agents (send `s3_url`).
Options depending on what the code looks like:

- Check agent URL or name prefix (`kagenti-`) to decide the format
- Add config flags for kagenti agent URLs
- Use agent card metadata (if available) to detect A2A agents

The simplest approach: if the target agent URL contains `kagenti`,
send the S3 URL instead of document ID.

- [ ] **Step 3: Implement S3 URL forwarding**

When the dashboard invokes a kagenti agent:

1. Fetch the document metadata (which now includes `s3_url`)
1. Construct an A2A `tasks/send` message with the S3 URL in the
   text part: `"Summarize s3://zt-demo-documents/finance/q4-report.md"`
1. Send to the kagenti agent's A2A endpoint

- [ ] **Step 4: Test with mock agents**

Start a kagenti agent locally and verify the dashboard sends the
correct format.

- [ ] **Step 5: Commit**

```bash
git add web-dashboard/
git commit -s -m "feat(dashboard): send S3 URL when targeting kagenti agents"
```

---

### Task 12: Deployment manifests — Kagenti overlay

**Files:**

- Create: `deploy/k8s/overlays/kagenti-s3-agents/kustomization.yaml`
- Create: `deploy/k8s/overlays/kagenti-s3-agents/kagenti-summarizer.yaml`
- Create: `deploy/k8s/overlays/kagenti-s3-agents/kagenti-reviewer.yaml`
- Create: `deploy/k8s/overlays/kagenti-s3-agents/opa-s3-documents-cm.yaml`

- [ ] **Step 1: Create Kustomize overlay directory**

```bash
mkdir -p deploy/k8s/overlays/kagenti-s3-agents
```

- [ ] **Step 2: Create kagenti-summarizer deployment manifest**

Write `kagenti-summarizer.yaml` with:

- Deployment with Kagenti labels:
  `kagenti.io/type: agent`, `protocol.kagenti.io/a2a: ""`
- Container: kagenti-summarizer image, port 8000
- Env vars: `PORT=8000`, `LLM_PROVIDER`, `LLM_API_KEY` (from Secret)
- Service: port 8000
- ConfigMap: agent-card.json content

- [ ] **Step 3: Create kagenti-reviewer deployment manifest**

Same pattern as summarizer, different image and agent card.

- [ ] **Step 4: Create OPA s3_documents ConfigMap**

Write `opa-s3-documents-cm.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: opa-s3-documents
data:
  s3_documents.json: |
    { "demo": { "s3_documents": [...] } }
```

This ConfigMap mounts alongside existing OPA policies.

- [ ] **Step 5: Create kustomization.yaml**

Reference a base overlay and add the new resources and patches.

- [ ] **Step 6: Validate manifests**

```bash
kubectl kustomize deploy/k8s/overlays/kagenti-s3-agents
```

Expected: valid YAML output with all resources.

- [ ] **Step 7: Commit**

```bash
git add deploy/k8s/overlays/kagenti-s3-agents/
git commit -s -m "feat(deploy): Kustomize overlay for kagenti S3 agents"
```

---

### Task 13: AuthBridge route config

**Files:**

- Create or modify: route config within the kagenti-s3-agents overlay

This task adds the AuthBridge route configuration so that outbound
S3 requests from kagenti agent pods are intercepted and routed to
the credential gateway.

- [ ] **Step 1: Create AuthBridge routes patch**

Add to the kagenti-s3-agents overlay a ConfigMap or patch that
provides the `routes.yaml` for AuthBridge:

```yaml
- host: "*.s3.amazonaws.com"
  target_audience: "credential-gateway"
  token_scopes: "openid"
- host: "*.s3.*.amazonaws.com"
  target_audience: "credential-gateway"
  token_scopes: "openid"
```

The exact mechanism depends on how Kagenti injects AuthBridge
config. If Kagenti auto-generates routes.yaml, this may need to
be an annotation or CR field rather than a raw ConfigMap.

- [ ] **Step 2: Document Envoy host rewrite requirement**

Add a note in the overlay or a README explaining that the Envoy
outbound listener needs a route rule to rewrite `*.s3.amazonaws.com`
destinations to the credential gateway service, prepending
`/s3-proxy/` to the path. This may require Kagenti operator support
or a manual Envoy config patch.

- [ ] **Step 3: Commit**

```bash
git add deploy/k8s/overlays/kagenti-s3-agents/
git commit -s -m "feat(deploy): AuthBridge route config for S3 interception"
```

---

### Task 14: Run full verification

- [ ] **Step 1: Run all linters and tests**

```bash
make lint
make test
make test-policies
cd kagenti-summarizer && uv run pytest tests/ -v && cd ..
cd kagenti-reviewer && uv run pytest tests/ -v && cd ..
```

Expected: everything passes.

- [ ] **Step 2: Validate Kustomize overlays**

```bash
kubectl kustomize deploy/k8s/overlays/kagenti-s3-agents
```

Expected: valid YAML.

- [ ] **Step 3: Build all container images**

```bash
make build
podman build -t kagenti-summarizer:test kagenti-summarizer/
podman build -t kagenti-reviewer:test kagenti-reviewer/
```

Expected: all images build successfully.
