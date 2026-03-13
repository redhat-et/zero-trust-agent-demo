#!/usr/bin/env bash
#
# E2E test for the credential gateway.
#
# Starts OPA and the credential gateway, sends test requests with
# unsigned JWTs, and verifies that:
#   1. Permission intersection is computed correctly
#   2. STS credentials are scoped to the intersection
#   3. Scoped credentials enforce access on S3
#
# Usage:
#   S3_BUCKET=zt-demo-documents \
#   AWS_ROLE_ARN=arn:aws:iam::ACCOUNT:role/zt-demo-delegated-access \
#   ./scripts/test-credential-gateway.sh
#
# Prerequisites:
#   - aws CLI configured with valid credentials
#   - S3 bucket seeded with sample documents (scripts/seed-s3.sh)
#   - IAM role created (scripts/setup-aws-iam.sh)
#   - Binaries built: make build-credential-gateway && go build -o bin/opa-service ./opa-service
#
set -euo pipefail

S3_BUCKET="${S3_BUCKET:?Set S3_BUCKET (e.g. zt-demo-documents)}"
AWS_ROLE_ARN="${AWS_ROLE_ARN:?Set AWS_ROLE_ARN (e.g. arn:aws:iam::123:role/zt-demo-delegated-access)}"
OPA_PORT="${OPA_PORT:-8080}"
GW_PORT="${GW_PORT:-8090}"

PASS=0
FAIL=0
CLEANUP_PIDS=()

cleanup() {
  for pid in "${CLEANUP_PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

# --- Helpers ---

mk_jwt() {
  local payload="$1"
  local header
  header=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
  local body
  body=$(echo -n "$payload" | base64 | tr -d '=' | tr '+/' '-_')
  echo "${header}.${body}."
}

pass() {
  echo "  PASS: $1"
  PASS=$((PASS + 1))
}

fail() {
  echo "  FAIL: $1"
  FAIL=$((FAIL + 1))
}

# --- Start services ---

echo "=== Credential Gateway E2E Test ==="
echo "  Bucket:   s3://${S3_BUCKET}"
echo "  Role:     ${AWS_ROLE_ARN}"
echo "  OPA port: ${OPA_PORT}"
echo "  GW port:  ${GW_PORT}"
echo ""

echo "--- Starting services ---"

# Check if ports are free
if lsof -ti :"$OPA_PORT" >/dev/null 2>&1; then
  echo "  Port ${OPA_PORT} in use, killing..."
  lsof -ti :"$OPA_PORT" | xargs kill -9 2>/dev/null || true
  sleep 1
fi
if lsof -ti :"$GW_PORT" >/dev/null 2>&1; then
  echo "  Port ${GW_PORT} in use, killing..."
  lsof -ti :"$GW_PORT" | xargs kill -9 2>/dev/null || true
  sleep 1
fi

# Start OPA
bin/opa-service serve --policy-dir=opa-service/policies --port "$OPA_PORT" > /tmp/opa-test.log 2>&1 &
CLEANUP_PIDS+=($!)
sleep 2

if ! curl -sf "http://localhost:${OPA_PORT}/health" >/dev/null; then
  echo "  ERROR: OPA service failed to start"
  cat /tmp/opa-test.log
  exit 1
fi
echo "  OPA service: OK"

# Start credential gateway
bin/credential-gateway serve \
  --aws-role-arn "$AWS_ROLE_ARN" \
  --s3-bucket "$S3_BUCKET" \
  --port "$GW_PORT" > /tmp/credgw-test.log 2>&1 &
CLEANUP_PIDS+=($!)
sleep 2

if ! curl -sf "http://localhost:${GW_PORT}/health" >/dev/null; then
  echo "  ERROR: Credential gateway failed to start"
  cat /tmp/credgw-test.log
  exit 1
fi
echo "  Credential gateway: OK"
echo ""

# --- Test 1: alice + summarizer -> finance only ---

echo "--- Test 1: alice + summarizer (intersection: finance) ---"
JWT=$(mk_jwt '{"sub":"alice","preferred_username":"alice","azp":"summarizer","exp":9999999999}')
RESULT=$(curl -sf -X POST "http://localhost:${GW_PORT}/credentials" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Content-Type: application/json" \
  -d '{"target_service":"s3","action":"read"}')

PREFIXES=$(echo "$RESULT" | python3 -c "import sys,json; print(','.join(json.load(sys.stdin)['scoped_prefixes']))")
if [ "$PREFIXES" = "finance/" ]; then
  pass "Scoped to finance/ only"
else
  fail "Expected 'finance/', got '${PREFIXES}'"
fi

# --- Test 2: alice + claude -> engineering, finance ---

echo "--- Test 2: alice + claude (intersection: engineering, finance) ---"
JWT=$(mk_jwt '{"sub":"alice","preferred_username":"alice","azp":"claude","exp":9999999999}')
RESULT=$(curl -sf -X POST "http://localhost:${GW_PORT}/credentials" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Content-Type: application/json" \
  -d '{"target_service":"s3","action":"read"}')

PREFIXES=$(echo "$RESULT" | python3 -c "import sys,json; print(','.join(sorted(json.load(sys.stdin)['scoped_prefixes'])))")
if [ "$PREFIXES" = "engineering/,finance/" ]; then
  pass "Scoped to engineering/ and finance/"
else
  fail "Expected 'engineering/,finance/', got '${PREFIXES}'"
fi

# --- Test 3: carol + summarizer -> denied ---

echo "--- Test 3: carol + summarizer (no overlap -> denied) ---"
JWT=$(mk_jwt '{"sub":"carol","preferred_username":"carol","azp":"summarizer","exp":9999999999}')
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://localhost:${GW_PORT}/credentials" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Content-Type: application/json" \
  -d '{"target_service":"s3","action":"read"}')

if [ "$HTTP_CODE" = "403" ]; then
  pass "Denied with 403 (no overlapping permissions)"
else
  fail "Expected 403, got ${HTTP_CODE}"
fi

# --- Test 4: bob + gpt4 -> finance ---

echo "--- Test 4: bob + gpt4 (intersection: finance) ---"
JWT=$(mk_jwt '{"sub":"bob","preferred_username":"bob","azp":"gpt4","exp":9999999999}')
RESULT=$(curl -sf -X POST "http://localhost:${GW_PORT}/credentials" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Content-Type: application/json" \
  -d '{"target_service":"s3","action":"read"}')

PREFIXES=$(echo "$RESULT" | python3 -c "import sys,json; print(','.join(json.load(sys.stdin)['scoped_prefixes']))")
if [ "$PREFIXES" = "finance/" ]; then
  pass "Scoped to finance/ only"
else
  fail "Expected 'finance/', got '${PREFIXES}'"
fi

# --- Test 5: S3 access verification with scoped credentials ---

echo "--- Test 5: Verify scoped credentials enforce access on S3 ---"
JWT=$(mk_jwt '{"sub":"alice","preferred_username":"alice","azp":"summarizer","exp":9999999999}')
CREDS=$(curl -sf -X POST "http://localhost:${GW_PORT}/credentials" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Content-Type: application/json" \
  -d '{"target_service":"s3","action":"read"}')

# Use scoped credentials
export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_key_id'])")
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['secret_access_key'])")
export AWS_SESSION_TOKEN=$(echo "$CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_token'])")

# finance/ should be accessible
if aws s3 cp "s3://${S3_BUCKET}/finance/q4-report.md" - --region us-east-1 2>/dev/null | head -1 | grep -q "Financial"; then
  pass "finance/q4-report.md: accessible"
else
  fail "finance/q4-report.md: should be accessible"
fi

# engineering/ should be denied
if aws s3 cp "s3://${S3_BUCKET}/engineering/roadmap.md" - --region us-east-1 2>/dev/null | head -1 | grep -q "Engineering"; then
  fail "engineering/roadmap.md: should be denied"
else
  pass "engineering/roadmap.md: correctly denied"
fi

# admin/ should be denied
if aws s3 cp "s3://${S3_BUCKET}/admin/policies.md" - --region us-east-1 2>/dev/null | head -1 | grep -q "Administrative"; then
  fail "admin/policies.md: should be denied"
else
  pass "admin/policies.md: correctly denied"
fi

unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

# --- Test 6: Missing auth header ---

echo "--- Test 6: Missing Authorization header ---"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://localhost:${GW_PORT}/credentials" \
  -H "Content-Type: application/json" \
  -d '{"target_service":"s3","action":"read"}')

if [ "$HTTP_CODE" = "401" ]; then
  pass "Rejected with 401 (no auth header)"
else
  fail "Expected 401, got ${HTTP_CODE}"
fi

# --- Summary ---

echo ""
echo "============================================"
echo "  Results"
echo "============================================"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "  Total:  $((PASS + FAIL))"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
