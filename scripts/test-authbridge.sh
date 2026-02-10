#!/usr/bin/env bash
#
# Test AuthBridge token exchange integration.
#
# This script:
#   1. Obtains a token using agent-service's dynamically registered credentials
#   2. Verifies the token has the agent's SPIFFE ID as audience
#   3. Tests access to allowed and denied documents through the agent-service flow
#
# Prerequisites:
#   - AuthBridge overlay deployed (./scripts/setup-authbridge.sh)
#   - Port forwarding active for keycloak (port 8080)
#
# Usage:
#   ./scripts/test-authbridge.sh
#
set -euo pipefail

KEYCLOAK_URL="${KEYCLOAK_URL:-http://keycloak.localtest.me:8080}"
REALM="spiffe-demo"
TOKEN_ENDPOINT="$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token"

PASS=0
FAIL=0

pass() {
  echo "  ✓ PASS: $1"
  PASS=$((PASS + 1))
}

fail() {
  echo "  ✗ FAIL: $1"
  FAIL=$((FAIL + 1))
}

echo "=== AuthBridge Token Exchange Tests ==="
echo ""
echo "Keycloak URL: $KEYCLOAK_URL"
echo ""

# Get agent-service credentials from the pod
echo "--- Retrieving agent-service credentials ---"
AGENT_POD=$(kubectl get pods -n spiffe-demo -l app=agent-service -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -z "$AGENT_POD" ]; then
  echo "ERROR: No agent-service pod found. Deploy AuthBridge first."
  exit 1
fi

CLIENT_ID=$(kubectl exec "$AGENT_POD" -n spiffe-demo -c client-registration -- cat /shared/client-id.txt 2>/dev/null || echo "")
CLIENT_SECRET=$(kubectl exec "$AGENT_POD" -n spiffe-demo -c client-registration -- cat /shared/client-secret.txt 2>/dev/null || echo "")

if [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ]; then
  echo "ERROR: Could not retrieve client credentials. Check client-registration container."
  echo "  kubectl logs $AGENT_POD -n spiffe-demo -c client-registration"
  exit 1
fi

echo "  Client ID: $CLIENT_ID"
echo "  Client Secret: ${CLIENT_SECRET:0:8}..."
echo ""

# Test 1: Obtain token with client credentials
echo "--- Test 1: Obtain token with client credentials ---"
TOKEN_RESPONSE=$(curl -sf -X POST "$TOKEN_ENDPOINT" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" 2>/dev/null || echo "")

if [ -z "$TOKEN_RESPONSE" ]; then
  fail "Could not obtain token from Keycloak"
else
  ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty')
  if [ -n "$ACCESS_TOKEN" ]; then
    pass "Obtained access token"
  else
    fail "Token response missing access_token"
    echo "  Response: $TOKEN_RESPONSE"
  fi
fi
echo ""

# Test 2: Verify token audience contains agent's SPIFFE ID
echo "--- Test 2: Verify token audience ---"
if [ -n "${ACCESS_TOKEN:-}" ]; then
  # Decode JWT payload (base64url)
  PAYLOAD=$(echo "$ACCESS_TOKEN" | cut -d'.' -f2 | tr '_-' '/+' | base64 -d 2>/dev/null || echo "")
  if [ -n "$PAYLOAD" ]; then
    TOKEN_AUD=$(echo "$PAYLOAD" | jq -r '.aud // empty')
    TOKEN_AZP=$(echo "$PAYLOAD" | jq -r '.azp // empty')
    echo "  Token audience: $TOKEN_AUD"
    echo "  Token azp: $TOKEN_AZP"

    if echo "$TOKEN_AUD" | grep -q "$CLIENT_ID"; then
      pass "Token audience contains agent's SPIFFE ID"
    else
      fail "Token audience does not contain agent's SPIFFE ID"
    fi
  else
    fail "Could not decode JWT payload"
  fi
fi
echo ""

# Test 3: Token exchange for document-service audience
echo "--- Test 3: Token exchange for document-service ---"
if [ -n "${ACCESS_TOKEN:-}" ]; then
  EXCHANGE_RESPONSE=$(curl -sf -X POST "$TOKEN_ENDPOINT" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "subject_token=$ACCESS_TOKEN" \
    -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "audience=document-service" \
    -d "scope=openid document-service-aud" 2>/dev/null || echo "")

  if [ -z "$EXCHANGE_RESPONSE" ]; then
    fail "Token exchange request failed"
  else
    EXCHANGED_TOKEN=$(echo "$EXCHANGE_RESPONSE" | jq -r '.access_token // empty')
    if [ -n "$EXCHANGED_TOKEN" ]; then
      pass "Token exchange succeeded"

      # Verify exchanged token audience
      EX_PAYLOAD=$(echo "$EXCHANGED_TOKEN" | cut -d'.' -f2 | tr '_-' '/+' | base64 -d 2>/dev/null || echo "")
      if [ -n "$EX_PAYLOAD" ]; then
        EX_AUD=$(echo "$EX_PAYLOAD" | jq -r '.aud // empty')
        echo "  Exchanged token audience: $EX_AUD"
        if echo "$EX_AUD" | grep -q "document-service"; then
          pass "Exchanged token has document-service audience"
        else
          fail "Exchanged token missing document-service audience"
        fi
      fi
    else
      ERROR=$(echo "$EXCHANGE_RESPONSE" | jq -r '.error_description // .error // empty')
      fail "Token exchange failed: $ERROR"
    fi
  fi
fi
echo ""

# Test 4: Access allowed document via agent-service (through Envoy)
# Simulates: Alice (engineering, finance) delegates to GPT-4 (engineering, finance)
# requesting DOC-001 (engineering) — should be allowed
echo "--- Test 4: Access allowed document (DOC-001, engineering) ---"
echo "  Delegation: alice -> gpt4 -> DOC-001"
if [ -n "${ACCESS_TOKEN:-}" ]; then
  # This request goes through Envoy which should exchange the token
  ACCESS_RESULT=$(kubectl exec "$AGENT_POD" -n spiffe-demo -c agent-service -- \
    curl -s -w "\nHTTP_STATUS: %{http_code}" -X POST "http://document-service:8084/access" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -d '{
      "document_id": "DOC-001",
      "delegation": {
        "user_spiffe_id": "spiffe://demo.example.com/user/alice",
        "agent_spiffe_id": "spiffe://demo.example.com/agent/gpt4"
      }
    }' 2>/dev/null || echo '{"error":"request failed"}')

  HTTP_CODE=$(echo "$ACCESS_RESULT" | grep "HTTP_STATUS:" | awk '{print $2}')
  RESPONSE_BODY=$(echo "$ACCESS_RESULT" | grep -v "HTTP_STATUS:")
  if [ "$HTTP_CODE" = "200" ] && echo "$RESPONSE_BODY" | jq -e '.access.granted' &>/dev/null 2>&1; then
    pass "Access to DOC-001 granted (engineering document, alice+gpt4)"
  elif echo "$RESPONSE_BODY" | jq -e '.error' &>/dev/null 2>&1; then
    REASON=$(echo "$RESPONSE_BODY" | jq -r '.reason // .error // "unknown"')
    fail "Access to DOC-001 denied: $REASON"
  else
    fail "Unexpected response for DOC-001 (HTTP $HTTP_CODE)"
    echo "  Response: $RESPONSE_BODY"
  fi
fi
echo ""

# Test 5: Access denied document via agent-service
# Simulates: Alice (engineering, finance) delegates to GPT-4 (engineering, finance)
# requesting DOC-004 (hr) — should be denied (neither has hr)
echo "--- Test 5: Access denied document (DOC-004, hr) ---"
echo "  Delegation: alice -> gpt4 -> DOC-004"
if [ -n "${ACCESS_TOKEN:-}" ]; then
  DENY_RESULT=$(kubectl exec "$AGENT_POD" -n spiffe-demo -c agent-service -- \
    curl -s -w "\nHTTP_STATUS: %{http_code}" -X POST "http://document-service:8084/access" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -d '{
      "document_id": "DOC-004",
      "delegation": {
        "user_spiffe_id": "spiffe://demo.example.com/user/alice",
        "agent_spiffe_id": "spiffe://demo.example.com/agent/gpt4"
      }
    }' 2>/dev/null || echo '{"error":"request failed"}')

  HTTP_CODE=$(echo "$DENY_RESULT" | grep "HTTP_STATUS:" | awk '{print $2}')
  if [ "$HTTP_CODE" = "403" ]; then
    REASON=$(echo "$DENY_RESULT" | grep -v "HTTP_STATUS:" | jq -r '.reason // .error // "unknown"')
    pass "Access to DOC-004 correctly denied: $REASON"
  elif echo "$DENY_RESULT" | jq -e '.access.granted' &>/dev/null 2>&1; then
    fail "Access to DOC-004 should have been denied"
  else
    fail "Unexpected response for DOC-004"
    echo "  Response: $DENY_RESULT"
  fi
fi
echo ""

# Print summary
echo "=== Test Summary ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "  Total:  $((PASS + FAIL))"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "Some tests failed. Check the output above for details."
  echo ""
  echo "Troubleshooting:"
  echo "  - Check envoy-proxy logs: kubectl logs $AGENT_POD -n spiffe-demo -c envoy-proxy"
  echo "  - Check client-registration: kubectl logs $AGENT_POD -n spiffe-demo -c client-registration"
  echo "  - Check spiffe-helper: kubectl logs $AGENT_POD -n spiffe-demo -c spiffe-helper"
  echo "  - Verify port forwarding: kubectl port-forward svc/keycloak 8080:8080 -n spiffe-demo"
  exit 1
fi
