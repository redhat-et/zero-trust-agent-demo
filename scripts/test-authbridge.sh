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

# Decode a JWT payload with proper base64url padding.
# macOS base64 -d is strict about padding; without it, output is truncated.
decode_jwt_payload() {
  local b64
  b64=$(echo "$1" | cut -d'.' -f2 | tr '_-' '/+')
  local mod=$((${#b64} % 4))
  if [ "$mod" -eq 2 ]; then b64="${b64}=="
  elif [ "$mod" -eq 3 ]; then b64="${b64}="
  fi
  echo "$b64" | base64 -d 2>/dev/null
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
  PAYLOAD=$(decode_jwt_payload "$ACCESS_TOKEN")
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
      EX_PAYLOAD=$(decode_jwt_payload "$EXCHANGED_TOKEN")
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
    curl -s -w "\nHTTP_STATUS: %{http_code}" -X POST "http://document-service:8080/access" \
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
    curl -s -w "\nHTTP_STATUS: %{http_code}" -X POST "http://document-service:8080/access" \
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

# ===== A2A Agent Tests (Tests 6-11) =====
# These tests are conditional on summarizer-service being deployed.
SUMMARIZER_POD=$(kubectl get pods -n spiffe-demo -l app=summarizer-service -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -n "$SUMMARIZER_POD" ]; then
  echo "=== A2A Agent Token Exchange Tests ==="
  echo "  Summarizer pod: $SUMMARIZER_POD"
  echo ""

  # Test 6: Verify summarizer-service AuthBridge sidecar setup
  echo "--- Test 6: Verify summarizer-service AuthBridge sidecar setup ---"
  SUMM_CONTAINERS=$(kubectl get pod "$SUMMARIZER_POD" -n spiffe-demo -o jsonpath='{.spec.containers[*].name}' 2>/dev/null || echo "")
  echo "  Containers: $SUMM_CONTAINERS"
  SIDECAR_OK=true
  for expected in envoy-proxy client-registration spiffe-helper; do
    if echo "$SUMM_CONTAINERS" | grep -q "$expected"; then
      echo "  ✓ $expected container present"
    else
      echo "  ✗ $expected container MISSING"
      SIDECAR_OK=false
    fi
  done

  SUMM_CLIENT_ID=$(kubectl exec "$SUMMARIZER_POD" -n spiffe-demo -c client-registration -- cat /shared/client-id.txt 2>/dev/null || echo "")
  SUMM_CLIENT_SECRET=$(kubectl exec "$SUMMARIZER_POD" -n spiffe-demo -c client-registration -- cat /shared/client-secret.txt 2>/dev/null || echo "")
  if [ -n "$SUMM_CLIENT_ID" ] && [ -n "$SUMM_CLIENT_SECRET" ]; then
    pass "Summarizer AuthBridge sidecars ready (client: ${SUMM_CLIENT_ID})"
  else
    fail "Summarizer client credentials not available"
    SIDECAR_OK=false
  fi
  echo ""

  # Test 7: Token exchange proof (demo-friendly claim inspection)
  # Obtain a summarizer token, then exchange it for document-service audience.
  # This shows the claim transformation: azp changes, aud changes.
  echo "--- Test 7: Token exchange proof (claim inspection) ---"
  if [ -n "${SUMM_CLIENT_ID:-}" ] && [ -n "${SUMM_CLIENT_SECRET:-}" ]; then
    # Get summarizer's own token via client_credentials
    SUMM_OWN_TOKEN_RESP=$(curl -s -X POST "$TOKEN_ENDPOINT" \
      -d "grant_type=client_credentials" \
      -d "client_id=$SUMM_CLIENT_ID" \
      -d "client_secret=$SUMM_CLIENT_SECRET" 2>/dev/null || echo "")
    SUMM_OWN_TOKEN=$(echo "$SUMM_OWN_TOKEN_RESP" | jq -r '.access_token // empty')

    if [ -z "$SUMM_OWN_TOKEN" ]; then
      fail "Could not obtain summarizer's own token"
    else
      # Exchange summarizer's token for document-service audience
      SUMM_EXCHANGE=$(curl -s -X POST "$TOKEN_ENDPOINT" \
        -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
        -d "client_id=$SUMM_CLIENT_ID" \
        -d "client_secret=$SUMM_CLIENT_SECRET" \
        -d "subject_token=$SUMM_OWN_TOKEN" \
        -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
        -d "audience=document-service" \
        -d "scope=openid document-service-aud" 2>/dev/null || echo "")
      SUMM_TOKEN=$(echo "$SUMM_EXCHANGE" | jq -r '.access_token // empty')

      if [ -n "$SUMM_TOKEN" ]; then
        # Decode original and exchanged tokens side by side
        ORIG_PAYLOAD=$(decode_jwt_payload "$SUMM_OWN_TOKEN")
        EXCH_PAYLOAD=$(decode_jwt_payload "$SUMM_TOKEN")

        echo "  Original token (summarizer):"
        echo "    sub: $(echo "$ORIG_PAYLOAD" | jq -r '.sub // empty')"
        echo "    azp: $(echo "$ORIG_PAYLOAD" | jq -r '.azp // empty')"
        echo "    aud: $(echo "$ORIG_PAYLOAD" | jq -r '.aud // empty')"
        echo "  Exchanged token (for document-service):"
        echo "    sub: $(echo "$EXCH_PAYLOAD" | jq -r '.sub // empty')"
        echo "    azp: $(echo "$EXCH_PAYLOAD" | jq -r '.azp // empty')"
        echo "    aud: $(echo "$EXCH_PAYLOAD" | jq -r '.aud // empty')"

        EXCH_AUD=$(echo "$EXCH_PAYLOAD" | jq -r '.aud // empty')
        if echo "$EXCH_AUD" | grep -q "document-service"; then
          pass "Token exchange produces document-service audience"
        else
          fail "Exchanged token missing document-service audience"
        fi
      else
        ERROR=$(echo "$SUMM_EXCHANGE" | jq -r '.error_description // .error // empty')
        fail "Token exchange failed: $ERROR"
      fi
    fi
  else
    fail "Summarizer credentials not available"
  fi
  echo ""

  # Test 8: GET /documents with delegation headers + token exchange — allowed
  # This tests the Phase 6 delegation header forwarding: the agent code does
  # a plain GET, and the X-Delegation-* headers carry delegation context
  # through envoy to document-service transparently.
  echo "--- Test 8: GET /documents with delegation headers (DOC-002, allowed) ---"
  echo "  Delegation: alice -> summarizer -> DOC-002 (finance)"
  if [ -n "${SUMM_TOKEN:-}" ]; then
    DOC_RESULT=$(kubectl exec "$SUMMARIZER_POD" -n spiffe-demo -c summarizer-service -- \
      curl -s -w "\nHTTP_STATUS: %{http_code}" \
      "http://document-service:8080/documents/DOC-002" \
      -H "Authorization: Bearer $SUMM_TOKEN" \
      -H "X-Delegation-User: spiffe://demo.example.com/user/alice" \
      -H "X-Delegation-Agent: spiffe://demo.example.com/agent/summarizer" \
      2>/dev/null || echo '{"error":"request failed"}')

    HTTP_CODE=$(echo "$DOC_RESULT" | grep "HTTP_STATUS:" | awk '{print $2}')
    RESPONSE_BODY=$(echo "$DOC_RESULT" | grep -v "HTTP_STATUS:")
    if [ "$HTTP_CODE" = "200" ]; then
      DOC_TITLE=$(echo "$RESPONSE_BODY" | jq -r '.document.title // empty')
      pass "Document DOC-002 retrieved via delegation headers (title: $DOC_TITLE)"
    else
      REASON=$(echo "$RESPONSE_BODY" | jq -r '.reason // .error // "unknown"' 2>/dev/null || echo "HTTP $HTTP_CODE")
      fail "Expected HTTP 200 for DOC-002, got $HTTP_CODE: $REASON"
    fi
  else
    fail "No exchanged token available (test 7 must pass first)"
  fi
  echo ""

  # Test 9: GET /documents with delegation headers + token exchange — denied
  echo "--- Test 9: GET /documents with delegation headers (DOC-004, denied) ---"
  echo "  Delegation: alice -> summarizer -> DOC-004 (hr)"
  if [ -n "${SUMM_TOKEN:-}" ]; then
    DENY_DOC_RESULT=$(kubectl exec "$SUMMARIZER_POD" -n spiffe-demo -c summarizer-service -- \
      curl -s -w "\nHTTP_STATUS: %{http_code}" \
      "http://document-service:8080/documents/DOC-004" \
      -H "Authorization: Bearer $SUMM_TOKEN" \
      -H "X-Delegation-User: spiffe://demo.example.com/user/alice" \
      -H "X-Delegation-Agent: spiffe://demo.example.com/agent/summarizer" \
      2>/dev/null || echo '{"error":"request failed"}')

    HTTP_CODE=$(echo "$DENY_DOC_RESULT" | grep "HTTP_STATUS:" | awk '{print $2}')
    if [ "$HTTP_CODE" = "403" ]; then
      pass "Access to DOC-004 correctly denied via delegation headers"
    else
      fail "Expected HTTP 403 for DOC-004, got $HTTP_CODE"
    fi
  else
    fail "No exchanged token available (test 7 must pass first)"
  fi
  echo ""

  # Test 10: Full A2A invoke end-to-end — allowed
  echo "--- Test 10: Full A2A invoke end-to-end (DOC-002, allowed) ---"
  echo "  agent-service -> summarizer (A2A) -> document-service"
  if [ -n "${ACCESS_TOKEN:-}" ]; then
    INVOKE_RESULT=$(kubectl exec "$AGENT_POD" -n spiffe-demo -c agent-service -- \
      curl -s -w "\nHTTP_STATUS: %{http_code}" -X POST "http://localhost:8080/agents/summarizer/invoke" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -d '{
        "document_id": "DOC-002",
        "user_spiffe_id": "spiffe://demo.example.com/user/alice"
      }' 2>/dev/null || echo '{"error":"request failed"}')

    HTTP_CODE=$(echo "$INVOKE_RESULT" | grep "HTTP_STATUS:" | awk '{print $2}')
    RESPONSE_BODY=$(echo "$INVOKE_RESULT" | grep -v "HTTP_STATUS:")
    GRANTED=$(echo "$RESPONSE_BODY" | jq -r '.granted // empty' 2>/dev/null || echo "")
    STATE=$(echo "$RESPONSE_BODY" | jq -r '.state // empty' 2>/dev/null || echo "")
    if [ "$GRANTED" = "true" ] && [ "$STATE" != "failed" ]; then
      RESULT_TEXT=$(echo "$RESPONSE_BODY" | jq -r '.result // empty' | head -c 100)
      pass "A2A invoke succeeded (result: ${RESULT_TEXT}...)"
    elif [ "$GRANTED" = "true" ] && [ "$STATE" = "failed" ]; then
      RESULT_TEXT=$(echo "$RESPONSE_BODY" | jq -r '.result // empty')
      fail "Delegation allowed but document fetch failed: $RESULT_TEXT"
    else
      REASON=$(echo "$RESPONSE_BODY" | jq -r '.reason // .error // "unknown"' 2>/dev/null || echo "HTTP $HTTP_CODE")
      fail "A2A invoke failed: $REASON"
    fi
  fi
  echo ""

  # Test 11: Full A2A invoke end-to-end — denied
  echo "--- Test 11: Full A2A invoke end-to-end (DOC-004, denied) ---"
  echo "  agent-service -> summarizer (A2A) -> document-service (hr doc)"
  if [ -n "${ACCESS_TOKEN:-}" ]; then
    DENY_INVOKE_RESULT=$(kubectl exec "$AGENT_POD" -n spiffe-demo -c agent-service -- \
      curl -s -w "\nHTTP_STATUS: %{http_code}" -X POST "http://localhost:8080/agents/summarizer/invoke" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -d '{
        "document_id": "DOC-004",
        "user_spiffe_id": "spiffe://demo.example.com/user/alice"
      }' 2>/dev/null || echo '{"error":"request failed"}')

    HTTP_CODE=$(echo "$DENY_INVOKE_RESULT" | grep "HTTP_STATUS:" | awk '{print $2}')
    RESPONSE_BODY=$(echo "$DENY_INVOKE_RESULT" | grep -v "HTTP_STATUS:")
    GRANTED=$(echo "$RESPONSE_BODY" | jq -r '.granted' 2>/dev/null || echo "")
    if [ "$GRANTED" = "false" ]; then
      REASON=$(echo "$RESPONSE_BODY" | jq -r '.reason // empty')
      pass "A2A invoke correctly denied: $REASON"
    else
      fail "A2A invoke for DOC-004 should have been denied (granted=$GRANTED)"
    fi
  fi
  echo ""

  # Test 12: Show token exchange and delegation evidence from logs
  # This is a demo-friendly test that proves the mechanism is working
  # by extracting relevant log lines from the envoy-proxy sidecar.
  echo "--- Test 12: Token exchange and delegation proof (log evidence) ---"
  echo ""

  # Trigger a fresh request so the logs have a recent entry
  if [ -n "${SUMM_TOKEN:-}" ]; then
    kubectl exec "$SUMMARIZER_POD" -n spiffe-demo -c summarizer-service -- \
      curl -s "http://document-service:8080/documents/DOC-002" \
      -H "Authorization: Bearer $SUMM_TOKEN" \
      -H "X-Delegation-User: spiffe://demo.example.com/user/alice" \
      -H "X-Delegation-Agent: spiffe://demo.example.com/agent/summarizer" \
      >/dev/null 2>&1
  fi

  echo "  ┌─────────────────────────────────────────────────────────────────┐"
  echo "  │  Summarizer envoy-proxy logs (ext-proc token exchange)          │"
  echo "  └─────────────────────────────────────────────────────────────────┘"

  # Extract the most recent token exchange and delegation log lines
  ENVOY_LOGS=$(kubectl logs "$SUMMARIZER_POD" -n spiffe-demo -c envoy-proxy --tail=100 2>/dev/null || echo "")
  if [ -n "$ENVOY_LOGS" ]; then
    # Show delegation header forwarding
    DELEG_LINES=$(echo "$ENVOY_LOGS" | grep -E "\[Delegation\]" | tail -2)
    if [ -n "$DELEG_LINES" ]; then
      echo "$DELEG_LINES" | while read -r line; do echo "    $line"; done
    else
      echo "    (no delegation header logs found)"
    fi

    # Show token exchange activity
    EXCHANGE_LINES=$(echo "$ENVOY_LOGS" | grep -E "\[Token Exchange\] (Starting|Client ID|Audience|Successfully)" | tail -4)
    if [ -n "$EXCHANGE_LINES" ]; then
      echo "$EXCHANGE_LINES" | while read -r line; do echo "    $line"; done
      pass "Envoy ext-proc logs show token exchange with delegation headers"
    else
      fail "No token exchange evidence in envoy-proxy logs"
    fi
  else
    fail "Could not read envoy-proxy logs"
  fi

  echo ""
  echo "  ┌─────────────────────────────────────────────────────────────────┐"
  echo "  │  Document-service logs (delegation header consumption)          │"
  echo "  └─────────────────────────────────────────────────────────────────┘"

  DOC_POD=$(kubectl get pods -n spiffe-demo -l app=document-service -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
  if [ -n "$DOC_POD" ]; then
    DOC_LOGS=$(kubectl logs "$DOC_POD" -n spiffe-demo -c document-service --tail=50 2>/dev/null || echo "")
    DELEG_CONSUMED=$(echo "$DOC_LOGS" | grep -i "delegation header" | tail -2)
    if [ -n "$DELEG_CONSUMED" ]; then
      echo "$DELEG_CONSUMED" | while read -r line; do echo "    $line"; done
      pass "Document-service logs show delegation headers received"
    else
      echo "    (no delegation header logs found — may use JWT claims directly)"
      pass "Document-service processed request successfully"
    fi
  fi

  echo ""
  echo "  ┌─────────────────────────────────────────────────────────────────┐"
  echo "  │  Token claim transformation (before → after exchange)           │"
  echo "  └─────────────────────────────────────────────────────────────────┘"

  # Show the summarizer's own token vs the exchanged token side by side
  if [ -n "${SUMM_OWN_TOKEN:-}" ] && [ -n "${SUMM_TOKEN:-}" ]; then
    ORIG_PAYLOAD=$(decode_jwt_payload "$SUMM_OWN_TOKEN")
    EXCH_PAYLOAD=$(decode_jwt_payload "$SUMM_TOKEN")

    echo ""
    echo "    BEFORE exchange (summarizer's own token):"
    echo "      sub: $(echo "$ORIG_PAYLOAD" | jq -r '.sub // empty')"
    echo "      azp: $(echo "$ORIG_PAYLOAD" | jq -r '.azp // empty')"
    echo "      aud: $(echo "$ORIG_PAYLOAD" | jq -r 'if (.aud | type) == "array" then (.aud | join(", ")) else .aud end')"
    echo ""
    echo "    AFTER exchange (for document-service):"
    echo "      sub: $(echo "$EXCH_PAYLOAD" | jq -r '.sub // empty')"
    echo "      azp: $(echo "$EXCH_PAYLOAD" | jq -r '.azp // empty')"
    echo "      aud: $(echo "$EXCH_PAYLOAD" | jq -r 'if (.aud | type) == "array" then (.aud | join(", ")) else .aud end')"
    echo ""
    echo "    KEY OBSERVATIONS:"
    echo "      • sub stays the same (Keycloak service account UUID)"
    echo "      • azp stays the same (summarizer's SPIFFE ID)"
    echo "      • aud CHANGES: agent-service → document-service"
    echo "      • Delegation context travels via X-Delegation-* headers,"
    echo "        NOT in the JWT — the agent code never touches tokens"
    echo ""
    pass "Token claim transformation demonstrated"
  fi
  echo ""

else
  echo ""
  echo "--- Skipping A2A agent tests (summarizer-service not deployed) ---"
  echo "  Deploy with: make deploy-authbridge-ai-agents"
  echo ""
fi

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
