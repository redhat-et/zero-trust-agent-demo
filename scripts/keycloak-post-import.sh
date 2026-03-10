#!/usr/bin/env bash
#
# Post-import fixup for Keycloak realm on OpenShift.
#
# The realm JSON (realm-spiffe-demo.json) uses demo.example.com SPIFFE IDs
# for audience scopes. On OpenShift, auto-registered clients use the real
# cluster SPIFFE IDs. This script adds additional audience mappers so token
# exchange works with both SPIFFE trust domains.
#
# Run this after every Keycloak restart/reimport:
#   KEYCLOAK_URL=https://keycloak-spiffe-demo.apps.example.com ./scripts/keycloak-post-import.sh
#
# Prerequisites:
#   - Keycloak is running and healthy
#   - Service pods are running (to read their SPIFFE IDs)
#   - jq and curl installed
#
set -euo pipefail

KEYCLOAK_URL="${KEYCLOAK_URL:?Set KEYCLOAK_URL (e.g. https://keycloak-spiffe-demo.apps.example.com)}"
REALM="spiffe-demo"
ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"
ADMIN_PASS="${KEYCLOAK_ADMIN_PASSWORD:-admin123}"
NAMESPACE="${NAMESPACE:-spiffe-demo}"

echo "=== Keycloak Post-Import Fixup ==="
echo "  Keycloak: $KEYCLOAK_URL"
echo "  Realm: $REALM"
echo ""

# --- Helper functions ---

get_admin_token() {
  curl -sf -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" \
    -d "username=$ADMIN_USER" \
    -d "password=$ADMIN_PASS" | jq -r '.access_token'
}

get_scope_id() {
  local token="$1" scope_name="$2"
  curl -sf "${KEYCLOAK_URL}/admin/realms/${REALM}/client-scopes" \
    -H "Authorization: Bearer $token" | jq -r ".[] | select(.name==\"${scope_name}\") | .id"
}

get_client_uuid() {
  local token="$1" client_id="$2"
  curl -sf "${KEYCLOAK_URL}/admin/realms/${REALM}/clients?clientId=${client_id}" \
    -H "Authorization: Bearer $token" | jq -r '.[0].id // empty'
}

add_audience_mapper() {
  local token="$1" scope_id="$2" mapper_name="$3" audience="$4"

  # Check if mapper already exists
  local existing
  existing=$(curl -sf "${KEYCLOAK_URL}/admin/realms/${REALM}/client-scopes/${scope_id}/protocol-mappers/models" \
    -H "Authorization: Bearer $token" | jq -r ".[] | select(.name==\"${mapper_name}\") | .id")

  if [ -n "$existing" ]; then
    echo "  (already exists: $mapper_name)"
    return 0
  fi

  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "${KEYCLOAK_URL}/admin/realms/${REALM}/client-scopes/${scope_id}/protocol-mappers/models" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"${mapper_name}\",
      \"protocol\": \"openid-connect\",
      \"protocolMapper\": \"oidc-audience-mapper\",
      \"config\": {
        \"included.custom.audience\": \"${audience}\",
        \"id.token.claim\": \"false\",
        \"access.token.claim\": \"true\",
        \"lightweight.claim\": \"false\",
        \"introspection.token.claim\": \"true\"
      }
    }")

  if [ "$status" = "201" ]; then
    echo "  + Added: $mapper_name -> $audience"
  else
    echo "  ! Failed ($status): $mapper_name"
    return 1
  fi
}

add_optional_scope() {
  local token="$1" client_uuid="$2" scope_id="$3" scope_name="$4"

  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    "${KEYCLOAK_URL}/admin/realms/${REALM}/clients/${client_uuid}/optional-client-scopes/${scope_id}" \
    -H "Authorization: Bearer $token")

  if [ "$status" = "204" ]; then
    echo "  + Added optional scope: $scope_name"
  elif [ "$status" = "409" ]; then
    echo "  (already assigned: $scope_name)"
  else
    echo "  ! Failed ($status): $scope_name"
  fi
}

# --- Main ---

echo "--- Step 1: Obtain admin token ---"
ADMIN_TOKEN=$(get_admin_token)
if [ -z "$ADMIN_TOKEN" ]; then
  echo "  ! Could not authenticate to Keycloak"
  exit 1
fi
echo "  OK"
echo ""

echo "--- Step 2: Discover SPIFFE IDs from running pods ---"
AGENT_SPIFFE_ID=$(kubectl exec "$(kubectl get pods -n "$NAMESPACE" -l app=agent-service \
  -o jsonpath='{.items[0].metadata.name}')" -n "$NAMESPACE" -c client-registration \
  -- cat /shared/client-id.txt 2>/dev/null || echo "")
SUMM_SPIFFE_ID=$(kubectl exec "$(kubectl get pods -n "$NAMESPACE" -l app=summarizer-service \
  -o jsonpath='{.items[0].metadata.name}')" -n "$NAMESPACE" -c client-registration \
  -- cat /shared/client-id.txt 2>/dev/null || echo "")
REVIEWER_SPIFFE_ID=$(kubectl exec "$(kubectl get pods -n "$NAMESPACE" -l app=reviewer-service \
  -o jsonpath='{.items[0].metadata.name}')" -n "$NAMESPACE" -c client-registration \
  -- cat /shared/client-id.txt 2>/dev/null || echo "")

echo "  Agent:      ${AGENT_SPIFFE_ID:-not found}"
echo "  Summarizer: ${SUMM_SPIFFE_ID:-not found}"
echo "  Reviewer:   ${REVIEWER_SPIFFE_ID:-not found}"
echo ""

if [ -z "$AGENT_SPIFFE_ID" ]; then
  echo "  ! Agent SPIFFE ID not found. Are service pods running?"
  exit 1
fi

echo "--- Step 3: Add OpenShift audience mappers ---"

AGENT_AUD_ID=$(get_scope_id "$ADMIN_TOKEN" "agent-service-spiffe-aud")
SUMM_AUD_ID=$(get_scope_id "$ADMIN_TOKEN" "summarizer-service-aud")
REV_AUD_ID=$(get_scope_id "$ADMIN_TOKEN" "reviewer-service-aud")

echo "  Scope IDs:"
echo "    agent-service-spiffe-aud: ${AGENT_AUD_ID:-(not found)}"
echo "    summarizer-service-aud:   ${SUMM_AUD_ID:-(not found)}"
echo "    reviewer-service-aud:     ${REV_AUD_ID:-(not found)}"
echo ""

if [ -n "$AGENT_AUD_ID" ] && [ -n "$AGENT_SPIFFE_ID" ]; then
  add_audience_mapper "$ADMIN_TOKEN" "$AGENT_AUD_ID" \
    "agent-service-openshift-aud" "$AGENT_SPIFFE_ID"
fi

if [ -n "$SUMM_AUD_ID" ] && [ -n "$SUMM_SPIFFE_ID" ]; then
  add_audience_mapper "$ADMIN_TOKEN" "$SUMM_AUD_ID" \
    "summarizer-service-openshift-aud" "$SUMM_SPIFFE_ID"
fi

if [ -n "$REV_AUD_ID" ] && [ -n "$REVIEWER_SPIFFE_ID" ]; then
  add_audience_mapper "$ADMIN_TOKEN" "$REV_AUD_ID" \
    "reviewer-service-openshift-aud" "$REVIEWER_SPIFFE_ID"
fi
echo ""

echo "--- Step 4: Add audience scopes to dashboard client ---"

DASHBOARD_UUID=$(get_client_uuid "$ADMIN_TOKEN" "spiffe-demo-dashboard")
if [ -n "$DASHBOARD_UUID" ]; then
  echo "  Dashboard client UUID: $DASHBOARD_UUID"
  [ -n "$AGENT_AUD_ID" ] && add_optional_scope "$ADMIN_TOKEN" "$DASHBOARD_UUID" "$AGENT_AUD_ID" "agent-service-spiffe-aud"
  [ -n "$SUMM_AUD_ID" ] && add_optional_scope "$ADMIN_TOKEN" "$DASHBOARD_UUID" "$SUMM_AUD_ID" "summarizer-service-aud"
  [ -n "$REV_AUD_ID" ] && add_optional_scope "$ADMIN_TOKEN" "$DASHBOARD_UUID" "$REV_AUD_ID" "reviewer-service-aud"
else
  echo "  ! Dashboard client not found"
fi
echo ""

echo "--- Step 5: Verify ---"

# Quick smoke test: can we get alice's token with the agent audience?
ALICE_TOKEN=$(curl -sf -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=spiffe-demo-dashboard" \
  -d "username=alice" \
  -d "password=alice123" \
  -d "scope=openid agent-service-spiffe-aud" 2>/dev/null | jq -r '.access_token // empty')

if [ -n "$ALICE_TOKEN" ]; then
  AUD=$(echo "$ALICE_TOKEN" | cut -d'.' -f2 | tr '_-' '/+' | \
    awk '{mod=length%4; if(mod==2) printf "%s==",$0; else if(mod==3) printf "%s=",$0; else print}' | \
    base64 -d 2>/dev/null | jq -r '.aud')
  echo "  Alice's token audience: $AUD"
  if echo "$AUD" | grep -q "$AGENT_SPIFFE_ID"; then
    echo "  OK: OpenShift SPIFFE ID is in the audience"
  else
    echo "  ! Warning: OpenShift SPIFFE ID not found in audience"
  fi
else
  echo "  ! Could not obtain alice's token (is directAccessGrantsEnabled set?)"
fi
echo ""

echo "=== Post-import fixup complete ==="
