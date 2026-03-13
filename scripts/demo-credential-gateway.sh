#!/usr/bin/env bash
#
# Interactive demo: Credential Gateway with AWS STS session policies
#
# Walks through the permission intersection model step-by-step,
# showing how JWTs with delegation claims are translated into
# scoped AWS credentials that enforce the intersection on S3.
#
# Usage:
#   ./scripts/demo-credential-gateway.sh                # against OpenShift (port-forward)
#   GW_URL=http://localhost:8090 ./scripts/demo-credential-gateway.sh  # custom endpoint
#
# Prerequisites:
#   - Credential gateway running (locally or on OpenShift)
#   - aws CLI configured (for S3 access verification)
#   - S3 bucket seeded with sample documents
#
set -euo pipefail

# --- Configuration ---

GW_URL="${GW_URL:-http://localhost:8090}"
S3_BUCKET="${S3_BUCKET:-zt-demo-documents}"
S3_REGION="${S3_REGION:-us-east-1}"
AUTO="${AUTO:-false}"  # set AUTO=true to skip pauses

# --- Colors and formatting ---

BOLD='\033[1m'
DIM='\033[2m'
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
MAGENTA='\033[35m'
CYAN='\033[36m'
WHITE='\033[37m'
RESET='\033[0m'

# Box-drawing characters
H_LINE='─'
V_LINE='│'
TL='┌'
TR='┐'
BL='└'
BR='┘'

banner() {
  local width=62
  local text="$1"
  local pad=$(( (width - ${#text} - 2) / 2 ))
  echo ""
  echo -e "${CYAN}${TL}$(printf '%0.s─' $(seq 1 $width))${TR}${RESET}"
  echo -e "${CYAN}${V_LINE}$(printf '%*s' $pad '')${BOLD}${WHITE} ${text} ${RESET}${CYAN}$(printf '%*s' $(( width - pad - ${#text} - 2 )) '')${V_LINE}${RESET}"
  echo -e "${CYAN}${BL}$(printf '%0.s─' $(seq 1 $width))${BR}${RESET}"
  echo ""
}

step() {
  echo -e "\n${BOLD}${YELLOW}>>> $1${RESET}\n"
}

info() {
  echo -e "  ${DIM}$1${RESET}"
}

show_json() {
  echo "$1" | python3 -m json.tool 2>/dev/null | while IFS= read -r line; do
    echo -e "  ${DIM}${line}${RESET}"
  done
}

success() {
  echo -e "  ${GREEN}$1${RESET}"
}

denied() {
  echo -e "  ${RED}$1${RESET}"
}

pause() {
  if [ "$AUTO" = "true" ]; then
    sleep 1
    return
  fi
  echo ""
  echo -e "  ${DIM}Press Enter to continue...${RESET}"
  read -r
}

mk_jwt() {
  local payload="$1"
  local header
  header=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
  local body
  body=$(echo -n "$payload" | base64 | tr -d '=' | tr '+/' '-_')
  echo "${header}.${body}."
}

# --- Pre-flight check ---

if ! curl -sf "${GW_URL}/health" >/dev/null 2>&1; then
  echo -e "${RED}ERROR: Credential gateway not reachable at ${GW_URL}${RESET}"
  echo ""
  echo "If running on OpenShift, start a port-forward first:"
  echo "  oc port-forward -n spiffe-demo svc/credential-gateway 8090:8080 &"
  echo ""
  echo "Or set GW_URL to the correct endpoint."
  exit 1
fi

# ============================================================
# INTRO
# ============================================================

banner "Zero Trust Credential Gateway Demo"

echo -e "  This demo shows how the ${BOLD}permission intersection${RESET} model"
echo -e "  translates JWT delegation claims into ${BOLD}scoped AWS credentials${RESET}."
echo ""
echo -e "  ${BOLD}Core principle:${RESET}"
echo -e "    Effective Permissions = User Departments ${CYAN}∩${RESET} Agent Capabilities"
echo ""
echo -e "  The credential gateway:"
echo -e "    1. Validates the JWT and extracts the delegation chain"
echo -e "    2. Queries OPA for the permission intersection"
echo -e "    3. Calls AWS STS AssumeRole with a ${BOLD}session policy${RESET}"
echo -e "       that restricts S3 access to the intersection"

pause

# ============================================================
# PERMISSION MATRIX
# ============================================================

banner "Permission Matrix"

echo -e "  ${BOLD}Users and their departments:${RESET}"
echo ""
echo -e "    ${BLUE}Alice${RESET}   ${H_LINE} engineering, finance"
echo -e "    ${BLUE}Bob${RESET}     ${H_LINE} finance, admin"
echo -e "    ${BLUE}Carol${RESET}   ${H_LINE} hr"
echo -e "    ${BLUE}David${RESET}   ${H_LINE} engineering, hr"
echo ""
echo -e "  ${BOLD}Agents and their capabilities:${RESET}"
echo ""
echo -e "    ${MAGENTA}Summarizer${RESET}  ${H_LINE} finance"
echo -e "    ${MAGENTA}Claude${RESET}      ${H_LINE} engineering, finance, admin, hr"
echo -e "    ${MAGENTA}GPT-4${RESET}       ${H_LINE} engineering, finance"
echo ""
echo -e "  ${BOLD}S3 documents organized by department prefix:${RESET}"
echo ""
echo -e "    s3://${S3_BUCKET}/${GREEN}engineering/${RESET}roadmap.md"
echo -e "    s3://${S3_BUCKET}/${GREEN}finance/${RESET}q4-report.md"
echo -e "    s3://${S3_BUCKET}/${GREEN}admin/${RESET}policies.md"
echo -e "    s3://${S3_BUCKET}/${GREEN}hr/${RESET}guidelines.md"
echo -e "    s3://${S3_BUCKET}/${GREEN}public/${RESET}all-hands.md"

pause

# ============================================================
# SCENARIO 1: Alice + Summarizer
# ============================================================

banner "Scenario 1: Alice + Summarizer"

echo -e "  ${BLUE}Alice${RESET} (engineering, finance) delegates to ${MAGENTA}Summarizer${RESET} (finance)"
echo ""
echo -e "  Intersection: {engineering, finance} ${CYAN}∩${RESET} {finance} = ${BOLD}${GREEN}{finance}${RESET}"
echo ""
echo -e "  The summarizer should only get S3 access to ${GREEN}finance/${RESET} prefixes."

pause

step "Creating delegation JWT"

JWT_PAYLOAD='{"sub":"alice","preferred_username":"alice","azp":"summarizer","exp":9999999999}'
JWT=$(mk_jwt "$JWT_PAYLOAD")

echo -e "  ${BOLD}JWT payload:${RESET}"
show_json "$JWT_PAYLOAD"

pause

step "Calling credential gateway"

info "POST ${GW_URL}/credentials"
info "Authorization: Bearer <JWT>"
info "Body: {\"target_service\": \"s3\", \"action\": \"read\"}"
echo ""

RESULT=$(curl -sf -X POST "${GW_URL}/credentials" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Content-Type: application/json" \
  -d '{"target_service":"s3","action":"read"}')

echo -e "  ${BOLD}Response:${RESET}"

# Extract key fields for display
SESSION=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_name'])")
PREFIXES=$(echo "$RESULT" | python3 -c "import sys,json; print(', '.join(json.load(sys.stdin)['scoped_prefixes']))")
EXPIRATION=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['expiration'])")

echo -e "    Session:   ${BOLD}${SESSION}${RESET}"
echo -e "    Prefixes:  ${GREEN}${PREFIXES}${RESET}"
echo -e "    Expires:   ${DIM}${EXPIRATION}${RESET}"
echo -e "    Keys:      ${DIM}(temporary STS credentials issued)${RESET}"

pause

step "Verifying S3 access with scoped credentials"

AK=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_key_id'])")
SK=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['secret_access_key'])")
ST=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_token'])")

info "Using scoped credentials (${SESSION}):"
echo ""

# finance/ should work
echo -ne "  s3://${S3_BUCKET}/${GREEN}finance/${RESET}q4-report.md     ... "
if AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="$ST" \
   aws s3 cp "s3://${S3_BUCKET}/finance/q4-report.md" - --region "$S3_REGION" 2>/dev/null | head -1 | grep -q .; then
  success "ACCESSIBLE"
else
  denied "DENIED"
fi

# engineering/ should be denied
echo -ne "  s3://${S3_BUCKET}/${RED}engineering/${RESET}roadmap.md  ... "
if AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="$ST" \
   aws s3 cp "s3://${S3_BUCKET}/engineering/roadmap.md" - --region "$S3_REGION" 2>/dev/null | head -1 | grep -q .; then
  denied "ACCESSIBLE (unexpected!)"
else
  success "DENIED (correct)"
fi

# admin/ should be denied
echo -ne "  s3://${S3_BUCKET}/${RED}admin/${RESET}policies.md        ... "
if AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="$ST" \
   aws s3 cp "s3://${S3_BUCKET}/admin/policies.md" - --region "$S3_REGION" 2>/dev/null | head -1 | grep -q .; then
  denied "ACCESSIBLE (unexpected!)"
else
  success "DENIED (correct)"
fi

echo ""
echo -e "  ${GREEN}The STS session policy restricts access to finance/ only.${RESET}"
echo -e "  ${DIM}AWS enforces: Role Policy ∩ Session Policy = finance/* only${RESET}"

pause

# ============================================================
# SCENARIO 2: Alice + Claude
# ============================================================

banner "Scenario 2: Alice + Claude"

echo -e "  ${BLUE}Alice${RESET} (engineering, finance) delegates to ${MAGENTA}Claude${RESET} (engineering, finance, admin, hr)"
echo ""
echo -e "  Intersection: {engineering, finance} ${CYAN}∩${RESET} {engineering, finance, admin, hr}"
echo -e "               = ${BOLD}${GREEN}{engineering, finance}${RESET}"
echo ""
echo -e "  Claude has broad capabilities, but is limited to Alice's departments."

pause

step "Calling credential gateway"

JWT=$(mk_jwt '{"sub":"alice","preferred_username":"alice","azp":"claude","exp":9999999999}')
RESULT=$(curl -sf -X POST "${GW_URL}/credentials" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Content-Type: application/json" \
  -d '{"target_service":"s3","action":"read"}')

SESSION=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_name'])")
PREFIXES=$(echo "$RESULT" | python3 -c "import sys,json; print(', '.join(json.load(sys.stdin)['scoped_prefixes']))")

echo -e "  ${BOLD}Response:${RESET}"
echo -e "    Session:   ${BOLD}${SESSION}${RESET}"
echo -e "    Prefixes:  ${GREEN}${PREFIXES}${RESET}"

step "Verifying S3 access"

AK=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_key_id'])")
SK=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['secret_access_key'])")
ST=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_token'])")

echo -ne "  s3://${S3_BUCKET}/${GREEN}engineering/${RESET}roadmap.md  ... "
if AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="$ST" \
   aws s3 cp "s3://${S3_BUCKET}/engineering/roadmap.md" - --region "$S3_REGION" 2>/dev/null | head -1 | grep -q .; then
  success "ACCESSIBLE"
else
  denied "DENIED"
fi

echo -ne "  s3://${S3_BUCKET}/${GREEN}finance/${RESET}q4-report.md     ... "
if AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="$ST" \
   aws s3 cp "s3://${S3_BUCKET}/finance/q4-report.md" - --region "$S3_REGION" 2>/dev/null | head -1 | grep -q .; then
  success "ACCESSIBLE"
else
  denied "DENIED"
fi

echo -ne "  s3://${S3_BUCKET}/${RED}admin/${RESET}policies.md        ... "
if AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="$ST" \
   aws s3 cp "s3://${S3_BUCKET}/admin/policies.md" - --region "$S3_REGION" 2>/dev/null | head -1 | grep -q .; then
  denied "ACCESSIBLE (unexpected!)"
else
  success "DENIED (correct)"
fi

echo -ne "  s3://${S3_BUCKET}/${RED}hr/${RESET}guidelines.md          ... "
if AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="$ST" \
   aws s3 cp "s3://${S3_BUCKET}/hr/guidelines.md" - --region "$S3_REGION" 2>/dev/null | head -1 | grep -q .; then
  denied "ACCESSIBLE (unexpected!)"
else
  success "DENIED (correct)"
fi

echo ""
echo -e "  ${GREEN}Claude can access engineering/ and finance/ but NOT admin/ or hr/.${RESET}"
echo -e "  ${DIM}Even though Claude has admin and hr capabilities, Alice does not.${RESET}"

pause

# ============================================================
# SCENARIO 3: Carol + Summarizer (denied)
# ============================================================

banner "Scenario 3: Carol + Summarizer (Denied)"

echo -e "  ${BLUE}Carol${RESET} (hr) delegates to ${MAGENTA}Summarizer${RESET} (finance)"
echo ""
echo -e "  Intersection: {hr} ${CYAN}∩${RESET} {finance} = ${BOLD}${RED}{}  (empty!)${RESET}"
echo ""
echo -e "  No overlap -- the credential gateway should deny the request."

pause

step "Calling credential gateway"

JWT=$(mk_jwt '{"sub":"carol","preferred_username":"carol","azp":"summarizer","exp":9999999999}')
HTTP_CODE=$(curl -s -o /tmp/demo-cg-deny.json -w "%{http_code}" -X POST "${GW_URL}/credentials" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Content-Type: application/json" \
  -d '{"target_service":"s3","action":"read"}')

echo -e "  ${BOLD}HTTP Status: ${RED}${HTTP_CODE}${RESET}"
echo -e "  ${BOLD}Response:${RESET}"
show_json "$(cat /tmp/demo-cg-deny.json)"
echo ""
echo -e "  ${GREEN}No credentials issued. The agent cannot access any S3 objects.${RESET}"
echo -e "  ${DIM}Zero trust: no overlap means no access, regardless of either party's permissions.${RESET}"

pause

# ============================================================
# SCENARIO 4: Bob + GPT-4
# ============================================================

banner "Scenario 4: Bob + GPT-4"

echo -e "  ${BLUE}Bob${RESET} (finance, admin) delegates to ${MAGENTA}GPT-4${RESET} (engineering, finance)"
echo ""
echo -e "  Intersection: {finance, admin} ${CYAN}∩${RESET} {engineering, finance} = ${BOLD}${GREEN}{finance}${RESET}"
echo ""
echo -e "  Bob has admin access, but GPT-4 doesn't. GPT-4 has engineering, but Bob doesn't."
echo -e "  Only finance is in common."

pause

step "Calling credential gateway"

JWT=$(mk_jwt '{"sub":"bob","preferred_username":"bob","azp":"gpt4","exp":9999999999}')
RESULT=$(curl -sf -X POST "${GW_URL}/credentials" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Content-Type: application/json" \
  -d '{"target_service":"s3","action":"read"}')

SESSION=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_name'])")
PREFIXES=$(echo "$RESULT" | python3 -c "import sys,json; print(', '.join(json.load(sys.stdin)['scoped_prefixes']))")

echo -e "  ${BOLD}Response:${RESET}"
echo -e "    Session:   ${BOLD}${SESSION}${RESET}"
echo -e "    Prefixes:  ${GREEN}${PREFIXES}${RESET}"

step "Verifying S3 access"

AK=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_key_id'])")
SK=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['secret_access_key'])")
ST=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_token'])")

echo -ne "  s3://${S3_BUCKET}/${GREEN}finance/${RESET}q4-report.md     ... "
if AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="$ST" \
   aws s3 cp "s3://${S3_BUCKET}/finance/q4-report.md" - --region "$S3_REGION" 2>/dev/null | head -1 | grep -q .; then
  success "ACCESSIBLE"
else
  denied "DENIED"
fi

echo -ne "  s3://${S3_BUCKET}/${RED}admin/${RESET}policies.md        ... "
if AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="$ST" \
   aws s3 cp "s3://${S3_BUCKET}/admin/policies.md" - --region "$S3_REGION" 2>/dev/null | head -1 | grep -q .; then
  denied "ACCESSIBLE (unexpected!)"
else
  success "DENIED (correct -- GPT-4 lacks admin)"
fi

echo -ne "  s3://${S3_BUCKET}/${RED}engineering/${RESET}roadmap.md  ... "
if AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="$ST" \
   aws s3 cp "s3://${S3_BUCKET}/engineering/roadmap.md" - --region "$S3_REGION" 2>/dev/null | head -1 | grep -q .; then
  denied "ACCESSIBLE (unexpected!)"
else
  success "DENIED (correct -- Bob lacks engineering)"
fi

pause

# ============================================================
# SUMMARY
# ============================================================

banner "How It Works"

cat <<'DIAGRAM'

     JWT with delegation          OPA Policy Engine
     ┌──────────────────┐        ┌──────────────────────┐
     │ sub: alice       │───────►│ user_depts(alice)    │
     │ azp: summarizer  │        │   = [engineering,    │
     │                  │        │      finance]        │
     └──────────────────┘        │                      │
                                 │agent_caps(summarizer)│
                                 │   = [finance]        │
                                 │                      │
                                 │ intersection:        │
                                 │   = [finance]        │
                                 └──────────┬───────────┘
                                            │
                                            ▼
                                 ┌──────────────────────┐
                                 │ AWS STS AssumeRole   │
                                 │                      │
                                 │ Session Policy:      │
                                 │  Allow s3:GetObject  │
                                 │  Resource:           │
                                 │   arn:...:bucket     │
                                 │   arn:...:bucket/    │
                                 │     finance/*        │
                                 │                      │
                                 │ Effective:           │
                                 │  Role ∩ Session      │
                                 │  = finance/* only    │
                                 └──────────┬───────────┘
                                            │
                                            ▼
                                   Scoped credentials
                                   (15-min TTL)
DIAGRAM

echo ""
echo -e "  ${BOLD}Key insight:${RESET} AWS STS session policies implement permission"
echo -e "  intersection ${BOLD}natively${RESET}. The cloud provider enforces the scoping --"
echo -e "  not our code. Even if an agent tries to access paths outside"
echo -e "  the intersection, AWS itself will deny the request."
echo ""
echo -e "  ${BOLD}Components:${RESET}"
echo -e "    ${CYAN}Credential Gateway${RESET}  ${H_LINE} JWT validation + OPA query + STS call"
echo -e "    ${CYAN}OPA Policy Engine${RESET}   ${H_LINE} Computes user ${CYAN}∩${RESET} agent departments"
echo -e "    ${CYAN}AWS STS${RESET}             ${H_LINE} Issues scoped temporary credentials"
echo -e "    ${CYAN}S3${RESET}                  ${H_LINE} Enforces session policy on every request"
echo ""

rm -f /tmp/demo-cg-deny.json

echo -e "${BOLD}${GREEN}Demo complete.${RESET}"
echo ""
