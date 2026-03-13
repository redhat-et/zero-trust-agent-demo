#!/usr/bin/env bash
#
# Set up AWS IAM resources for the credential gateway demo.
#
# Creates:
#   1. IAM role (zt-demo-delegated-access) with S3 read permissions
#   2. Trust policy allowing the caller's IAM identity to assume the role
#
# The role has broad S3 read access to the demo bucket. Session policies
# passed during AssumeRole restrict it to specific prefixes (departments),
# implementing permission intersection:
#
#   Effective permissions = Role policy ∩ Session policy
#
# Usage:
#   S3_BUCKET=zt-demo-documents ./scripts/setup-aws-iam.sh
#
# Teardown:
#   S3_BUCKET=zt-demo-documents ./scripts/setup-aws-iam.sh --delete
#
# Prerequisites:
#   - aws CLI configured with credentials that can create IAM roles/policies
#
set -euo pipefail

S3_BUCKET="${S3_BUCKET:?Set S3_BUCKET (e.g. zt-demo-documents)}"
ROLE_NAME="${ROLE_NAME:-zt-demo-delegated-access}"
POLICY_NAME="${ROLE_NAME}-s3-read"
DELETE=false

if [ "${1:-}" = "--delete" ]; then
  DELETE=true
fi

echo "=== AWS IAM Setup for Credential Gateway Demo ==="
echo "  Bucket:  s3://${S3_BUCKET}"
echo "  Role:    ${ROLE_NAME}"
echo "  Policy:  ${POLICY_NAME}"
echo ""

# Check prerequisites
if ! command -v aws &>/dev/null; then
  echo "ERROR: aws CLI not found."
  exit 1
fi

# Get caller identity
CALLER_ARN=$(aws sts get-caller-identity --query "Arn" --output text)
ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)

if [ -z "$ACCOUNT_ID" ]; then
  echo "ERROR: Could not determine AWS account ID. Check credentials."
  exit 1
fi

echo "  Account: ${ACCOUNT_ID}"
echo "  Caller:  ${CALLER_ARN}"
echo ""

# --- Teardown ---

if [ "$DELETE" = true ]; then
  echo "--- Deleting IAM resources ---"

  # Detach and delete policy
  POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}"
  if aws iam get-policy --policy-arn "$POLICY_ARN" &>/dev/null; then
    aws iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn "$POLICY_ARN" 2>/dev/null || true
    aws iam delete-policy --policy-arn "$POLICY_ARN"
    echo "  - Deleted policy: ${POLICY_NAME}"
  else
    echo "  (policy not found: ${POLICY_NAME})"
  fi

  # Delete role
  if aws iam get-role --role-name "$ROLE_NAME" &>/dev/null; then
    aws iam delete-role --role-name "$ROLE_NAME"
    echo "  - Deleted role: ${ROLE_NAME}"
  else
    echo "  (role not found: ${ROLE_NAME})"
  fi

  echo ""
  echo "=== Teardown complete ==="
  exit 0
fi

# --- Create ---

echo "--- Step 1: Create IAM role ---"

# Trust policy: allow the caller to assume this role
# Use the root ARN so any user/role in the account can assume it,
# or restrict to the specific caller ARN for tighter security.
TRUST_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "${CALLER_ARN}"},
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
)

if aws iam get-role --role-name "$ROLE_NAME" &>/dev/null; then
  echo "  Role already exists, updating trust policy..."
  aws iam update-assume-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-document "$TRUST_POLICY"
  echo "  ~ Updated trust policy for: ${ROLE_NAME}"
else
  aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document "$TRUST_POLICY" \
    --description "Zero Trust demo: delegated S3 access with session policy intersection" \
    --max-session-duration 3600 \
    --query "Role.Arn" --output text
  echo "  + Created role: ${ROLE_NAME}"
fi
echo ""

echo "--- Step 2: Create and attach S3 read policy ---"

# Broad S3 read policy — session policies will restrict at runtime
S3_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3Read",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::${S3_BUCKET}",
        "arn:aws:s3:::${S3_BUCKET}/*"
      ]
    }
  ]
}
EOF
)

POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}"

if aws iam get-policy --policy-arn "$POLICY_ARN" &>/dev/null; then
  echo "  Policy already exists, creating new version..."
  # Delete oldest version if at the limit (max 5 versions)
  OLDEST=$(aws iam list-policy-versions --policy-arn "$POLICY_ARN" \
    --query "Versions[?IsDefaultVersion==\`false\`].VersionId" --output text | tail -1)
  if [ -n "$OLDEST" ]; then
    aws iam delete-policy-version --policy-arn "$POLICY_ARN" --version-id "$OLDEST" 2>/dev/null || true
  fi
  aws iam create-policy-version \
    --policy-arn "$POLICY_ARN" \
    --policy-document "$S3_POLICY" \
    --set-as-default --query "PolicyVersion.VersionId" --output text
  echo "  ~ Updated policy: ${POLICY_NAME}"
else
  aws iam create-policy \
    --policy-name "$POLICY_NAME" \
    --policy-document "$S3_POLICY" \
    --description "S3 read access to ${S3_BUCKET} for zero trust demo" \
    --query "Policy.Arn" --output text
  echo "  + Created policy: ${POLICY_NAME}"
fi

# Attach policy to role (idempotent)
aws iam attach-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-arn "$POLICY_ARN"
echo "  + Attached policy to role"
echo ""

echo "--- Step 3: Verify ---"

ROLE_ARN=$(aws iam get-role --role-name "$ROLE_NAME" --query "Role.Arn" --output text)
echo "  Role ARN: ${ROLE_ARN}"
echo ""
echo "  Attached policies:"
aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
  --query "AttachedPolicies[].PolicyName" --output text | sed 's/^/    /'
echo ""
echo "  Trust policy principals:"
aws iam get-role --role-name "$ROLE_NAME" \
  --query "Role.AssumeRolePolicyDocument.Statement[].Principal" --output text | sed 's/^/    /'
echo ""

echo "--- Quick test ---"
echo "  Try assuming the role with a session policy:"
echo ""
echo "  aws sts assume-role \\"
echo "    --role-arn \"${ROLE_ARN}\" \\"
echo "    --role-session-name \"test-intersection\" \\"
echo "    --policy '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\",\"s3:ListBucket\"],\"Resource\":[\"arn:aws:s3:::${S3_BUCKET}\",\"arn:aws:s3:::${S3_BUCKET}/engineering/*\"]}]}' \\"
echo "    --duration-seconds 900"
echo ""
echo "=== IAM setup complete ==="
