#!/usr/bin/env bash
#
# Seed an S3 bucket with sample documents organized by department prefix.
#
# Documents are read from sample-documents/ and uploaded preserving the
# directory structure:
#
#   sample-documents/engineering/roadmap.md -> s3://BUCKET/engineering/roadmap.md
#   sample-documents/finance/q4-report.md   -> s3://BUCKET/finance/q4-report.md
#
# YAML front matter is stripped before upload and collected into a manifest
# file (manifest.json) that maps document IDs to their S3 keys and metadata.
#
# Usage:
#   S3_BUCKET=zt-demo-documents ./scripts/seed-s3.sh
#
# Prerequisites:
#   - aws CLI configured with valid credentials
#   - S3 bucket must already exist (script will not create it)
#
set -euo pipefail

S3_BUCKET="${S3_BUCKET:?Set S3_BUCKET (e.g. zt-demo-documents)}"
S3_REGION="${S3_REGION:-us-east-1}"
DOCS_DIR="${DOCS_DIR:-$(cd "$(dirname "$0")/.." && pwd)/sample-documents}"

echo "=== Seed S3 Bucket ==="
echo "  Bucket:    s3://${S3_BUCKET}"
echo "  Region:    ${S3_REGION}"
echo "  Source:    ${DOCS_DIR}"
echo ""

# Check prerequisites
if ! command -v aws &>/dev/null; then
  echo "ERROR: aws CLI not found. Install it first."
  exit 1
fi

if [ ! -d "$DOCS_DIR" ]; then
  echo "ERROR: Source directory not found: $DOCS_DIR"
  exit 1
fi

# Verify bucket access
if ! aws s3api head-bucket --bucket "$S3_BUCKET" --region "$S3_REGION" 2>/dev/null; then
  echo "ERROR: Cannot access bucket s3://${S3_BUCKET}"
  echo "  Create it first: aws s3 mb s3://${S3_BUCKET} --region ${S3_REGION}"
  exit 1
fi
echo "  Bucket accessible: OK"
echo ""

# --- Helper: parse YAML front matter ---

# Extract a single-value field from front matter
fm_field() {
  local content="$1" field="$2"
  echo "$content" | sed -n "/^---$/,/^---$/p" | grep "^${field}:" | head -1 | sed "s/^${field}:[[:space:]]*//" \
    || true
}

# Extract a list field from front matter (indented with "  - ")
fm_list() {
  local content="$1" field="$2"
  echo "$content" | sed -n "/^---$/,/^---$/p" | \
    sed -n "/^${field}:/,/^[^[:space:]-]/p" | \
    grep "^  - " | sed 's/^  - //' | tr '\n' ',' | sed 's/,$//' \
    || true
}

# Strip front matter, return content only
strip_fm() {
  local file="$1"
  # Skip everything between first and second ---
  awk 'BEGIN{fm=0} /^---$/{fm++; next} fm>=2{print}' "$file"
}

# --- Main: upload documents ---

echo "--- Uploading documents ---"

MANIFEST="[]"
COUNT=0
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

while IFS= read -r -d '' file; do
  # Relative path from DOCS_DIR (e.g. "engineering/roadmap.md")
  rel_path="${file#"${DOCS_DIR}/"}"

  # Read file content for front matter parsing
  file_content=$(cat "$file")

  # Parse front matter
  doc_id=$(fm_field "$file_content" "id")
  title=$(fm_field "$file_content" "title")
  sensitivity=$(fm_field "$file_content" "sensitivity")
  departments=$(fm_list "$file_content" "departments")

  if [ -z "$doc_id" ]; then
    echo "  SKIP: ${rel_path} (no id in front matter)"
    continue
  fi

  # Strip front matter and write to temp file
  content_file="${TMPDIR}/${rel_path}"
  mkdir -p "$(dirname "$content_file")"
  strip_fm "$file" > "$content_file"

  # Upload to S3
  aws s3 cp "$content_file" "s3://${S3_BUCKET}/${rel_path}" \
    --region "$S3_REGION" \
    --content-type "text/markdown" \
    --quiet

  echo "  + ${doc_id}: ${rel_path} (${sensitivity})"

  # Build manifest entry
  dept_json=""
  if [ -n "$departments" ]; then
    dept_json=$(echo "$departments" | sed 's/[^,]*/"&"/g')
  fi
  entry=$(printf '{"id":"%s","title":"%s","key":"%s","sensitivity":"%s","departments":[%s]}' \
    "$doc_id" "$title" "$rel_path" "$sensitivity" "$dept_json")

  # Append to manifest array using simple string manipulation
  if [ "$MANIFEST" = "[]" ]; then
    MANIFEST="[${entry}]"
  else
    MANIFEST="${MANIFEST%]},$entry]"
  fi

  COUNT=$((COUNT + 1))
done < <(find "$DOCS_DIR" -name "*.md" -type f -print0 | sort -z)

echo ""

# Upload manifest
echo "--- Uploading manifest ---"
echo "$MANIFEST" | python3 -m json.tool > "${TMPDIR}/manifest.json"
aws s3 cp "${TMPDIR}/manifest.json" "s3://${S3_BUCKET}/manifest.json" \
  --region "$S3_REGION" \
  --content-type "application/json" \
  --quiet
echo "  + manifest.json"
echo ""

# Verify
echo "--- Verification ---"
echo "  Documents uploaded: ${COUNT}"
echo ""
echo "  Bucket contents:"
aws s3 ls "s3://${S3_BUCKET}/" --region "$S3_REGION" --recursive | \
  sed 's/^/    /'
echo ""
echo "=== Seed complete ==="
