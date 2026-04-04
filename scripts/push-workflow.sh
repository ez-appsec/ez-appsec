#!/usr/bin/env bash
# push-workflow.sh — Push a local workflow file to a GitHub repo (create or update).
#
# Usage:
#   push-workflow.sh <local-file> <owner/repo> [<dest-path>] [--message <msg>]
#
# Examples:
#   push-workflow.sh .github/workflows/github-scan.yml ez-appsec/juice-shop-public
#   push-workflow.sh .github/workflows/github-scan.yml ez-appsec/juice-shop-public \
#       .github/workflows/ez-appsec-scan.yml
#   push-workflow.sh .github/workflows/github-scan.yml ez-appsec/juice-shop-public \
#       .github/workflows/ez-appsec-scan.yml \
#       --message "fix: update scan workflow"
#
# Reads GH_TOKEN or GITHUB_ACCESS_TOKEN from environment or /Users/johnfelten/git/2026/.env.
set -euo pipefail

# ── Resolve token ─────────────────────────────────────────────────────────────
ENV_FILE="$(dirname "$0")/../../.env"
[[ -f "$ENV_FILE" ]] && source "$ENV_FILE" 2>/dev/null || true
GH_TOKEN="${GH_TOKEN:-${GITHUB_ACCESS_TOKEN:-}}"
if [[ -z "$GH_TOKEN" ]]; then
  echo "ERROR: set GH_TOKEN or GITHUB_ACCESS_TOKEN" >&2; exit 1
fi

# ── Args ──────────────────────────────────────────────────────────────────────
LOCAL_FILE="${1:-}"
REPO="${2:-}"
DEST_PATH="${3:-}"
COMMIT_MSG=""

# Parse --message flag from remaining args
shift 3 2>/dev/null || shift $# 2>/dev/null || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --message|-m) COMMIT_MSG="$2"; shift 2 ;;
    *) shift ;;
  esac
done

if [[ -z "$LOCAL_FILE" || -z "$REPO" ]]; then
  echo "Usage: push-workflow.sh <local-file> <owner/repo> [<dest-path>] [--message <msg>]" >&2
  exit 1
fi

[[ -z "$DEST_PATH" ]] && DEST_PATH="$LOCAL_FILE"
[[ -z "$COMMIT_MSG" ]] && COMMIT_MSG="ci: update $(basename "$DEST_PATH")"

if [[ ! -f "$LOCAL_FILE" ]]; then
  echo "ERROR: $LOCAL_FILE not found" >&2; exit 1
fi

# ── Get current SHA if file exists ────────────────────────────────────────────
ENCODED_PATH=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$DEST_PATH")
CURRENT_SHA=$(GH_TOKEN="$GH_TOKEN" gh api \
  "repos/${REPO}/contents/${ENCODED_PATH}" \
  --jq '.sha' 2>/dev/null || echo "")

# ── Push via GitHub API ───────────────────────────────────────────────────────
echo "Pushing $LOCAL_FILE → $REPO:$DEST_PATH"
if [[ -n "$CURRENT_SHA" ]]; then
  echo "  (updating existing file, sha=${CURRENT_SHA:0:8})"
  GH_TOKEN="$GH_TOKEN" gh api "repos/${REPO}/contents/${ENCODED_PATH}" \
    --method PUT \
    -f message="$COMMIT_MSG" \
    -f sha="$CURRENT_SHA" \
    -f content="$(base64 < "$LOCAL_FILE")" \
    --jq '.content.html_url'
else
  echo "  (creating new file)"
  GH_TOKEN="$GH_TOKEN" gh api "repos/${REPO}/contents/${ENCODED_PATH}" \
    --method PUT \
    -f message="$COMMIT_MSG" \
    -f content="$(base64 < "$LOCAL_FILE")" \
    --jq '.content.html_url'
fi
echo "Done."
