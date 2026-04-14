#!/usr/bin/env bash
# github-pipeline-test.sh — Trigger, wait, and verify a GitHub Actions scan pipeline.
#
# Usage:
#   github-pipeline-test.sh [options]
#
# Options:
#   --repo      <owner/repo>   Target repo  (default: ez-appsec/juice-shop-public)
#   --workflow  <filename>     Workflow name (default: ez-appsec-scan.yml)
#   --ref       <branch>       Branch to run on (default: master)
#   --timeout   <seconds>      Max wait time  (default: 600)
#   --push-workflow <file>     Push this local workflow file before triggering
#   --dest-path <path>         Destination path for --push-workflow
#   --download-dir <dir>       Where to save artifacts (default: /tmp/ez-appsec-gh-test)
#   --check-sarif              Also verify the SARIF artifact has findings
#   --check-dashboard          Verify scan pushed results to ez-appsec-dashboard
#   --dashboard-repo <r>       Dashboard repo to check (default: ez-appsec/ez-appsec-dashboard)
#
# Exit codes:
#   0 — pipeline succeeded and vulnerabilities.json has findings
#   1 — pipeline failed or no findings
#
# Reads GH_TOKEN or GITHUB_ACCESS_TOKEN from environment or 2026/.env.
set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
REPO="ez-appsec/juice-shop-public"
WORKFLOW="ez-appsec-scan.yml"
REF="master"
TIMEOUT=600
PUSH_WORKFLOW=""
DEST_PATH=""
DOWNLOAD_DIR="/tmp/ez-appsec-gh-test"
CHECK_SARIF=false
CHECK_DASHBOARD=false
DASHBOARD_REPO="ez-appsec/ez-appsec-dashboard"

# ── Resolve token ─────────────────────────────────────────────────────────────
ENV_FILE="$(dirname "$0")/../../../.env"
[[ -f "$ENV_FILE" ]] && source "$ENV_FILE" 2>/dev/null || true
GH_TOKEN="${GH_TOKEN:-${GITHUB_ACCESS_TOKEN:-}}"
if [[ -z "$GH_TOKEN" ]]; then
  echo "ERROR: set GH_TOKEN or GITHUB_ACCESS_TOKEN" >&2; exit 1
fi
export GH_TOKEN

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)          REPO="$2"; shift 2 ;;
    --workflow)      WORKFLOW="$2"; shift 2 ;;
    --ref)           REF="$2"; shift 2 ;;
    --timeout)       TIMEOUT="$2"; shift 2 ;;
    --push-workflow) PUSH_WORKFLOW="$2"; shift 2 ;;
    --dest-path)     DEST_PATH="$2"; shift 2 ;;
    --download-dir)  DOWNLOAD_DIR="$2"; shift 2 ;;
    --check-sarif)      CHECK_SARIF=true; shift ;;
    --check-dashboard)  CHECK_DASHBOARD=true; shift ;;
    --dashboard-repo)   DASHBOARD_REPO="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# ── Helper ───────────────────────────────────────────────────────────────────
log() { echo "[$(date +%H:%M:%S)] $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# ── Step 0: optionally push workflow ─────────────────────────────────────────
if [[ -n "$PUSH_WORKFLOW" ]]; then
  DEST="${DEST_PATH:-.github/workflows/$(basename "$PUSH_WORKFLOW")}"
  log "Pushing $PUSH_WORKFLOW → $REPO:$DEST"
  "$(dirname "$0")/push-workflow.sh" "$PUSH_WORKFLOW" "$REPO" "$DEST"
  sleep 5  # let GitHub process the new commit
fi

# ── Step 1: trigger workflow_dispatch ─────────────────────────────────────────
log "Triggering $WORKFLOW on $REPO@$REF ..."
gh workflow run "$WORKFLOW" --repo "$REPO" --ref "$REF"
sleep 8  # give GitHub a moment to queue the run

# ── Step 2: find the run we just triggered (most recent) ─────────────────────
RUN_ID=$(gh run list --repo "$REPO" --workflow "$WORKFLOW" \
  --limit 1 --json databaseId --jq '.[0].databaseId')
log "Run ID: $RUN_ID  →  https://github.com/$REPO/actions/runs/$RUN_ID"

# ── Step 3: poll until done ───────────────────────────────────────────────────
ELAPSED=0
POLL=15
while true; do
  STATUS=$(gh api "repos/$REPO/actions/runs/$RUN_ID" --jq '.status')
  CONCLUSION=$(gh api "repos/$REPO/actions/runs/$RUN_ID" --jq '.conclusion // "pending"')
  log "  status=$STATUS conclusion=$CONCLUSION (${ELAPSED}s elapsed)"

  if [[ "$STATUS" == "completed" ]]; then
    break
  fi

  if (( ELAPSED >= TIMEOUT )); then
    fail "Timed out after ${TIMEOUT}s waiting for run $RUN_ID"
  fi

  sleep $POLL
  (( ELAPSED += POLL )) || true
done

if [[ "$CONCLUSION" != "success" ]]; then
  log "Pipeline jobs:"
  gh run view "$RUN_ID" --repo "$REPO" 2>/dev/null || true
  fail "Pipeline $RUN_ID ended with conclusion=$CONCLUSION"
fi
log "Pipeline succeeded."

# ── Step 4: get the commit SHA from this run ──────────────────────────────────
RUN_SHA=$(gh api "repos/$REPO/actions/runs/$RUN_ID" --jq '.head_sha')
log "Head SHA: ${RUN_SHA:0:12}"

# ── Step 5: download vulnerabilities.json artifact ────────────────────────────
rm -rf "$DOWNLOAD_DIR" && mkdir -p "$DOWNLOAD_DIR"
ARTIFACT_PATTERN="ez-appsec-vulns-${RUN_SHA}"
log "Downloading artifact: $ARTIFACT_PATTERN"
gh run download "$RUN_ID" \
  --repo "$REPO" \
  --pattern "ez-appsec-vulns-*" \
  -D "$DOWNLOAD_DIR" 2>/dev/null || \
  fail "Could not download vulnerabilities.json artifact"

VULN_FILE=$(find "$DOWNLOAD_DIR" -name "vulnerabilities.json" | head -1)
[[ -z "$VULN_FILE" ]] && fail "vulnerabilities.json not found in downloaded artifact"

# ── Step 6: verify findings ───────────────────────────────────────────────────
COUNT=$(python3 -c "
import json
with open('$VULN_FILE') as f:
    d = json.load(f)
vulns = d.get('vulnerabilities', d) if isinstance(d, dict) else d
print(len(vulns))
")
log "vulnerabilities.json: $COUNT findings"
[[ "$COUNT" -eq 0 ]] && fail "vulnerabilities.json has 0 findings — scanner may not be running"

# ── Step 7: optionally verify SARIF ──────────────────────────────────────────
if $CHECK_SARIF; then
  gh run download "$RUN_ID" \
    --repo "$REPO" \
    --pattern "ez-appsec-scan-*" \
    -D "$DOWNLOAD_DIR/sarif" 2>/dev/null || true
  SARIF_FILE=$(find "$DOWNLOAD_DIR/sarif" -name "*.sarif" | head -1)
  if [[ -n "$SARIF_FILE" ]]; then
    SARIF_COUNT=$(python3 -c "
import json
with open('$SARIF_FILE') as f:
    d = json.load(f)
print(len(d['runs'][0]['results']))
")
    log "SARIF: $SARIF_COUNT findings"
  else
    log "WARN: no SARIF artifact found"
  fi
fi

# ── Step 8: optionally verify dashboard push ──────────────────────────────────
DASHBOARD_OK=true
if $CHECK_DASHBOARD; then
  REPO_NAME=$(echo "$REPO" | cut -d/ -f2)
  log "Checking dashboard push → $DASHBOARD_REPO/data/vulnerabilities/${REPO_NAME}.json"

  # Poll up to 60s for the dashboard commit to appear (push is async from scan)
  DASH_ELAPSED=0
  DASH_FOUND=false
  while (( DASH_ELAPSED < 60 )); do
    DASH_SHA=$(gh api "repos/$DASHBOARD_REPO/contents/data/vulnerabilities/${REPO_NAME}.json" \
      --jq '.sha' 2>/dev/null || echo "")
    if [[ -n "$DASH_SHA" ]]; then
      DASH_FOUND=true; break
    fi
    log "  dashboard file not yet present — waiting 10s..."
    sleep 10
    (( DASH_ELAPSED += 10 )) || true
  done

  if ! $DASH_FOUND; then
    log "FAIL: dashboard file data/vulnerabilities/${REPO_NAME}.json not found in $DASHBOARD_REPO"
    DASHBOARD_OK=false
  else
    # Verify the file has findings
    DASH_COUNT=$(gh api "repos/$DASHBOARD_REPO/contents/data/vulnerabilities/${REPO_NAME}.json" \
      --jq '.content' | base64 --decode \
      | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('vulnerabilities',d) if isinstance(d,dict) else d))")
    log "Dashboard vulnerabilities/${REPO_NAME}.json: $DASH_COUNT findings"
    if [[ "$DASH_COUNT" -eq 0 ]]; then
      log "FAIL: dashboard file has 0 findings"
      DASHBOARD_OK=false
    fi

    # Verify index.json lists this project
    INDEX_HAS=$(gh api "repos/$DASHBOARD_REPO/contents/data/index.json" \
      --jq '.content' | base64 --decode \
      | python3 -c "import json,sys; d=json.load(sys.stdin); slugs=[p['slug'] for p in d.get('projects',[])]; print('yes' if '${REPO_NAME}' in slugs else 'no')")
    if [[ "$INDEX_HAS" == "yes" ]]; then
      log "Dashboard index.json: project '${REPO_NAME}' present ✓"
    else
      log "FAIL: project '${REPO_NAME}' missing from index.json"
      DASHBOARD_OK=false
    fi
  fi

  if ! $DASHBOARD_OK; then
    log "Scan run: https://github.com/$REPO/actions/runs/$RUN_ID"
    log "Dashboard: https://github.com/$DASHBOARD_REPO"
    fail "Dashboard check failed for $REPO"
  fi
fi

# ── Step 9: summary ───────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo "PASS: GitHub pipeline test succeeded"
echo "  Repo:      $REPO"
echo "  Run:       https://github.com/$REPO/actions/runs/$RUN_ID"
echo "  Findings:  $COUNT"
if $CHECK_DASHBOARD; then
  echo "  Dashboard: https://ez-appsec.github.io/$(echo $DASHBOARD_REPO | cut -d/ -f2)/ ✓"
fi
echo "  Artifacts: $DOWNLOAD_DIR"
echo "========================================"
