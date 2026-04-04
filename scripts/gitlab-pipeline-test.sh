#!/usr/bin/env bash
# gitlab-pipeline-test.sh — Trigger, wait, and verify a GitLab ez-appsec cold:scan pipeline.
#
# Usage:
#   gitlab-pipeline-test.sh [options]
#
# Options:
#   --project   <ns/project>   GitLab project path (default: jfelten.work-group/ez_appsec/juice-shop)
#   --ref       <branch>       Branch (default: master)
#   --timeout   <seconds>      Max wait time (default: 900)
#   --download-dir <dir>       Where to save artifacts (default: /tmp/ez-appsec-gl-test)
#   --check-dashboard          Verify ingest pushed to dashboard and dashboard pipeline ran
#   --gitlab-url <url>         GitLab base URL (default: https://gitlab.com)
#
# Triggers via CI_PIPELINE_SOURCE=api which satisfies the cold:scan job rule.
#
# Exit codes:
#   0 — pipeline succeeded, vulnerabilities.json has findings
#   1 — pipeline failed or no findings
#
# Reads GITLAB_ACCESS_TOKEN from environment or 2026/.env.
set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
PROJECT="jfelten.work-group/ez_appsec/juice-shop"
REF="master"
TIMEOUT=900
DOWNLOAD_DIR="/tmp/ez-appsec-gl-test"
CHECK_DASHBOARD=false
GITLAB_URL="https://gitlab.com"

# ── Resolve token ─────────────────────────────────────────────────────────────
ENV_FILE="$(dirname "$0")/../../.env"
[[ -f "$ENV_FILE" ]] && source "$ENV_FILE" 2>/dev/null || true
GITLAB_TOKEN="${GITLAB_ACCESS_TOKEN:-${GITLAB_TOKEN:-}}"
if [[ -z "$GITLAB_TOKEN" ]]; then
  echo "ERROR: set GITLAB_ACCESS_TOKEN" >&2; exit 1
fi

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --project)        PROJECT="$2"; shift 2 ;;
    --ref)            REF="$2"; shift 2 ;;
    --timeout)        TIMEOUT="$2"; shift 2 ;;
    --download-dir)   DOWNLOAD_DIR="$2"; shift 2 ;;
    --check-dashboard) CHECK_DASHBOARD=true; shift ;;
    --gitlab-url)     GITLAB_URL="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
log() { echo "[$(date +%H:%M:%S)] $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

gl_api() {
  local path="$1"; shift
  curl -sf --header "PRIVATE-TOKEN: $GITLAB_TOKEN" "$@" "${GITLAB_URL}/api/v4/${path}"
}

# URL-encode a project path (slashes become %2F)
encode_project() {
  python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$1"
}

ENC_PROJECT=$(encode_project "$PROJECT")

# ── Step 0: resolve project ID ────────────────────────────────────────────────
PROJECT_ID=$(gl_api "projects/${ENC_PROJECT}" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
log "Project: $PROJECT  (id=$PROJECT_ID)"

# ── Step 1: verify required group variables exist ─────────────────────────────
log "Checking group CI variables..."
NS=$(python3 -c "import sys; parts=sys.argv[1].split('/'); print('/'.join(parts[:-1]))" "$PROJECT")
ENC_NS=$(encode_project "$NS")
DASH_PROJECT=$(gl_api "groups/${ENC_NS}/variables/EZ_APPSEC_DASHBOARD_PROJECT" \
  2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['value'])" 2>/dev/null || echo "")
DEPLOY_KEY_SET=$(gl_api "groups/${ENC_NS}/variables/EZ_APPSEC_DASHBOARD_DEPLOY_KEY" \
  2>/dev/null | python3 -c "import json,sys; print('yes' if json.load(sys.stdin)['value'] else 'no')" 2>/dev/null || echo "no")
log "  EZ_APPSEC_DASHBOARD_PROJECT=${DASH_PROJECT:-NOT SET}"
log "  EZ_APPSEC_DASHBOARD_DEPLOY_KEY=${DEPLOY_KEY_SET}"

# ── Step 2: trigger pipeline via API source (activates cold:scan) ─────────────
log "Triggering pipeline on $PROJECT@$REF (source=api → cold:scan) ..."
RESPONSE=$(gl_api "projects/${PROJECT_ID}/pipeline" \
  --request POST \
  --data "ref=${REF}" )
PIPELINE_ID=$(echo "$RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
log "Pipeline #${PIPELINE_ID}  →  ${GITLAB_URL}/${PROJECT}/-/pipelines/${PIPELINE_ID}"

# ── Step 3: poll until done ───────────────────────────────────────────────────
ELAPSED=0
POLL=20
while true; do
  STATUS=$(gl_api "projects/${PROJECT_ID}/pipelines/${PIPELINE_ID}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
  log "  status=$STATUS (${ELAPSED}s elapsed)"

  if [[ "$STATUS" == "success" || "$STATUS" == "failed" || "$STATUS" == "canceled" ]]; then
    break
  fi

  if (( ELAPSED >= TIMEOUT )); then
    fail "Timed out after ${TIMEOUT}s waiting for pipeline $PIPELINE_ID"
  fi

  sleep $POLL
  (( ELAPSED += POLL )) || true
done

if [[ "$STATUS" != "success" ]]; then
  log "Pipeline jobs:"
  gl_api "projects/${PROJECT_ID}/pipelines/${PIPELINE_ID}/jobs" | \
    python3 -c "
import json,sys
jobs=json.load(sys.stdin)
for j in jobs:
    print(f'  [{j[\"status\"]:8}] {j[\"name\"]}')" || true
  fail "Pipeline $PIPELINE_ID ended with status=$STATUS"
fi

# ── Step 4: show job summary ──────────────────────────────────────────────────
log "Pipeline succeeded. Jobs:"
gl_api "projects/${PROJECT_ID}/pipelines/${PIPELINE_ID}/jobs" | \
  python3 -c "
import json,sys
jobs=json.load(sys.stdin)
for j in sorted(jobs, key=lambda x: x.get('started_at','')):
    d = round(j.get('duration') or 0)
    print(f'  [{j[\"status\"]:8}] {j[\"name\"]:30} {d}s')"

# ── Step 5: find cold:scan job and download artifact ─────────────────────────
COLD_JOB_ID=$(gl_api "projects/${PROJECT_ID}/pipelines/${PIPELINE_ID}/jobs" | \
  python3 -c "
import json,sys
jobs=json.load(sys.stdin)
for j in jobs:
    if j['name'] == 'cold:scan' and j['status'] == 'success':
        print(j['id'])
        break
" || echo "")

if [[ -z "$COLD_JOB_ID" ]]; then
  fail "No successful cold:scan job found in pipeline $PIPELINE_ID"
fi
log "cold:scan job ID: $COLD_JOB_ID"

rm -rf "$DOWNLOAD_DIR" && mkdir -p "$DOWNLOAD_DIR"
log "Downloading artifact..."
curl -sf --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  --location \
  "${GITLAB_URL}/api/v4/projects/${PROJECT_ID}/jobs/${COLD_JOB_ID}/artifacts" \
  -o "${DOWNLOAD_DIR}/artifacts.zip" || fail "Could not download artifact"

cd "$DOWNLOAD_DIR" && unzip -o artifacts.zip > /dev/null 2>&1
VULN_FILE=$(find "$DOWNLOAD_DIR" -name "vulnerabilities.json" | head -1)
[[ -z "$VULN_FILE" ]] && fail "vulnerabilities.json not found in artifact"

# ── Step 6: verify findings ───────────────────────────────────────────────────
COUNT=$(python3 -c "
import json
with open('$VULN_FILE') as f:
    d = json.load(f)
vulns = d.get('vulnerabilities', [])
sev = {}
for v in vulns:
    s = v.get('severity','unknown')
    sev[s] = sev.get(s,0) + 1
print(len(vulns))
for s,c in sorted(sev.items()):
    print(f'  {s}: {c}')
")
TOTAL=$(echo "$COUNT" | head -1)
log "vulnerabilities.json: total=${TOTAL} findings"
echo "$COUNT" | tail -n +2 | while read line; do log "  $line"; done

[[ "$TOTAL" -eq 0 ]] && fail "vulnerabilities.json has 0 findings — scanner may not be running"

# ── Step 7: optionally check dashboard ────────────────────────────────────────
if $CHECK_DASHBOARD && [[ -n "$DASH_PROJECT" ]]; then
  log "Checking dashboard: $DASH_PROJECT ..."
  ENC_DASH=$(encode_project "$DASH_PROJECT")
  DASH_ID=$(gl_api "projects/${ENC_DASH}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")
  if [[ -n "$DASH_ID" ]]; then
    LATEST_COMMIT=$(gl_api "projects/${DASH_ID}/repository/commits?per_page=1" \
      | python3 -c "import json,sys; c=json.load(sys.stdin)[0]; print(f'{c[\"short_id\"]} {c[\"created_at\"][:19]} {c[\"title\"]}')" 2>/dev/null || echo "none")
    log "  Latest dashboard commit: $LATEST_COMMIT"
    LATEST_PIPE=$(gl_api "projects/${DASH_ID}/pipelines?per_page=1" \
      | python3 -c "import json,sys; p=json.load(sys.stdin)[0]; print(f'#{p[\"id\"]} {p[\"status\"]} {p[\"created_at\"][:19]}')" 2>/dev/null || echo "none")
    log "  Latest dashboard pipeline: $LATEST_PIPE"
  else
    log "  WARN: could not resolve dashboard project ID"
  fi
fi

# ── Step 8: summary ───────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo "PASS: GitLab pipeline test succeeded"
echo "  Project:  $PROJECT"
echo "  Pipeline: ${GITLAB_URL}/${PROJECT}/-/pipelines/${PIPELINE_ID}"
echo "  Findings: $TOTAL"
echo "  Artifacts: $DOWNLOAD_DIR"
echo "========================================"
