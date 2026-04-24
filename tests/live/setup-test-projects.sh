#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# ez-appsec test project setup script
#
# Forks vulnerable test apps (juice-shop, dvwa, webgoat, bwapp) into the
# ez-appsec GitHub org and a GitLab group, installs the ez-appsec scanner on
# each, triggers scans, and verifies that the dashboard gets updated.
#
# Usage:
#   ./setup-test-projects.sh [--github-only | --gitlab-only] [--no-verify]
#
# Required env vars (or loaded from /Users/johnfelten/git/2026/.env):
#   GH_PAT        GitHub PAT — needs: repo, delete_repo, packages:read,
#                              security_events, workflow scopes
#   GITLAB_PAT    GitLab PAT — needs: api scope
#
# Optional overrides:
#   GITHUB_ORG       default: ez-appsec
#   GITLAB_GROUP     default: jfelten.work-group/ez_appsec
#   GITHUB_DASHBOARD default: ez-appsec/ez-appsec-dashboard
#   GITLAB_DASHBOARD default: jfelten.work-group/ez_appsec/ez-appsec-dashboard
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EZ_APPSEC_SRC="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ─── Load .env from parent git root ─────────────────────────────────────────
ENV_FILE="${EZ_APPSEC_SRC}/../.env"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC2163
  while IFS='=' read -r key value; do
    [[ "$key" =~ ^#|^$ ]] && continue
    export "$key"="$value"
  done < "$ENV_FILE"
fi

# ─── Config ─────────────────────────────────────────────────────────────────
GITHUB_ORG="${GITHUB_ORG:-ez-appsec}"
GITLAB_GROUP="${GITLAB_GROUP:-jfelten.work-group/ez_appsec}"
GITHUB_DASHBOARD="${GITHUB_DASHBOARD:-ez-appsec/ez-appsec-dashboard}"
GITLAB_DASHBOARD="${GITLAB_DASHBOARD:-jfelten.work-group/ez_appsec/ez-appsec-dashboard}"

# PAT used both to authenticate gh CLI ops and as DASHBOARD_PUSH_TOKEN
GH_PAT="${GH_PAT:-${GITHUB_ACCESS_TOKEN:-}}"
GITLAB_PAT="${GITLAB_PAT:-${GITLAB_ACCESS_TOKEN:-}}"

# Where to persist the GitLab deploy key between runs
DEPLOY_KEY_DIR="${HOME}/.ez-appsec/deploy-key"

# Scan verification timeout (seconds per project)
VERIFY_TIMEOUT="${VERIFY_TIMEOUT:-600}"   # 10 minutes

# ─── Test projects: "slug|github_upstream" ──────────────────────────────────
declare -a TEST_PROJECTS=(
  "juice-shop|juice-shop/juice-shop"
  "dvwa|digininja/DVWA"
  "webgoat|WebGoat/WebGoat"
  "bwapp|raesene/bWAPP"
)

# ─── Flags ──────────────────────────────────────────────────────────────────
RUN_GITHUB=true
RUN_GITLAB=true
RUN_VERIFY=true

for arg in "$@"; do
  case "$arg" in
    --github-only) RUN_GITLAB=false ;;
    --gitlab-only) RUN_GITHUB=false ;;
    --no-verify)   RUN_VERIFY=false ;;
  esac
done

# ─── Colour helpers ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()   { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ ERR]${NC} $*" >&2; }
die()  { err "$*"; exit 1; }
hr()   { echo -e "${CYAN}${BOLD}────────────────────────────────────────────────────${NC}"; }
hdr()  { hr; echo -e "${CYAN}${BOLD}  $*${NC}"; hr; }

# ─── Utilities ───────────────────────────────────────────────────────────────
urlencode() { python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$1"; }
b64file()   { base64 < "$1" | tr -d '\n'; }
b64str()    { printf '%s' "$1" | base64 | tr -d '\n'; }

# Run gh with the PAT set
gh()   { GH_TOKEN="$GH_PAT" command gh "$@"; }

# Run glab with the PAT set
glab() { GITLAB_TOKEN="$GITLAB_PAT" command glab "$@"; }

# GitLab API shortcut
gl_api() { GITLAB_TOKEN="$GITLAB_PAT" command glab api "$@"; }

# ─── Prerequisites ────────────────────────────────────────────────────────────
check_prereqs() {
  hdr "Checking prerequisites"
  local missing=()
  for cmd in gh glab python3 git curl jq ssh-keygen base64; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  [[ ${#missing[@]} -gt 0 ]] && die "Missing required tools: ${missing[*]}"

  if $RUN_GITHUB && [[ -z "$GH_PAT" ]]; then
    die "GH_PAT (or GITHUB_ACCESS_TOKEN) not set. Export it or add to $ENV_FILE"
  fi
  if $RUN_GITLAB && [[ -z "$GITLAB_PAT" ]]; then
    die "GITLAB_PAT (or GITLAB_ACCESS_TOKEN) not set. Export it or add to $ENV_FILE"
  fi

  ok "All prerequisites satisfied"
  log "GitHub org:       $GITHUB_ORG"
  log "GitLab group:     $GITLAB_GROUP"
  log "GitHub dashboard: $GITHUB_DASHBOARD"
  log "GitLab dashboard: $GITLAB_DASHBOARD"
}

# ═══════════════════════════════════════════════════════════════════════════════
# GITHUB
# ═══════════════════════════════════════════════════════════════════════════════

gh_project_exists() {
  gh repo view "$1" &>/dev/null 2>&1
}

gh_delete_if_exists() {
  local target="$1"
  if gh_project_exists "$target"; then
    warn "GitHub → $target exists — attempting delete..."
    if gh repo delete "$target" --yes 2>/dev/null; then
      sleep 3
      ok "GitHub → $target deleted"
      return 0   # deleted — caller should fork
    else
      warn "GitHub → could not delete $target (token lacks delete_repo scope — updating in place)"
      return 1   # still exists — caller should skip fork, just update
    fi
  fi
  return 0  # did not exist — caller should fork
}

# Track repos that should skip forking (space-separated string, bash 3 compatible)
GH_SKIP_FORK_FOR=""

gh_fork() {
  local name="$1" upstream="$2"
  local target="${GITHUB_ORG}/${name}"

  # Skip forking if the repo exists and we couldn't delete it
  if echo " $GH_SKIP_FORK_FOR " | grep -q " $name "; then
    log "GitHub [$name] → skipping fork — updating existing repo in place"
    return
  fi

  log "GitHub [$name] → forking $upstream → $target"
  gh repo fork "$upstream" --org "$GITHUB_ORG" --fork-name "$name" --clone=false 2>/dev/null || {
    warn "GitHub [$name] → fork command returned non-zero (may already exist)"
  }

  # Wait up to 60 s for the fork to appear
  local attempts=0
  until gh_project_exists "$target"; do
    ((attempts++))
    [[ $attempts -gt 12 ]] && die "GitHub [$name] → fork did not appear after 60 s"
    sleep 5
  done
  ok "GitHub [$name] → https://github.com/$target"
}

gh_install_scanner() {
  local name="$1"
  local target="${GITHUB_ORG}/${name}"

  log "GitHub [$name] → pushing ez-appsec-scan.yml..."

  # Get default branch
  local default_branch
  default_branch=$(gh repo view "$target" --json defaultBranchRef --jq '.defaultBranchRef.name')

  # Check if workflow file already exists (get its sha for PUT)
  local existing_sha=""
  existing_sha=$(gh api "repos/${target}/contents/.github/workflows/ez-appsec-scan.yml" \
    --jq '.sha' 2>/dev/null || true)

  local workflow_b64
  workflow_b64=$(b64file "${EZ_APPSEC_SRC}/.github/workflows/github-scan.yml")

  if [[ -n "$existing_sha" ]]; then
    gh api --method PUT "repos/${target}/contents/.github/workflows/ez-appsec-scan.yml" \
      -f message="ci: update ez-appsec security scan workflow" \
      -f content="$workflow_b64" \
      -f sha="$existing_sha" \
      -f branch="$default_branch" &>/dev/null
    ok "GitHub [$name] → workflow updated"
  else
    gh api --method PUT "repos/${target}/contents/.github/workflows/ez-appsec-scan.yml" \
      -f message="ci: install ez-appsec security scan workflow" \
      -f content="$workflow_b64" \
      -f branch="$default_branch" &>/dev/null
    ok "GitHub [$name] → workflow installed"
  fi

  # Set DASHBOARD_PUSH_TOKEN secret
  log "GitHub [$name] → setting DASHBOARD_PUSH_TOKEN secret..."
  printf '%s' "$GH_PAT" | gh secret set DASHBOARD_PUSH_TOKEN --repo="$target" --body -
  ok "GitHub [$name] → DASHBOARD_PUSH_TOKEN set"

  # Set EZ_APPSEC_DASHBOARD_REPO variable
  log "GitHub [$name] → setting EZ_APPSEC_DASHBOARD_REPO variable..."
  gh api --method PUT "repos/${target}/actions/variables/EZ_APPSEC_DASHBOARD_REPO" \
    -f name="EZ_APPSEC_DASHBOARD_REPO" \
    -f value="$GITHUB_DASHBOARD" &>/dev/null 2>/dev/null || \
  gh variable set EZ_APPSEC_DASHBOARD_REPO \
    --repo="$target" --body "$GITHUB_DASHBOARD" &>/dev/null || true
  ok "GitHub [$name] → EZ_APPSEC_DASHBOARD_REPO=$GITHUB_DASHBOARD"
}

gh_trigger_scan() {
  local name="$1"
  local target="${GITHUB_ORG}/${name}"

  log "GitHub [$name] → triggering ez-appsec-scan.yml..."
  if gh workflow run ez-appsec-scan.yml --repo "$target" 2>/dev/null; then
    ok "GitHub [$name] → scan triggered"
  else
    warn "GitHub [$name] → could not trigger via workflow_dispatch — scan will run on next push"
  fi
}

# Returns the slug used for the dashboard directory
gh_slug() {
  local name="$1"
  echo "${GITHUB_ORG}/${name}" \
    | tr '/' '-' | tr '.' '-' | tr '_' '-' | tr '[:upper:]' '[:lower:]'
}

gh_verify_dashboard() {
  local name="$1"
  local slug
  slug=$(gh_slug "$name")

  if ! $RUN_VERIFY; then
    log "GitHub [$name] → verification skipped (--no-verify)"
    return
  fi

  log "GitHub [$name] → waiting for dashboard (slug=$slug, timeout=${VERIFY_TIMEOUT}s)..."

  local elapsed=0
  while [[ $elapsed -lt $VERIFY_TIMEOUT ]]; do
    local found
    found=$(curl -sf \
      -H "Authorization: token $GH_PAT" \
      -H "Cache-Control: no-cache" \
      "https://raw.githubusercontent.com/${GITHUB_DASHBOARD}/main/data/index.json" \
      2>/dev/null | \
      python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(any(p.get('slug') == '$slug' for p in d.get('projects', [])))
except:
    print('False')
" 2>/dev/null || echo "False")

    if [[ "$found" == "True" ]]; then
      ok "GitHub [$name] → dashboard updated (slug=$slug)"
      return
    fi

    sleep 15
    elapsed=$((elapsed + 15))
    log "GitHub [$name] → still waiting... ${elapsed}s/${VERIFY_TIMEOUT}s"
  done

  warn "GitHub [$name] → dashboard not updated within ${VERIFY_TIMEOUT}s — check manually"
  log "  Run ID: gh run list --repo ${GITHUB_ORG}/${name} --limit 1"
  log "  Dashboard: https://ez-appsec.github.io/ez-appsec-dashboard/"
}

# ═══════════════════════════════════════════════════════════════════════════════
# GITLAB
# ═══════════════════════════════════════════════════════════════════════════════

gl_get_group_id() {
  local group_path="$1"
  local encoded
  encoded=$(urlencode "$group_path")
  gl_api "groups/${encoded}" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])"
}

gl_get_project_id() {
  local project_path="$1"
  local encoded
  encoded=$(urlencode "$project_path")
  gl_api "projects/${encoded}" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo ""
}

gl_delete_if_exists() {
  local project_path="$1"
  local name="${project_path##*/}"
  local encoded
  encoded=$(urlencode "$project_path")

  local project_id
  project_id=$(gl_api "projects/${encoded}" 2>/dev/null | \
    python3 -c "import json,sys; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")

  if [[ -n "$project_id" ]]; then
    warn "GitLab [$name] → $project_path exists (id=$project_id) — deleting..."
    gl_api --method DELETE "projects/${project_id}" &>/dev/null

    # Wait for deletion
    local attempts=0
    while gl_api "projects/${encoded}" &>/dev/null 2>&1; do
      ((attempts++))
      [[ $attempts -gt 18 ]] && die "GitLab [$name] → deletion timed out after 90 s"
      sleep 5
    done
    ok "GitLab [$name] → deleted"
  fi
}

# Global variable for gl_import_project result (avoids subshell swallowing logs)
GL_IMPORTED_PROJECT_ID=""

gl_import_project() {
  GL_IMPORTED_PROJECT_ID=""
  local name="$1"
  local upstream="$2"   # e.g. "juice-shop/juice-shop"
  local group_path="$3"
  local group_id
  group_id=$(gl_get_group_id "$group_path")

  log "GitLab [$name] → importing https://github.com/$upstream into $group_path..."

  local response
  response=$(gl_api --method POST "projects" \
    --field name="$name" \
    --field path="$name" \
    --field namespace_id="$group_id" \
    --field import_url="https://github.com/${upstream}.git" \
    --field visibility="public" \
    --field initialize_with_readme=false 2>&1) || {
    err "GitLab [$name] → import request failed: $response"
    return
  }

  local project_id
  project_id=$(echo "$response" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")

  if [[ -z "$project_id" ]]; then
    err "GitLab [$name] → could not parse project id from response"
    return
  fi

  log "GitLab [$name] → import started (id=$project_id), polling status..."

  # Poll import status (up to 5 minutes)
  local attempts=0
  local import_status=""
  while true; do
    ((attempts++))
    import_status=$(gl_api "projects/${project_id}" 2>/dev/null | \
      python3 -c "import json,sys; print(json.load(sys.stdin).get('import_status','unknown'))" 2>/dev/null || echo "unknown")

    case "$import_status" in
      finished)
        ok "GitLab [$name] → import finished (id=$project_id)"
        GL_IMPORTED_PROJECT_ID="$project_id"
        return
        ;;
      failed)
        warn "GitLab [$name] → import failed — project may be partially created (id=$project_id)"
        GL_IMPORTED_PROJECT_ID="$project_id"
        return
        ;;
      none|"")
        ok "GitLab [$name] → import complete (id=$project_id)"
        GL_IMPORTED_PROJECT_ID="$project_id"
        return
        ;;
    esac

    if [[ $attempts -gt 30 ]]; then
      warn "GitLab [$name] → import status='$import_status' after 5 min — continuing anyway (id=$project_id)"
      GL_IMPORTED_PROJECT_ID="$project_id"
      return
    fi
    sleep 10
  done
}

gl_install_scanner() {
  local project_id="$1"
  local name="$2"

  log "GitLab [$name] → patching .gitlab-ci.yml with ez-appsec include..."

  # Fetch existing .gitlab-ci.yml (may not exist)
  local current_ci=""
  local file_info
  file_info=$(gl_api "projects/${project_id}/repository/files/.gitlab-ci.yml?ref=main" 2>/dev/null || \
              gl_api "projects/${project_id}/repository/files/.gitlab-ci.yml?ref=master" 2>/dev/null || echo "")

  if [[ -n "$file_info" ]]; then
    current_ci=$(echo "$file_info" | python3 -c "
import json,sys,base64
d=json.load(sys.stdin)
print(base64.b64decode(d['content']).decode('utf-8','replace'))
" 2>/dev/null || echo "")
  fi

  # Skip if already installed
  if echo "$current_ci" | grep -q "ez-appsec\|scan\.yml"; then
    ok "GitLab [$name] → ez-appsec already present in .gitlab-ci.yml"
    return
  fi

  # Build new .gitlab-ci.yml
  local new_ci
  new_ci=$(python3 << 'PYEOF'
import sys, textwrap

INCLUDE_BLOCK = textwrap.dedent("""\
    include:
      - remote: 'https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/gitlab/scan.yml'
    """)

STAGES_BLOCK = textwrap.dedent("""\
    stages:
      - .pre
      - ez-appsec
      - build
      - test
      - deploy
      - .post
    """)

existing = """EXISTING_CI_PLACEHOLDER"""

if not existing.strip():
    result = STAGES_BLOCK + "\n" + INCLUDE_BLOCK
else:
    # Prepend include if not present
    if 'include:' not in existing:
        result = INCLUDE_BLOCK + "\n" + existing
    else:
        result = existing
    # Add stages if not present
    if 'stages:' not in result:
        result = STAGES_BLOCK + "\n" + result

print(result.rstrip())
PYEOF
)
  # Replace placeholder with actual content (escape for sed)
  new_ci="${new_ci//EXISTING_CI_PLACEHOLDER/$current_ci}"

  # Re-run with actual content (use python for safety)
  new_ci=$(python3 -c "
import textwrap

INCLUDE_BLOCK = '''include:
  - remote: 'https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/gitlab/scan.yml'
'''

STAGES_BLOCK = '''stages:
  - .pre
  - ez-appsec
  - build
  - test
  - deploy
  - .post
'''

existing = open('/dev/stdin').read()

if not existing.strip():
    result = STAGES_BLOCK + '\n' + INCLUDE_BLOCK
elif 'include:' not in existing and 'scan.yml' not in existing:
    result = INCLUDE_BLOCK + '\n' + existing
    if 'stages:' not in result:
        result = STAGES_BLOCK + '\n' + result
else:
    result = existing

print(result.rstrip())
" <<< "$current_ci")

  # Get current branch
  local default_branch
  default_branch=$(gl_api "projects/${project_id}" | \
    python3 -c "import json,sys; print(json.load(sys.stdin).get('default_branch','main'))" 2>/dev/null || echo "main")

  # Encode and push via curl (glab api crashes on dotted URL paths)
  local encoded_ci
  encoded_ci=$(printf '%s' "$new_ci" | base64 | tr -d '\n')

  # GitLab Files API: file_path must be URL-encoded in the path
  local file_path_encoded
  file_path_encoded=$(urlencode ".gitlab-ci.yml")

  # Build JSON body in a temp file
  local json_tmp
  json_tmp=$(mktemp /tmp/ez-appsec-ci-XXXXXX.json)
  python3 -c "
import json, sys
body = {
    'branch': '$default_branch',
    'content': sys.stdin.read().strip(),
    'encoding': 'base64',
    'commit_message': 'ci: install ez-appsec security scanning'
}
print(json.dumps(body))
" <<< "$encoded_ci" > "$json_tmp"

  gl_files_api() {
    local method="$1"
    curl -s \
      -X "$method" \
      -H "PRIVATE-TOKEN: $GITLAB_PAT" \
      -H "Content-Type: application/json" \
      "https://gitlab.com/api/v4/projects/${project_id}/repository/files/${file_path_encoded}" \
      --data "@${json_tmp}" \
      -w "%{http_code}" -o /tmp/ez-appsec-curl-resp.json 2>/dev/null || echo "000"
  }

  local http_status
  # Try POST first; if 400 "already exists", retry with PUT
  if [[ -z "$current_ci" ]]; then
    http_status=$(gl_files_api POST)
    if [[ "$http_status" == "400" ]]; then
      http_status=$(gl_files_api PUT)
    fi
  else
    http_status=$(gl_files_api PUT)
    if [[ "$http_status" == "404" ]]; then
      http_status=$(gl_files_api POST)
    fi
  fi

  rm -f "$json_tmp"

  if [[ "$http_status" =~ ^2 ]]; then
    ok "GitLab [$name] → .gitlab-ci.yml updated (HTTP $http_status)"
  else
    local err_msg
    err_msg=$(python3 -c "import json,sys; d=json.load(open('/tmp/ez-appsec-curl-resp.json')); print(d.get('message',d))" 2>/dev/null || echo "unknown")
    warn "GitLab [$name] → failed to update .gitlab-ci.yml (HTTP $http_status): $err_msg"
  fi
}

gl_set_project_var() {
  local project_id="$1" key="$2" value="$3" masked="${4:-false}"
  gl_api --method POST "projects/${project_id}/variables" \
    --field key="$key" \
    --field value="$value" \
    --field masked="$masked" \
    --field protected=false &>/dev/null 2>/dev/null || \
  gl_api --method PUT "projects/${project_id}/variables/${key}" \
    --field value="$value" \
    --field masked="$masked" &>/dev/null 2>/dev/null || true
}

gl_set_group_var() {
  local group_id="$1" key="$2" value="$3" masked="${4:-false}"
  gl_api --method POST "groups/${group_id}/variables" \
    --field key="$key" \
    --field value="$value" \
    --field masked="$masked" \
    --field protected=false &>/dev/null 2>/dev/null || \
  gl_api --method PUT "groups/${group_id}/variables/${key}" \
    --field value="$value" \
    --field masked="$masked" &>/dev/null 2>/dev/null || true
}

gl_setup_deploy_key() {
  local group_path="$1"
  local dashboard_path="$2"
  local group_id
  group_id=$(gl_get_group_id "$group_path")

  hdr "GitLab — setting up dashboard deploy key"

  # Generate key if not already created
  mkdir -p "$DEPLOY_KEY_DIR" && chmod 700 "$DEPLOY_KEY_DIR"
  local private_key="${DEPLOY_KEY_DIR}/deploy_key"
  local public_key="${DEPLOY_KEY_DIR}/deploy_key.pub"

  if [[ ! -f "$private_key" ]]; then
    log "Generating ed25519 deploy key at $DEPLOY_KEY_DIR..."
    ssh-keygen -t ed25519 -N "" -C "ez-appsec-ci@ez-appsec.ai" -f "$private_key" -q
    ok "Deploy key generated"
  else
    log "Reusing existing deploy key at $DEPLOY_KEY_DIR"
  fi

  # Register public key on dashboard project (write access = can_push: true)
  local dashboard_id
  dashboard_id=$(gl_get_project_id "$dashboard_path")
  if [[ -z "$dashboard_id" ]]; then
    warn "GitLab dashboard project '$dashboard_path' not found — skipping deploy key registration"
    warn "Create the GitLab dashboard first with: /ez-appsec-install-dashboard $group_path"
  else
    log "Registering deploy key on $dashboard_path (id=$dashboard_id) with write access..."
    local pub_key_content
    pub_key_content=$(cat "$public_key")

    gl_api --method POST "projects/${dashboard_id}/deploy_keys" \
      --field title="ez-appsec-ci" \
      --field key="$pub_key_content" \
      --field can_push=true &>/dev/null 2>/dev/null && \
      ok "GitLab → deploy key registered (write access)" || \
      warn "GitLab → deploy key registration returned error (may already exist)"
  fi

  # Store private key as group variable (base64-encoded, masked)
  local private_key_b64
  private_key_b64=$(b64file "$private_key")

  log "Setting EZ_APPSEC_DASHBOARD_DEPLOY_KEY group variable..."
  gl_set_group_var "$group_id" "EZ_APPSEC_DASHBOARD_DEPLOY_KEY" "$private_key_b64" "true"
  ok "GitLab → EZ_APPSEC_DASHBOARD_DEPLOY_KEY set in group $group_path (masked)"

  # Store dashboard project path as group variable
  log "Setting EZ_APPSEC_DASHBOARD_PROJECT group variable..."
  gl_set_group_var "$group_id" "EZ_APPSEC_DASHBOARD_PROJECT" "$dashboard_path" "false"
  ok "GitLab → EZ_APPSEC_DASHBOARD_PROJECT=$dashboard_path set in group $group_path"
}

gl_trigger_pipeline() {
  local project_id="$1"
  local name="$2"

  # Determine default branch
  local branch
  branch=$(curl -sf -H "PRIVATE-TOKEN: $GITLAB_PAT" \
    "https://gitlab.com/api/v4/projects/${project_id}" 2>/dev/null | \
    python3 -c "import json,sys; print(json.load(sys.stdin).get('default_branch','main'))" 2>/dev/null || echo "main")

  log "GitLab [$name] → triggering cold:scan pipeline on branch $branch..."

  # Use curl for the pipeline trigger (glab api may crash)
  local body='{"ref":"'"$branch"'","variables":[{"key":"EZ_APPSEC_COLD_SCAN","value":"true"}]}'
  local response
  local http_status
  # Trigger without custom variables — CI_PIPELINE_SOURCE=api satisfies cold:scan rule
  http_status=$(curl -s \
    -X POST \
    -H "PRIVATE-TOKEN: $GITLAB_PAT" \
    "https://gitlab.com/api/v4/projects/${project_id}/pipeline?ref=${branch}" \
    -w "%{http_code}" -o /tmp/ez-appsec-pipeline-resp.json 2>/dev/null) || http_status="000"

  if [[ "$http_status" =~ ^2 ]]; then
    local pipeline_id
    pipeline_id=$(python3 -c "import json,sys; print(json.load(open('/tmp/ez-appsec-pipeline-resp.json')).get('id','?'))" 2>/dev/null || echo "?")
    ok "GitLab [$name] → pipeline #$pipeline_id triggered"
    log "GitLab [$name] → track: https://gitlab.com/${GITLAB_GROUP}/${name}/-/pipelines"
  else
    local err_msg
    err_msg=$(python3 -c "import json,sys; d=json.load(open('/tmp/ez-appsec-pipeline-resp.json')); print(d.get('message',d))" 2>/dev/null || echo "unknown")
    warn "GitLab [$name] → pipeline trigger failed (HTTP $http_status): $err_msg"
    warn "GitLab [$name] → NOTE: scans will fail until ghcr.io/ez-appsec/ez-appsec is public"
    warn "              Make public: https://github.com/orgs/ez-appsec/packages/container/ez-appsec/settings"
  fi
}

gl_verify_dashboard() {
  local name="$1"
  local group_path="$2"

  if ! $RUN_VERIFY; then
    log "GitLab [$name] → verification skipped (--no-verify)"
    return
  fi

  # GitLab project path slug: lowercase, replace / . _ with -
  local slug
  slug=$(echo "${group_path}/${name}" | \
    tr '[:upper:]' '[:lower:]' | tr '/' '-' | tr '.' '-' | tr '_' '-')

  log "GitLab [$name] → pipeline may fail until GHCR image is made public"
  log "GitLab [$name] → when scan succeeds, dashboard slug will be: $slug"
  log "GitLab [$name] → to make GHCR image public:"
  log "             https://github.com/orgs/ez-appsec/packages/container/ez-appsec/settings"

  # Attempt to verify by polling the GitLab dashboard
  local dashboard_id
  dashboard_id=$(gl_get_project_id "$GITLAB_DASHBOARD")
  if [[ -z "$dashboard_id" ]]; then
    warn "GitLab [$name] → dashboard project not found — cannot verify"
    return
  fi

  local elapsed=0
  while [[ $elapsed -lt $VERIFY_TIMEOUT ]]; do
    local found
    found=$(gl_api "projects/${dashboard_id}/repository/files/public%2Fdata%2Findex.json?ref=main" \
      2>/dev/null | \
      python3 -c "
import json,sys,base64
try:
  d=json.load(sys.stdin)
  idx=json.loads(base64.b64decode(d['content']))
  print(any(p.get('slug')=='$slug' for p in idx.get('projects',[])))
except:
  print('False')
" 2>/dev/null || echo "False")

    if [[ "$found" == "True" ]]; then
      ok "GitLab [$name] → dashboard updated (slug=$slug)"
      return
    fi

    sleep 15
    elapsed=$((elapsed + 15))
    log "GitLab [$name] → not in dashboard yet... ${elapsed}s/${VERIFY_TIMEOUT}s"
  done

  warn "GitLab [$name] → dashboard not updated within ${VERIFY_TIMEOUT}s"
  log "         This is expected if the GHCR image is still private"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

main() {
  hdr "ez-appsec test project setup"

  check_prereqs

  # ── GitHub phase ────────────────────────────────────────────────────────────
  if $RUN_GITHUB; then
    hdr "GITHUB — fork + install scanner"

    for entry in "${TEST_PROJECTS[@]}"; do
      local name="${entry%%|*}"
      local upstream="${entry##*|}"
      local target="${GITHUB_ORG}/${name}"

      hr
      log "GitHub [$name] — upstream: $upstream"

      if ! gh_delete_if_exists "$target"; then
        # Repo exists and couldn't be deleted — update in place
        GH_SKIP_FORK_FOR="$GH_SKIP_FORK_FOR $name"
      fi
      gh_fork "$name" "$upstream"
      gh_install_scanner "$name"
    done

    hdr "GITHUB — triggering scans"
    for entry in "${TEST_PROJECTS[@]}"; do
      local name="${entry%%|*}"
      gh_trigger_scan "$name"
    done

    hdr "GITHUB — verifying dashboard updates"
    for entry in "${TEST_PROJECTS[@]}"; do
      local name="${entry%%|*}"
      gh_verify_dashboard "$name"
    done
  fi

  # ── GitLab phase ────────────────────────────────────────────────────────────
  if $RUN_GITLAB; then
    hdr "GITLAB — setting up deploy key + group variables"
    gl_setup_deploy_key "$GITLAB_GROUP" "$GITLAB_DASHBOARD"

    hdr "GITLAB — import + install scanner"
    # Store project IDs as colon-separated "name:id" strings (bash 3 compatible)
    GL_PROJECT_ID_MAP=""

    for entry in "${TEST_PROJECTS[@]}"; do
      local name="${entry%%|*}"
      local upstream="${entry##*|}"
      local project_path="${GITLAB_GROUP}/${name}"

      hr
      log "GitLab [$name] — upstream: $upstream"

      gl_delete_if_exists "$project_path"
      gl_import_project "$name" "$upstream" "$GITLAB_GROUP"

      local project_id="$GL_IMPORTED_PROJECT_ID"
      if [[ -n "$project_id" ]]; then
        GL_PROJECT_ID_MAP="$GL_PROJECT_ID_MAP $name:$project_id"
        gl_install_scanner "$project_id" "$name"
        gl_set_project_var "$project_id" "EZ_APPSEC_VERSION" "latest"
        ok "GitLab [$name] → EZ_APPSEC_VERSION=latest"
      else
        warn "GitLab [$name] → import returned no project ID — skipping"
      fi
    done

    hdr "GITLAB — triggering pipelines"
    for entry in "${TEST_PROJECTS[@]}"; do
      local name="${entry%%|*}"
      # Extract project_id for this name from the map
      local project_id
      project_id=$(echo "$GL_PROJECT_ID_MAP" | tr ' ' '\n' | grep "^$name:" | cut -d: -f2 | head -1)
      if [[ -n "$project_id" ]]; then
        gl_trigger_pipeline "$project_id" "$name"
      fi
    done

    hdr "GITLAB — verifying dashboard updates"
    for entry in "${TEST_PROJECTS[@]}"; do
      local name="${entry%%|*}"
      gl_verify_dashboard "$name" "$GITLAB_GROUP"
    done
  fi

  # ── Summary ─────────────────────────────────────────────────────────────────
  hdr "DONE"

  if $RUN_GITHUB; then
    echo -e "${GREEN}GitHub:${NC}"
    for entry in "${TEST_PROJECTS[@]}"; do
      local name="${entry%%|*}"
      echo "  • https://github.com/${GITHUB_ORG}/${name}"
    done
    echo -e "${GREEN}GitHub dashboard:${NC} https://ez-appsec.github.io/ez-appsec-dashboard/"
    echo ""
  fi

  if $RUN_GITLAB; then
    echo -e "${GREEN}GitLab:${NC}"
    for entry in "${TEST_PROJECTS[@]}"; do
      local name="${entry%%|*}"
      echo "  • https://gitlab.com/${GITLAB_GROUP}/${name}"
    done
    local top_group="${GITLAB_GROUP%%/*}"
    local rest="${GITLAB_GROUP#*/}"
    if [[ "$rest" == "$GITLAB_GROUP" ]]; then
      echo -e "${GREEN}GitLab dashboard:${NC} https://${top_group}.gitlab.io/ez-appsec-dashboard/"
    else
      echo -e "${GREEN}GitLab dashboard:${NC} https://${top_group}.gitlab.io/${rest}/ez-appsec-dashboard/"
    fi
    echo ""
    echo -e "${YELLOW}NOTE:${NC} GitLab scans will fail until the GHCR image is made public:"
    echo "       https://github.com/orgs/ez-appsec/packages/container/ez-appsec/settings"
  fi

  hr
}

main "$@"
