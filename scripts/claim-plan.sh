#!/usr/bin/env bash
# claim-plan.sh — prepare a contribution workspace for an ez-appsec plan
#
# Usage:  bash scripts/claim-plan.sh <plan-issue-number>
# Example: bash scripts/claim-plan.sh 21
#
# What this script does (in order):
#   1. Validates all prerequisites with clear error messages
#   2. Fetches the issue body and saves it to .plan-context.md (gitignored)
#   3. Assigns the issue to you and moves it to "In Progress" on the project board
#   4. Creates a local git branch
#   5. Prints a minimal, copy-paste-ready prompt for your AI assistant
#
# Prerequisites:
#   - gh CLI authenticated (run: gh auth login)
#   - Required PAT scopes: repo, project, read:org  (browser OAuth covers all three)
#   - git configured with user.name and user.email
#   - Python 3.10+
#   - Docker running (needed to run the test suite locally)

set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────

REPO="ez-appsec/ez-appsec"
PROJECT_NUMBER=2
PROJECT_OWNER="ez-appsec"
IN_PROGRESS_OPTION_ID="47fc9ee4"
STATUS_FIELD_ID="PVTSSF_lADOEEhvmM4BUnlNzhBuhsY"
CONTEXT_FILE=".plan-context.md"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
err()  { echo -e "${RED}ERROR:${NC} $*" >&2; }
warn() { echo -e "${YELLOW}WARN:${NC}  $*" >&2; }
ok()   { echo -e "${GREEN}OK:${NC}    $*"; }

# ── Args ──────────────────────────────────────────────────────────────────────

if [[ $# -lt 1 ]]; then
  echo "Usage: bash scripts/claim-plan.sh <issue-number>"
  echo "       bash scripts/claim-plan.sh 21"
  exit 1
fi

ISSUE_NUMBER="$1"

# ── Prerequisite checks ───────────────────────────────────────────────────────

echo "Checking prerequisites..."

# gh CLI
if ! command -v gh &>/dev/null; then
  err "gh CLI not found. Install from https://cli.github.com then run: gh auth login"
  exit 1
fi

# gh auth
if ! gh auth status &>/dev/null; then
  err "Not authenticated with gh. Run: gh auth login"
  err "When prompted, choose browser-based auth to get all required scopes automatically."
  err "If using a PAT instead, it must have these scopes: repo, project, read:org"
  exit 1
fi

# PAT scope check
MISSING_SCOPES=()
TOKEN_SCOPES=$(gh auth status 2>&1 | grep "Token scopes" | sed "s/.*Token scopes: '//;s/'.*//")
for scope in repo project; do
  if ! echo "$TOKEN_SCOPES" | grep -qw "$scope"; then
    MISSING_SCOPES+=("$scope")
  fi
done
if [[ ${#MISSING_SCOPES[@]} -gt 0 ]]; then
  err "Your GitHub token is missing required scopes: ${MISSING_SCOPES[*]}"
  err ""
  err "To fix:"
  err "  Browser OAuth (recommended): gh auth login  (re-authenticate)"
  err "  PAT: create a new token at https://github.com/settings/tokens/new"
  err "       and check: repo (full), project, read:org"
  err "       Then: gh auth login --with-token < <(echo YOUR_TOKEN)"
  exit 1
fi

# git identity
if [[ -z "$(git config user.email 2>/dev/null)" ]]; then
  err "git user.email not set. Run:"
  err "  git config --global user.email 'you@example.com'"
  err "  git config --global user.name  'Your Name'"
  exit 1
fi

# Python version
if ! command -v python3 &>/dev/null; then
  err "python3 not found. Install Python 3.10+ from https://python.org"
  exit 1
fi
PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
if [[ "$PY_MAJOR" -lt 3 ]] || { [[ "$PY_MAJOR" -eq 3 ]] && [[ "$PY_MINOR" -lt 10 ]]; }; then
  err "Python 3.10+ required, found $PY_VERSION"
  exit 1
fi

# Docker (warn only — tests that need it will fail clearly)
if ! docker info &>/dev/null 2>&1; then
  warn "Docker is not running. Some tests require Docker. Start Docker Desktop before running pytest."
fi

ok "All prerequisites satisfied (Python $PY_VERSION, gh authenticated)"
echo ""

# ── Fetch issue ───────────────────────────────────────────────────────────────

echo "Fetching issue #${ISSUE_NUMBER}..."

ISSUE_JSON=$(gh issue view "$ISSUE_NUMBER" \
  --repo "$REPO" \
  --json number,title,body,labels,url 2>/dev/null) || {
  err "Could not fetch issue #${ISSUE_NUMBER} from ${REPO}."
  err "Check the issue number and that your token has 'repo' scope."
  exit 1
}

ISSUE_TITLE=$(echo "$ISSUE_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['title'])")
ISSUE_URL=$(echo "$ISSUE_JSON"   | python3 -c "import json,sys; print(json.load(sys.stdin)['url'])")
ISSUE_BODY=$(echo "$ISSUE_JSON"  | python3 -c "import json,sys; print(json.load(sys.stdin)['body'])")

# Derive branch slug from title: "[PLAN-21] Reusable Security Agent" → "plan-21-reusable-security-agent"
BRANCH_SLUG=$(echo "$ISSUE_TITLE" \
  | tr '[:upper:]' '[:lower:]' \
  | sed 's/\[//g; s/\]//g' \
  | sed 's/[^a-z0-9]/-/g' \
  | sed 's/-\+/-/g; s/^-//; s/-$//' \
  | cut -c1-60)
BRANCH_NAME="feat/${BRANCH_SLUG}"

ok "Issue: ${ISSUE_TITLE}"
ok "Branch: ${BRANCH_NAME}"

# ── Write context file ────────────────────────────────────────────────────────

cat > "$CONTEXT_FILE" <<EOF
# Plan Context
# Issue: ${ISSUE_URL}
# Branch: ${BRANCH_NAME}
# DO NOT COMMIT this file — it is gitignored.

${ISSUE_BODY}
EOF

ok "Saved plan to ${CONTEXT_FILE}"

# ── Claim issue on GitHub ─────────────────────────────────────────────────────

echo "Claiming issue..."

GH_USER=$(gh api user --jq '.login')

gh issue edit "$ISSUE_NUMBER" \
  --repo "$REPO" \
  --add-assignee "$GH_USER" \
  2>/dev/null && ok "Assigned issue #${ISSUE_NUMBER} to @${GH_USER}" \
               || warn "Could not assign issue (may already be assigned — continuing)"

# Move to "In Progress" on the project board via GraphQL
ITEM_ID=$(gh project item-list "$PROJECT_NUMBER" \
  --owner "$PROJECT_OWNER" \
  --format json 2>/dev/null \
  | python3 -c "
import json,sys
items = json.load(sys.stdin).get('items', [])
for item in items:
    content = item.get('content', {})
    if content.get('number') == ${ISSUE_NUMBER}:
        print(item['id'])
        break
")

if [[ -n "$ITEM_ID" ]]; then
  PROJECT_ID=$(gh api graphql -f query="
    query { organization(login: \"${PROJECT_OWNER}\") { projectV2(number: ${PROJECT_NUMBER}) { id } } }
  " --jq '.data.organization.projectV2.id')

  gh api graphql -f query="
    mutation {
      updateProjectV2ItemFieldValue(input: {
        projectId: \"${PROJECT_ID}\"
        itemId: \"${ITEM_ID}\"
        fieldId: \"${STATUS_FIELD_ID}\"
        value: { singleSelectOptionId: \"${IN_PROGRESS_OPTION_ID}\" }
      }) { projectV2Item { id } }
    }
  " &>/dev/null && ok "Moved issue to 'In Progress' on the project board" \
                 || warn "Could not update project board status (permissions issue — update manually)"
else
  warn "Issue not found on project board — add it manually if needed"
fi

# ── Create branch ─────────────────────────────────────────────────────────────

if git show-ref --verify --quiet "refs/heads/${BRANCH_NAME}"; then
  warn "Branch '${BRANCH_NAME}' already exists — switching to it"
  git checkout "$BRANCH_NAME"
else
  git checkout -b "$BRANCH_NAME"
  ok "Created branch: ${BRANCH_NAME}"
fi

# ── Print AI prompt ───────────────────────────────────────────────────────────

cat <<PROMPT

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Ready. Copy the prompt below into your AI assistant.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Read the plan in ${CONTEXT_FILE}.

Implement it exactly as specified:
- Create only the files listed under "New files"
- Add only what "Modified files" specifies — append, never restructure
- Do not touch any file listed under "Conflict guard"
- Write the tests in "Done criteria" first, then the implementation
- After each new file, run: pytest tests/ -x -q
- Fix all failures before moving to the next file
- When every done criterion is met:
    git add <only the files you created or modified>
    git commit -m "feat: ${ISSUE_TITLE}"
    gh pr create --draft --title "${ISSUE_TITLE}" --body "Closes #${ISSUE_NUMBER}" --repo ${REPO}

Do not ask for confirmation at any step. If pytest fails 3 times on the
same file, stop and report exactly which assertion is failing and why.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROMPT
