Remove ez-appsec from a GitHub repository — deletes the scan workflow, secrets, and variables,
and provides instructions to remove the repo from the GitHub App installation.

## Usage

```
/ez-appsec uninstall-app <owner/repo>
```

---

## Steps

### 1. Parse and validate the target repo

Extract `owner/repo` from `$ARGUMENTS`. If not provided, derive from the current directory:

```bash
TARGET_REPO=$(gh repo view --json nameWithOwner --jq '.nameWithOwner' 2>/dev/null)
```

**Validation — stop with the appropriate message if any check fails:**

```bash
if [ -z "$TARGET_REPO" ]; then
  echo "Error: no target repo specified."
  echo "Usage: /ez-appsec uninstall-app owner/repo-name"
  echo "Or run from inside the target repo's directory."
  exit 1
fi

if ! echo "$TARGET_REPO" | grep -qE '^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$'; then
  echo "Error: '$TARGET_REPO' is not a valid owner/repo."
  echo "Expected format: owner/repo-name"
  exit 1
fi

if ! gh auth status 2>/dev/null; then
  echo "Error: gh CLI is not authenticated."
  echo "Run: gh auth login"
  exit 1
fi

if ! gh repo view "$TARGET_REPO" --json name 2>/dev/null | grep -q name; then
  echo "Error: repository '$TARGET_REPO' not found or not accessible."
  echo "Check the repo name and that your gh token has access."
  exit 1
fi
```

### 2. Detect current state (silent — no output yet)

```bash
# Scan workflow present?
WORKFLOW_SHA=$(gh api /repos/${TARGET_REPO}/contents/.github/workflows/ez-appsec-scan.yml \
  --jq '.sha' 2>/dev/null || echo "")

# Which secrets/variables are set? (check presence, not values)
HAS_APP_ID=$(gh secret list --repo=${TARGET_REPO} 2>/dev/null | grep -c "EZ_APPSEC_APP_ID" || echo 0)
HAS_PRIVATE_KEY=$(gh secret list --repo=${TARGET_REPO} 2>/dev/null | grep -c "EZ_APPSEC_PRIVATE_KEY" || echo 0)
HAS_DASHBOARD_VAR=$(gh variable list --repo=${TARGET_REPO} 2>/dev/null | grep -c "EZ_APPSEC_DASHBOARD_REPO" || echo 0)
```

### 3. Present plan and ask permission — ONCE

Do not output anything before this step.

**If nothing is installed** (workflow absent, no secrets, no variables):
```
ez-appsec does not appear to be installed on <TARGET_REPO>.
Nothing to remove.
```
Stop — do not ask permission.

**Otherwise**, also check for dashboard data:

```bash
DASHBOARD_REPO="ez-appsec/ez-appsec-dashboard"

# Check all possible paths: with and without a team prefix
DASHBOARD_FILE_SHA=""
DASHBOARD_FILE_PATH=""
for CANDIDATE in \
  "data/vulnerabilities/${REPO_NAME}.json" \
  "data/vulnerabilities/${OWNER}/${REPO_NAME}.json"; do
  SHA=$(gh api /repos/${DASHBOARD_REPO}/contents/${CANDIDATE} --jq '.sha' 2>/dev/null || echo "")
  if [ -n "$SHA" ]; then
    DASHBOARD_FILE_SHA="$SHA"
    DASHBOARD_FILE_PATH="$CANDIDATE"
    break
  fi
done
```

Then list exactly what will be removed:

```
ez-appsec is installed on <TARGET_REPO>.

This will remove:
  • .github/workflows/ez-appsec-scan.yml       [workflow file]
  • Secret: EZ_APPSEC_APP_ID                   [if present]
  • Secret: EZ_APPSEC_PRIVATE_KEY              [if present]
  • Variable: EZ_APPSEC_DASHBOARD_REPO         [if present]
  • Dashboard data: <DASHBOARD_FILE_PATH>      [if found]

After removal, you will be given a link to deselect the repo
from the GitHub App installation (requires browser, 1 click).

Proceed with uninstall?
```

Only list items that are actually present (omit absent ones).
Use AskUserQuestion with yes/no. If no, stop.

Only list items that are actually present (omit absent ones).
Use AskUserQuestion with yes/no. If no, stop.

### 4. Execute — single script block

Replace all `<...>` placeholders with actual values before running.

```bash
set -euo pipefail
TARGET_REPO="<TARGET_REPO>"
OWNER=$(echo "$TARGET_REPO" | cut -d/ -f1)
REPO_NAME=$(echo "$TARGET_REPO" | cut -d/ -f2)
WORKFLOW_SHA="<WORKFLOW_SHA>"
HAS_APP_ID=<HAS_APP_ID>
HAS_PRIVATE_KEY=<HAS_PRIVATE_KEY>
HAS_DASHBOARD_VAR=<HAS_DASHBOARD_VAR>
DASHBOARD_REPO="ez-appsec/ez-appsec-dashboard"
DASHBOARD_FILE_PATH="<DASHBOARD_FILE_PATH>"   # empty string if not found
DASHBOARD_FILE_SHA="<DASHBOARD_FILE_SHA>"     # empty string if not found
ERRORS=0

# ── 1. Remove workflow file ───────────────────────────────────────────────────
if [ -n "$WORKFLOW_SHA" ]; then
  echo "Removing scan workflow..."
  if gh api repos/${TARGET_REPO}/contents/.github/workflows/ez-appsec-scan.yml \
    -X DELETE \
    -f message="chore: remove ez-appsec scan workflow" \
    -f sha="$WORKFLOW_SHA" 2>/tmp/ez_err; then
    echo "  ✓ .github/workflows/ez-appsec-scan.yml removed"
  else
    echo "  ✗ Could not remove workflow file: $(cat /tmp/ez_err)"
    echo "    Your token may lack write access to ${TARGET_REPO}."
    echo "    Remove manually: https://github.com/${TARGET_REPO}/blob/main/.github/workflows/ez-appsec-scan.yml"
    ERRORS=$((ERRORS + 1))
  fi
fi

# ── 2. Remove secrets ─────────────────────────────────────────────────────────
echo "Removing secrets..."
for SECRET in \
  ${HAS_APP_ID:+EZ_APPSEC_APP_ID} \
  ${HAS_PRIVATE_KEY:+EZ_APPSEC_PRIVATE_KEY}; do
  [ -z "$SECRET" ] && continue
  if gh secret delete "$SECRET" --repo="$TARGET_REPO" 2>/tmp/ez_err; then
    echo "  ✓ Secret ${SECRET} removed"
  else
    echo "  ✗ Could not remove secret ${SECRET}: $(cat /tmp/ez_err)"
    echo "    Remove manually: https://github.com/${TARGET_REPO}/settings/secrets/actions"
    ERRORS=$((ERRORS + 1))
  fi
done

# ── 3. Remove variable ────────────────────────────────────────────────────────
if [ "$HAS_DASHBOARD_VAR" -gt 0 ]; then
  echo "Removing variables..."
  if gh variable delete EZ_APPSEC_DASHBOARD_REPO --repo="$TARGET_REPO" 2>/tmp/ez_err; then
    echo "  ✓ Variable EZ_APPSEC_DASHBOARD_REPO removed"
  else
    echo "  ✗ Could not remove variable: $(cat /tmp/ez_err)"
    echo "    Remove manually: https://github.com/${TARGET_REPO}/settings/variables/actions"
    ERRORS=$((ERRORS + 1))
  fi
fi

# ── 4. Remove dashboard data ─────────────────────────────────────────────────
if [ -n "$DASHBOARD_FILE_SHA" ]; then
  echo "Removing dashboard data..."
  if gh api repos/${DASHBOARD_REPO}/contents/${DASHBOARD_FILE_PATH} \
    -X DELETE \
    -f message="chore: remove scan data for ${TARGET_REPO}" \
    -f sha="$DASHBOARD_FILE_SHA" 2>/tmp/ez_err; then
    echo "  ✓ ${DASHBOARD_FILE_PATH} removed from dashboard"

    # Regenerate the dashboard index by triggering dashboard-update workflow
    if gh workflow run dashboard-update.yml --repo ez-appsec/ez-appsec 2>/dev/null; then
      echo "  ✓ Dashboard index update triggered"
    else
      echo "  ⚠ Could not trigger dashboard index update automatically."
      echo "    Trigger manually: gh workflow run dashboard-update.yml --repo ez-appsec/ez-appsec"
    fi
  else
    echo "  ✗ Could not remove dashboard data: $(cat /tmp/ez_err)"
    echo "    Your token may lack write access to ${DASHBOARD_REPO}."
    echo "    Remove manually: https://github.com/${DASHBOARD_REPO}/blob/main/${DASHBOARD_FILE_PATH}"
    ERRORS=$((ERRORS + 1))
  fi
fi

# ── 5. Summary ────────────────────────────────────────────────────────────────
echo ""
if [ $ERRORS -eq 0 ]; then
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "✓ ez-appsec removed from ${TARGET_REPO}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "⚠ Uninstall completed with ${ERRORS} error(s) — see above"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fi
echo ""
echo "One manual step remaining — remove '${REPO_NAME}' from the App installation:"
echo ""
echo "  https://github.com/organizations/${OWNER}/settings/installations"
echo ""
echo "  1. Click 'Configure' next to the ez-appsec App"
echo "  2. Under 'Repository access', deselect '${REPO_NAME}'"
echo "  3. Click Save"
echo ""
echo "Scans on ${TARGET_REPO} will stop immediately."
if [ -n "$DASHBOARD_FILE_SHA" ]; then
  echo "Dashboard data has been removed and the index is being regenerated."
else
  echo "No dashboard data was found for ${TARGET_REPO} — nothing to prune there."
fi
```
