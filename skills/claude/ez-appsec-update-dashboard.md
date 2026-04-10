Update the ez-appsec dashboard web app to the latest release — installs or updates the
`update-assets.yml` workflow in the dashboard repo, then triggers it to pull the latest
`app-github.js`, `index.html`, and `style.css` from the newest ez-appsec release.

The `update-assets.yml` workflow is always kept current: it is installed on first run and
re-synced on every subsequent run before being triggered.

## Usage

```
/ez-appsec update-dashboard [owner/repo]
```

`owner/repo` is the dashboard repo to update. Defaults to `ez-appsec/ez-appsec-dashboard`.

---

## Steps

### 1. Validate

```bash
if ! gh auth status 2>/dev/null; then
  echo "Error: gh CLI is not authenticated."
  echo "Run: gh auth login"
  exit 1
fi

# workflow scope is required to write files in .github/workflows/
if ! gh auth status 2>/dev/null | grep -q "workflow"; then
  echo "Note: Your gh token is missing the 'workflow' scope."
  echo "Run: gh auth refresh -s workflow"
  echo "Then retry this command."
  exit 1
fi
```

### 2. Detect current state (silent — no output yet)

```bash
EZ_APPSEC_REPO="ez-appsec/ez-appsec"
DASHBOARD_REPO="${ARGUMENTS:-ez-appsec/ez-appsec-dashboard}"

# Validate owner/repo format if provided
if ! echo "$DASHBOARD_REPO" | grep -qE '^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$'; then
  echo "Error: '$DASHBOARD_REPO' is not a valid owner/repo."
  exit 1
fi

# Check dashboard repo is accessible
if ! gh repo view "$DASHBOARD_REPO" --json name 2>/dev/null | grep -q name; then
  echo "Error: repository '$DASHBOARD_REPO' not found or not accessible."
  exit 1
fi

# Latest ez-appsec release
LATEST_TAG=$(gh api /repos/${EZ_APPSEC_REPO}/releases/latest --jq '.tag_name' 2>/dev/null || echo "")
if [ -z "$LATEST_TAG" ]; then
  echo "Error: could not determine latest ez-appsec release."
  echo "Check: https://github.com/${EZ_APPSEC_REPO}/releases"
  exit 1
fi

# Current version in dashboard (from data/config.json if present)
CURRENT_VERSION=$(gh api /repos/${DASHBOARD_REPO}/contents/data/config.json \
  --jq '.content' 2>/dev/null \
  | base64 --decode \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('ez_appsec_version','unknown'))" \
  2>/dev/null || echo "unknown")

# Last commit date on dashboard main
LAST_UPDATE=$(gh api /repos/${DASHBOARD_REPO}/commits/main \
  --jq '.commit.author.date' 2>/dev/null | cut -c1-10 || echo "unknown")

# Is update-assets.yml already installed in the dashboard repo?
WORKFLOW_SHA=$(gh api /repos/${DASHBOARD_REPO}/contents/.github/workflows/update-assets.yml \
  2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('sha',''))" 2>/dev/null || echo "")
WORKFLOW_STATUS=$( [ -n "$WORKFLOW_SHA" ] && echo "installed" || echo "not installed" )
```

### 3. Present plan and ask permission — ONCE

Do not output anything before this step.

**If `CURRENT_VERSION` matches `LATEST_TAG` (strip leading `v` from both before comparing):**
```
Dashboard is already at ez-appsec <LATEST_TAG>.
Nothing to update.
```
Stop — do not ask permission.

**Otherwise:**

```
Dashboard: <DASHBOARD_REPO>
Current:   <CURRENT_VERSION>   (last updated <LAST_UPDATE>)
Latest:    <LATEST_TAG>

This will:
  1. Install/update .github/workflows/update-assets.yml in <DASHBOARD_REPO>
  2. Trigger the workflow to pull the latest assets and commit them

Ready to update?
```

Note whether the workflow is already installed or needs to be installed fresh:
- If `WORKFLOW_STATUS` is "installed": say "Update" in item 1
- If `WORKFLOW_STATUS` is "not installed": say "Install" in item 1

Use AskUserQuestion with yes/no. If no, stop.

### 4. Execute — single script block

Replace all `<...>` placeholders with actual values before running.

```bash
set -euo pipefail
EZ_APPSEC_REPO="ez-appsec/ez-appsec"
DASHBOARD_REPO="<DASHBOARD_REPO>"
LATEST_TAG="<LATEST_TAG>"
WORKFLOW_SHA="<WORKFLOW_SHA>"   # empty string if not installed
ERRORS=0

# ── 1. Install/update the update-assets.yml workflow ─────────────────────────
echo "Installing update-assets.yml workflow in ${DASHBOARD_REPO}..."

# Fetch workflow content from ez-appsec at LATEST_TAG (base64, newlines stripped)
# macOS base64 uses -i flag; GNU base64 accepts a positional argument
CONTENT=$(gh api "/repos/${EZ_APPSEC_REPO}/contents/github/dashboard/update-assets.yml?ref=${LATEST_TAG}" \
  2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('content',''))" \
  | tr -d '\n')

if [ -z "$CONTENT" ]; then
  echo "  ✗ Could not fetch update-assets.yml from ${EZ_APPSEC_REPO}@${LATEST_TAG}: $(cat /tmp/ez_err)"
  exit 1
fi

# Build the JSON payload for the GitHub Contents API
if [ -n "$WORKFLOW_SHA" ]; then
  PAYLOAD=$(python3 -c "
import json, sys
print(json.dumps({
  'message': 'chore: update dashboard workflow to $LATEST_TAG',
  'content': sys.argv[1],
  'sha':     '$WORKFLOW_SHA',
}))
" "$CONTENT")
else
  PAYLOAD=$(python3 -c "
import json, sys
print(json.dumps({
  'message': 'chore: install dashboard update workflow',
  'content': sys.argv[1],
}))
" "$CONTENT")
fi

if echo "$PAYLOAD" | gh api /repos/${DASHBOARD_REPO}/contents/.github/workflows/update-assets.yml \
    -X PUT --input - 2>/tmp/ez_err >/dev/null; then
  echo "  ✓ update-assets.yml $( [ -n '$WORKFLOW_SHA' ] && echo updated || echo installed ) in ${DASHBOARD_REPO}"
else
  echo "  ✗ Could not write workflow: $(cat /tmp/ez_err)"
  ERRORS=$((ERRORS + 1))
  exit 1
fi

# ── 2. Trigger the workflow ───────────────────────────────────────────────────
echo "Triggering update-assets.yml..."

# GitHub needs a moment to index the newly pushed workflow file
sleep 8

TRIGGERED=0
for attempt in 1 2 3 4 5; do
  if gh workflow run update-assets.yml --repo "${DASHBOARD_REPO}" 2>/tmp/ez_err; then
    TRIGGERED=1
    break
  fi
  printf "  Workflow not yet indexed — retrying in 10s (%d/5)...\r" "$attempt"
  sleep 10
done

if [ $TRIGGERED -eq 0 ]; then
  echo ""
  echo "  ✗ Could not trigger workflow after 60s: $(cat /tmp/ez_err)"
  echo "    Trigger manually: gh workflow run update-assets.yml --repo ${DASHBOARD_REPO}"
  ERRORS=$((ERRORS + 1))
fi

# ── 3. Watch the run ──────────────────────────────────────────────────────────
if [ $TRIGGERED -eq 1 ]; then
  echo "  → Watching run..."
  sleep 5
  RUN_ID=$(gh run list --workflow=update-assets.yml --repo="${DASHBOARD_REPO}" \
    --limit=1 --json databaseId --jq '.[0].databaseId' 2>/dev/null || echo "")

  if [ -z "$RUN_ID" ]; then
    echo "  ⚠ Run not yet visible — check manually:"
    echo "    https://github.com/${DASHBOARD_REPO}/actions/workflows/update-assets.yml"
  else
    echo "  → Run: https://github.com/${DASHBOARD_REPO}/actions/runs/${RUN_ID}"
    if gh run watch "$RUN_ID" --repo "${DASHBOARD_REPO}" --exit-status 2>/dev/null; then
      echo "  ✓ Dashboard assets updated"
    else
      echo ""
      echo "  ✗ Workflow run failed. Recent log:"
      gh run view "$RUN_ID" --repo "${DASHBOARD_REPO}" --log-failed 2>/dev/null | tail -20
      echo ""
      echo "  Full run: https://github.com/${DASHBOARD_REPO}/actions/runs/${RUN_ID}"
      ERRORS=$((ERRORS + 1))
    fi
  fi
fi

# ── 4. Summary ────────────────────────────────────────────────────────────────
echo ""
if [ $ERRORS -eq 0 ]; then
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "✓ Dashboard updated to ${LATEST_TAG}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "⚠ Update completed with ${ERRORS} error(s) — see above"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fi
echo ""
echo "  Dashboard  https://ez-appsec.github.io/ez-appsec-dashboard/"
echo "  Repo       https://github.com/${DASHBOARD_REPO}"
echo "  Release    https://github.com/${EZ_APPSEC_REPO}/releases/tag/${LATEST_TAG}"
echo ""
```
