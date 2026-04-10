Install ez-appsec into a GitHub repository via the GitHub App — provisions the scan workflow,
secrets, and variables automatically, then triggers an initial scan to populate the dashboard.

## Usage

```
/ez-appsec install-app <owner/repo>
```

---

## Steps

### 1. Parse the target repo

Extract `owner/repo` from `$ARGUMENTS`. If not provided, derive from the current directory:

```bash
TARGET_REPO=$(gh repo view --json nameWithOwner --jq '.nameWithOwner' 2>/dev/null)
```

If still empty, stop with:
```
Error: no target repo specified.
Usage: /ez-appsec install-app <owner/repo>
```

### 2. Detect current state (silent — no output yet)

```bash
# GitHub App configured at org level?
APP_CONFIGURED=$(gh secret list --org ez-appsec 2>/dev/null | grep -c "EZ_APPSEC_APP_ID" || echo 0)

# Scan workflow already present on the target repo?
PROVISIONED=$(gh api /repos/${TARGET_REPO}/contents/.github/workflows/ez-appsec-scan.yml \
  --jq '.name' 2>/dev/null || echo "")

# Last scan result (if any)
LAST_RUN=$(gh run list --workflow=ez-appsec-scan.yml --repo=${TARGET_REPO} \
  --limit=1 --json conclusion,createdAt \
  --jq '.[0] | "\(.conclusion) on \(.createdAt | split("T")[0])"' 2>/dev/null || echo "none")
```

### 3. Present plan and ask permission — ONCE

Do not output anything before this. Use AskUserQuestion with a single yes/no question.

**If `APP_CONFIGURED` is 0**, stop with (no permission prompt needed):
```
The ez-appsec GitHub App is not configured for this org.

Complete the one-time setup first:
  1. Register the App:  github.com/organizations/ez-appsec/settings/apps/new
  2. Set org secrets:   EZ_APPSEC_APP_ID, EZ_APPSEC_PRIVATE_KEY
  3. Deploy the Worker: github.com/ez-appsec/ez-appsec-webhook
```

**If `PROVISIONED` is non-empty** (updating an existing install):
```
ez-appsec is already installed on <TARGET_REPO>.
Last scan: <LAST_RUN>

This will:
  1. Update the scan workflow to the latest template
  2. Run a fresh scan and push results to the dashboard

Ready to update?
```

**If `PROVISIONED` is empty** (fresh install):
```
ez-appsec is not installed on <TARGET_REPO>.

This will:
  1. Open the GitHub App install page in your browser (2-click process)
  2. Push the scan workflow, secrets, and variables automatically
  3. Run the first scan and push results to the dashboard

Ready to install?
```

If the user says no, stop.

### 4. Execute — single script block

Replace `<TARGET_REPO>` with the actual value before running.

```bash
set -euo pipefail
TARGET_REPO="<TARGET_REPO>"
EZ_APPSEC_REPO="ez-appsec/ez-appsec"
REPO_NAME=$(echo "$TARGET_REPO" | cut -d/ -f2)
OWNER=$(echo "$TARGET_REPO" | cut -d/ -f1)

# ── Helper: find and watch the most recent run of a workflow ──────────────────
watch_latest_run() {
  local REPO=$1 WORKFLOW=$2 LABEL=$3
  sleep 5
  local RUN_ID
  RUN_ID=$(gh run list --workflow="$WORKFLOW" --repo="$REPO" \
    --limit=1 --json databaseId --jq '.[0].databaseId')
  echo "  → $LABEL: https://github.com/$REPO/actions/runs/$RUN_ID"
  if gh run watch "$RUN_ID" --repo "$REPO" --exit-status 2>/dev/null; then
    echo "  ✓ $LABEL passed"
  else
    echo "  ✗ $LABEL failed — see details:"
    gh run view "$RUN_ID" --repo "$REPO" --log-failed
    exit 1
  fi
  echo "$RUN_ID"
}

# ── Check current state ───────────────────────────────────────────────────────
PROVISIONED=$(gh api /repos/${TARGET_REPO}/contents/.github/workflows/ez-appsec-scan.yml \
  --jq '.name' 2>/dev/null || echo "")

if [ -z "$PROVISIONED" ]; then

  # ── Fresh install ─────────────────────────────────────────────────────────
  echo "Opening install page in your browser..."
  open "https://github.com/apps/ez-appsec/installations/new" 2>/dev/null || true
  echo ""
  echo "In the browser:"
  echo "  1. Select the '${OWNER}' account"
  echo "  2. Choose 'Only select repositories' → pick '${REPO_NAME}'"
  echo "  3. Click Install"
  echo ""
  echo "Waiting for installation to complete..."

  ELAPSED=0
  while [ $ELAPSED -lt 360 ]; do
    PROVISIONED=$(gh api /repos/${TARGET_REPO}/contents/.github/workflows/ez-appsec-scan.yml \
      --jq '.name' 2>/dev/null || echo "")
    if [ -n "$PROVISIONED" ]; then
      echo "  ✓ Scan workflow pushed to ${TARGET_REPO}"
      break
    fi
    printf "  %ds elapsed — waiting for installation...\r" "$ELAPSED"
    sleep 10
    ELAPSED=$((ELAPSED + 10))
  done

  if [ -z "$PROVISIONED" ]; then
    echo ""
    echo "Timed out after 6 minutes."
    echo "Check the installation at: https://github.com/organizations/${OWNER}/settings/installations"
    echo "Check the setup workflow at: https://github.com/${EZ_APPSEC_REPO}/actions/workflows/app-install.yml"
    exit 1
  fi

  echo ""
  echo "Step 1/2 — Watching workflow setup..."
  watch_latest_run "$EZ_APPSEC_REPO" "app-install.yml" "Workflow setup" > /dev/null

else

  # ── Update existing install ───────────────────────────────────────────────
  echo "Step 1/2 — Updating workflow and secrets on ${TARGET_REPO}..."
  INSTALLATION_ID=$(gh api /repos/${TARGET_REPO}/installation --jq '.id' 2>/dev/null \
    | grep -E '^[0-9]+$' || echo "0")
  gh api repos/${EZ_APPSEC_REPO}/dispatches -X POST \
    -H "Accept: application/vnd.github+json" \
    --input - <<EOF
{
  "event_type": "app-install",
  "client_payload": {
    "installation_id": ${INSTALLATION_ID},
    "repos": ["${TARGET_REPO}"]
  }
}
EOF
  watch_latest_run "$EZ_APPSEC_REPO" "app-install.yml" "Workflow setup" > /dev/null

fi

# ── Trigger and watch scan ────────────────────────────────────────────────────
echo ""
echo "Step 2/2 — Running security scan on ${TARGET_REPO}..."
sleep 15  # allow GitHub to index the updated workflow
gh workflow run ez-appsec-scan.yml --repo "$TARGET_REPO"
SCAN_RUN=$(watch_latest_run "$TARGET_REPO" "ez-appsec-scan.yml" "Security scan")

# ── Final summary ─────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✓ ez-appsec installed on ${TARGET_REPO}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Workflow   https://github.com/${TARGET_REPO}/blob/main/.github/workflows/ez-appsec-scan.yml"
echo "  Scan       https://github.com/${TARGET_REPO}/actions/runs/${SCAN_RUN}"
echo "  Dashboard  https://${OWNER}.github.io/ez-appsec-dashboard/"
echo ""
echo "Scans run automatically on push and pull_request."
```
