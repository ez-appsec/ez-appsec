Install ez-appsec into a GitHub repository via the GitHub App — provisions the scan workflow,
secrets, and variables automatically, then triggers an initial scan to populate the dashboard.

## Usage

```
/ez-appsec install-app <owner/repo>
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
# Must be non-empty
if [ -z "$TARGET_REPO" ]; then
  echo "Error: no target repo specified."
  echo "Usage: /ez-appsec install-app owner/repo-name"
  echo "Or run from inside the target repo's directory."
  exit 1
fi

# Must match owner/repo format
if ! echo "$TARGET_REPO" | grep -qE '^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$'; then
  echo "Error: '$TARGET_REPO' is not a valid owner/repo."
  echo "Expected format: owner/repo-name"
  echo "Example: /ez-appsec install-app acme-corp/payments-api"
  exit 1
fi

# gh CLI must be authenticated
if ! gh auth status 2>/dev/null; then
  echo "Error: gh CLI is not authenticated."
  echo "Run: gh auth login"
  exit 1
fi

# Repo must exist and be accessible
if ! gh repo view "$TARGET_REPO" --json name 2>/dev/null | grep -q name; then
  echo "Error: repository '$TARGET_REPO' not found or not accessible."
  echo "Check the repo name and that your gh token has access."
  exit 1
fi
```

### 2. Detect current state (silent — no output yet)

```bash
# GitHub App configured at org level?
# Note: gh secret list --org requires admin:org scope.
# A failure here produces a warning in Step 3, not a hard stop.
APP_CONFIGURED=0
if gh secret list --org ez-appsec 2>/dev/null | grep -q "EZ_APPSEC_APP_ID"; then
  APP_CONFIGURED=1
fi

# Scan workflow already present on the target repo?
PROVISIONED=$(gh api /repos/${TARGET_REPO}/contents/.github/workflows/ez-appsec-scan.yml \
  --jq '.name' 2>/dev/null || echo "")

# Last scan result (if any)
LAST_RUN=$(gh run list --workflow=ez-appsec-scan.yml --repo=${TARGET_REPO} \
  --limit=1 --json conclusion,createdAt \
  --jq '.[0] | "\(.conclusion) on \(.createdAt | split("T")[0])"' 2>/dev/null || echo "none")

# Is the repo private? (affects error messaging)
REPO_PRIVATE=$(gh api /repos/${TARGET_REPO} --jq '.private' 2>/dev/null || echo "unknown")
```

### 3. Present plan and ask permission — ONCE

Do not output anything before this step. Build the summary from detected state, then use
AskUserQuestion with a single yes/no question. Do not ask anything else.

**If `APP_CONFIGURED` is 0:**

If `gh secret list --org` returned an error (not just "not found"), add a caveat:

```
Note: Could not verify GitHub App configuration — your token may lack admin:org scope.
      If the App is set up, you can proceed. If not, complete setup first:
        1. Register the App:   github.com/organizations/ez-appsec/settings/apps/new
        2. Set org secrets:    EZ_APPSEC_APP_ID, EZ_APPSEC_PRIVATE_KEY
        3. Deploy the Worker:  github.com/ez-appsec/ez-appsec-webhook
```

Then still show the plan and ask permission — do not hard-stop.

**If `PROVISIONED` is non-empty** (updating an existing install):

```
ez-appsec is already installed on <TARGET_REPO>.
Last scan: <LAST_RUN>

This will:
  1. Update the scan workflow to the latest template
  2. Reset secrets and variables to current values
  3. Run a fresh scan and push results to the dashboard

Ready to update?
```

**If `PROVISIONED` is empty** (fresh install):

If `REPO_PRIVATE` is `true`, add a note:
```
Note: <TARGET_REPO> is a private repo. If ez-appsec was previously installed and later
      removed, this will reinstall it. If already installed, choose "Update" above.
```

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
OWNER=$(echo "$TARGET_REPO" | cut -d/ -f1)
REPO_NAME=$(echo "$TARGET_REPO" | cut -d/ -f2)

# Derive the repo's default branch for accurate summary links
DEFAULT_BRANCH=$(gh api /repos/${TARGET_REPO} --jq '.default_branch' 2>/dev/null || echo "main")

# ── Helper: find and watch the most recent run of a workflow ──────────────────
watch_latest_run() {
  local REPO=$1 WORKFLOW=$2 LABEL=$3
  sleep 5
  local RUN_ID
  RUN_ID=$(gh run list --workflow="$WORKFLOW" --repo="$REPO" \
    --limit=1 --json databaseId --jq '.[0].databaseId' 2>/dev/null || echo "")

  if [ -z "$RUN_ID" ]; then
    echo "  ⚠ No run found yet — it may still be queued."
    echo "    Monitor manually: https://github.com/$REPO/actions/workflows/$WORKFLOW"
    echo ""
    return 0
  fi

  echo "  → $LABEL: https://github.com/$REPO/actions/runs/$RUN_ID"
  if gh run watch "$RUN_ID" --repo "$REPO" --exit-status 2>/dev/null; then
    echo "  ✓ $LABEL passed"
  else
    echo ""
    echo "  ✗ $LABEL failed. Recent log:"
    gh run view "$RUN_ID" --repo "$REPO" --log-failed 2>/dev/null | tail -30
    echo ""
    echo "  Full run: https://github.com/$REPO/actions/runs/$RUN_ID"
    exit 1
  fi
  echo "$RUN_ID"
}

# ── Determine current state ───────────────────────────────────────────────────
PROVISIONED=$(gh api /repos/${TARGET_REPO}/contents/.github/workflows/ez-appsec-scan.yml \
  --jq '.name' 2>/dev/null || echo "")

if [ -z "$PROVISIONED" ]; then

  # ── FRESH INSTALL ─────────────────────────────────────────────────────────
  echo "Install the GitHub App on ${TARGET_REPO}:"
  echo ""
  echo "  URL: https://github.com/apps/ez-appsec/installations/new"
  echo ""
  echo "  In the browser:"
  echo "    1. Select the '${OWNER}' account"
  echo "    2. Choose 'Only select repositories'"
  echo "    3. Pick '${REPO_NAME}' from the list"
  echo "    4. Click Install"
  echo ""

  # Try to open browser — always print URL above regardless of whether this works
  open "https://github.com/apps/ez-appsec/installations/new" 2>/dev/null || true

  echo "Waiting for installation to complete..."
  ELAPSED=0
  WAIT_MAX=360
  while [ $ELAPSED -lt $WAIT_MAX ]; do
    PROVISIONED=$(gh api /repos/${TARGET_REPO}/contents/.github/workflows/ez-appsec-scan.yml \
      --jq '.name' 2>/dev/null || echo "")
    if [ -n "$PROVISIONED" ]; then
      echo ""
      echo "  ✓ Scan workflow pushed to ${TARGET_REPO}"
      break
    fi
    printf "  %ds elapsed — complete the browser steps above...\r" "$ELAPSED"
    sleep 10
    ELAPSED=$((ELAPSED + 10))
  done

  if [ -z "$PROVISIONED" ]; then
    echo ""
    echo "Timed out after ${WAIT_MAX}s. The workflow file has not appeared on ${TARGET_REPO}."
    echo ""
    echo "Common causes and fixes:"
    echo ""
    echo "  1. App installed on wrong account or repo"
    echo "     → Check and reconfigure: github.com/organizations/${OWNER}/settings/installations"
    echo ""
    echo "  2. Cloudflare Worker not receiving webhooks"
    echo "     → Check Worker deployment and webhook URL in App settings"
    echo "     → App settings: github.com/organizations/ez-appsec/settings/apps/ez-appsec"
    echo ""
    echo "  3. Provisioner workflow failed"
    echo "     → Check: https://github.com/${EZ_APPSEC_REPO}/actions/workflows/app-install.yml"
    echo ""
    echo "After fixing, retry: /ez-appsec install-app ${TARGET_REPO}"
    exit 1
  fi

  echo ""
  echo "Step 1/2 — Watching workflow setup..."
  watch_latest_run "$EZ_APPSEC_REPO" "app-install.yml" "Workflow setup" > /dev/null

else

  # ── UPDATE EXISTING INSTALL ───────────────────────────────────────────────
  echo "Step 1/2 — Updating workflow and secrets on ${TARGET_REPO}..."

  # The /repos/{repo}/installation endpoint requires App JWT auth — user tokens get 401.
  # We try anyway; if it fails we surface a clear manual fallback.
  INSTALLATION_ID=$(gh api /repos/${TARGET_REPO}/installation --jq '.id' 2>/dev/null \
    | grep -E '^[0-9]+$' || echo "")

  if [ -z "$INSTALLATION_ID" ]; then
    echo ""
    echo "  ⚠ Could not look up the App installation ID automatically."
    echo "    (GitHub requires App credentials for this — your user token cannot do it.)"
    echo ""
    echo "  Find it manually and run:"
    echo "    1. Go to: github.com/organizations/${OWNER}/settings/installations"
    echo "    2. Click the ez-appsec installation"
    echo "    3. The installation ID is the last number in the browser URL"
    echo "    4. Then run:"
    echo "       gh api repos/${EZ_APPSEC_REPO}/dispatches -X POST \\"
    echo "         -H 'Accept: application/vnd.github+json' \\"
    echo "         --input - <<<'{\"event_type\":\"app-install\",\"client_payload\":{\"installation_id\":<ID>,\"repos\":[\"${TARGET_REPO}\"]}}'"
    exit 1
  fi

  if ! gh api repos/${EZ_APPSEC_REPO}/dispatches -X POST \
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
  then
    echo ""
    echo "  ✗ Could not trigger the update — your token may lack access to ${EZ_APPSEC_REPO}."
    echo ""
    echo "  Options:"
    echo "    a) Re-authenticate with a token that has 'repo' scope on ${EZ_APPSEC_REPO}:"
    echo "       gh auth login"
    echo ""
    echo "    b) Ask an ez-appsec admin to trigger the update manually at:"
    echo "       https://github.com/${EZ_APPSEC_REPO}/actions/workflows/app-install.yml"
    exit 1
  fi

  watch_latest_run "$EZ_APPSEC_REPO" "app-install.yml" "Workflow setup" > /dev/null

fi

# ── Trigger scan with retry (GitHub needs time to index the workflow) ─────────
echo ""
echo "Step 2/2 — Running security scan on ${TARGET_REPO}..."
SCAN_RUN=""
TRIGGERED=0
for attempt in 1 2 3 4 5 6; do
  if gh workflow run ez-appsec-scan.yml --repo "$TARGET_REPO" 2>/tmp/ez_scan_err; then
    TRIGGERED=1
    break
  fi
  ERR=$(cat /tmp/ez_scan_err)
  if echo "$ERR" | grep -qi "disabled"; then
    echo ""
    echo "  ✗ GitHub Actions is disabled on ${TARGET_REPO}."
    echo "    Enable it at: https://github.com/${TARGET_REPO}/settings/actions"
    echo "    Then run: gh workflow run ez-appsec-scan.yml --repo ${TARGET_REPO}"
    exit 1
  fi
  printf "  Workflow not yet indexed — retrying in 10s (%d/6)...\r" "$attempt"
  sleep 10
done

if [ $TRIGGERED -eq 0 ]; then
  echo ""
  echo "  ⚠ Could not trigger the scan after 60s — GitHub may still be indexing the workflow."
  echo ""
  echo "  Run manually once the workflow appears:"
  echo "    gh workflow run ez-appsec-scan.yml --repo ${TARGET_REPO}"
  echo ""
  echo "  Monitor: https://github.com/${TARGET_REPO}/actions/workflows/ez-appsec-scan.yml"
else
  SCAN_RUN=$(watch_latest_run "$TARGET_REPO" "ez-appsec-scan.yml" "Security scan")
fi

# ── Final summary ─────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✓ ez-appsec installed on ${TARGET_REPO}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Workflow   https://github.com/${TARGET_REPO}/blob/${DEFAULT_BRANCH}/.github/workflows/ez-appsec-scan.yml"
if [ -n "$SCAN_RUN" ]; then
  echo "  Scan       https://github.com/${TARGET_REPO}/actions/runs/${SCAN_RUN}"
fi
echo "  Dashboard  https://ez-appsec.github.io/ez-appsec-dashboard/"
echo ""
echo "Scans run automatically on push and pull_request."
echo ""
echo "If dashboard results are missing after the scan, check that"
echo "EZ_APPSEC_APP_ID and EZ_APPSEC_PRIVATE_KEY are set on ${TARGET_REPO}:"
echo "  https://github.com/${TARGET_REPO}/settings/secrets/actions"
```
