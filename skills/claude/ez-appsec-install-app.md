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

If still empty, output:
```
Error: provide a target repo — e.g. /ez-appsec install-app ez-appsec/juice-shop-public
```
and stop.

### 2. Detect current state (no user interaction yet)

Run all detection silently:

```bash
# App configured at org level?
APP_CONFIGURED=$(gh secret list --org ez-appsec 2>/dev/null | grep -c "EZ_APPSEC_APP_ID" || echo 0)

# Workflow already provisioned on target repo?
PROVISIONED=$(gh api /repos/${TARGET_REPO}/contents/.github/workflows/ez-appsec-scan.yml \
  --jq '.name' 2>/dev/null || echo "")

# Most recent scan run (if any)
LAST_RUN=$(gh run list --workflow=ez-appsec-scan.yml --repo=${TARGET_REPO} \
  --limit=1 --json status,conclusion,createdAt \
  --jq '.[0] | "\(.conclusion) @ \(.createdAt)"' 2>/dev/null || echo "none")
```

### 3. Present plan and ask permission — ONCE

Based on the detected state, build a one-paragraph summary and use AskUserQuestion with a
single yes/no question. Do not ask anything else.

If `APP_CONFIGURED` is 0:
```
Error: GitHub App not configured for the ez-appsec org.
Complete the one-time setup first:
  1. Register the App at github.com/organizations/ez-appsec/settings/apps/new
  2. Store EZ_APPSEC_APP_ID and EZ_APPSEC_PRIVATE_KEY as org-level secrets
  3. Deploy the Cloudflare Worker (see ez-appsec/ez-appsec-webhook)
```
Stop — do not ask permission.

If `PROVISIONED` is non-empty (already installed):

Present:
```
ez-appsec is already installed on <TARGET_REPO>.
Last scan: <LAST_RUN>

I will:
  • Reprovision .github/workflows/ez-appsec-scan.yml (update to latest template)
  • Trigger a fresh scan → dashboard update

Proceed?
```

If `PROVISIONED` is empty (fresh install):

Present:
```
ez-appsec is not yet installed on <TARGET_REPO>.

I will:
  • Open the GitHub App install page in your browser
  • Wait for you to complete the installation
  • Provision .github/workflows/ez-appsec-scan.yml + secrets + variables
  • Trigger initial scan → dashboard update

Proceed?
```

Ask the user with AskUserQuestion (yes / no). If no, stop.

### 4. Execute — single script block

Run everything in one Bash call:

```bash
set -euo pipefail
TARGET_REPO="<TARGET_REPO>"
EZ_APPSEC_REPO="ez-appsec/ez-appsec"

# ── Helper: watch a run to completion ─────────────────────────────────────────
watch_run() {
  local REPO=$1 RUN_ID=$2 LABEL=$3
  echo "⏳ ${LABEL}: https://github.com/${REPO}/actions/runs/${RUN_ID}"
  gh run watch "$RUN_ID" --repo "$REPO" --exit-status && \
    echo "✓ ${LABEL} completed" || \
    { echo "✗ ${LABEL} failed:"; gh run view "$RUN_ID" --repo "$REPO" --log-failed; return 1; }
}

# ── Fresh install: open browser and wait for App installation ─────────────────
PROVISIONED=$(gh api /repos/${TARGET_REPO}/contents/.github/workflows/ez-appsec-scan.yml \
  --jq '.name' 2>/dev/null || echo "")

if [ -z "$PROVISIONED" ]; then
  echo "Opening GitHub App install page..."
  open "https://github.com/apps/ez-appsec/installations/new" 2>/dev/null || \
    echo "Visit: https://github.com/apps/ez-appsec/installations/new"
  echo "Select the account, choose 'Only select repositories', pick $(echo $TARGET_REPO | cut -d/ -f2), then click Install."
  echo ""

  # Poll for the provisioner workflow to fire (webhook → dispatch → app-install.yml)
  echo "Waiting for provisioner to run..."
  for i in $(seq 1 36); do
    PROVISIONED=$(gh api /repos/${TARGET_REPO}/contents/.github/workflows/ez-appsec-scan.yml \
      --jq '.name' 2>/dev/null || echo "")
    if [ -n "$PROVISIONED" ]; then
      echo "✓ Workflow file provisioned"
      break
    fi
    printf "  [%d/36] waiting...\r" "$i"
    sleep 10
  done

  if [ -z "$PROVISIONED" ]; then
    echo "✗ Timed out — provisioner did not run. Check: https://github.com/${EZ_APPSEC_REPO}/actions/workflows/app-install.yml"
    exit 1
  fi

  # Watch the provisioner run
  sleep 3
  PROV_RUN=$(gh run list --workflow=app-install.yml --repo="$EZ_APPSEC_REPO" \
    --limit=1 --json databaseId --jq '.[0].databaseId' 2>/dev/null || echo "")
  [ -n "$PROV_RUN" ] && watch_run "$EZ_APPSEC_REPO" "$PROV_RUN" "Provisioner"

else
  # Reprovision: trigger dispatch manually
  echo "Reprovisioning ${TARGET_REPO}..."
  INSTALLATION_ID=$(gh api /repos/${TARGET_REPO}/installation --jq '.id' 2>/dev/null | grep -E '^[0-9]+$' || echo "")
  if [ -z "$INSTALLATION_ID" ]; then
    echo "⚠ Could not get installation ID — triggering provisioner with repo only"
  fi
  gh api repos/${EZ_APPSEC_REPO}/dispatches -X POST \
    -H "Accept: application/vnd.github+json" \
    --input - <<EOF
{
  "event_type": "app-install",
  "client_payload": {
    "installation_id": ${INSTALLATION_ID:-0},
    "repos": ["${TARGET_REPO}"]
  }
}
EOF
  sleep 5
  PROV_RUN=$(gh run list --workflow=app-install.yml --repo="$EZ_APPSEC_REPO" \
    --limit=1 --json databaseId --jq '.[0].databaseId')
  watch_run "$EZ_APPSEC_REPO" "$PROV_RUN" "Provisioner"
fi

# ── Trigger and watch initial/updated scan ────────────────────────────────────
echo "Triggering scan on ${TARGET_REPO}..."
sleep 15  # allow GitHub to index the (re)provisioned workflow
gh workflow run ez-appsec-scan.yml --repo "$TARGET_REPO"
sleep 5
SCAN_RUN=$(gh run list --workflow=ez-appsec-scan.yml --repo="$TARGET_REPO" \
  --limit=1 --json databaseId --jq '.[0].databaseId')
watch_run "$TARGET_REPO" "$SCAN_RUN" "Security Scan"

# ── Summary ───────────────────────────────────────────────────────────────────
OWNER=$(echo $TARGET_REPO | cut -d/ -f1)
echo ""
echo "✓ ez-appsec installed on ${TARGET_REPO}"
echo ""
echo "  Workflow:   https://github.com/${TARGET_REPO}/blob/main/.github/workflows/ez-appsec-scan.yml"
echo "  Scan run:   https://github.com/${TARGET_REPO}/actions/runs/${SCAN_RUN}"
echo "  Dashboard:  https://${OWNER}.github.io/ez-appsec-dashboard/"
```
