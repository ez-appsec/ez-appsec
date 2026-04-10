Install ez-appsec into a GitHub repository via the GitHub App — provisions the scan workflow,
secrets, and variables automatically, then triggers an initial scan to populate the dashboard.

## Usage

```
/ez-appsec install-app <owner/repo>
```

---

## Steps

### 1. Parse the target repo

Extract `owner/repo` from `$ARGUMENTS`. If not provided, derive it from the current directory:

```bash
TARGET_REPO=$(gh repo view --json nameWithOwner --jq '.nameWithOwner' 2>/dev/null)
```

If still empty, exit with:
```
Error: provide a target repo — e.g. /ez-appsec install-app ez-appsec/juice-shop-public
```

### 2. Check the GitHub App is configured

Verify `EZ_APPSEC_APP_ID` exists as an org secret (confirms one-time App setup is complete):

```bash
gh secret list --org ez-appsec 2>/dev/null | grep -q "EZ_APPSEC_APP_ID"
```

If not found, exit with:
```
Error: GitHub App not configured for the ez-appsec org.
Run the one-time setup first:
  1. Register the GitHub App at github.com/organizations/ez-appsec/settings/apps/new
  2. Store EZ_APPSEC_APP_ID and EZ_APPSEC_PRIVATE_KEY as org-level secrets
  3. Deploy the Cloudflare Worker (see ez-appsec-webhook repo)
```

### 3. Check if the App is already installed on the target repo

```bash
INSTALLATION=$(gh api /repos/${TARGET_REPO}/installation 2>/dev/null)
INSTALLATION_ID=$(echo "$INSTALLATION" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])" 2>/dev/null)
```

#### If NOT installed (no installation ID)

Print:
```
The ez-appsec GitHub App is not yet installed on <TARGET_REPO>.

Install it here:
  https://github.com/apps/ez-appsec/installations/new

Select "<owner>" as the account, choose "Only select repositories",
pick "<repo>", and click Install.

Waiting for installation... (press Ctrl+C to cancel)
```

Then poll every 10 seconds (up to 5 minutes) until the installation appears:

```bash
for i in $(seq 1 30); do
  INSTALLATION_ID=$(gh api /repos/${TARGET_REPO}/installation --jq '.id' 2>/dev/null)
  if [ -n "$INSTALLATION_ID" ]; then
    echo "✓ App installed (installation ID: ${INSTALLATION_ID})"
    break
  fi
  echo "  Waiting... (${i}/30)"
  sleep 10
done

if [ -z "$INSTALLATION_ID" ]; then
  echo "Timed out waiting for installation. Re-run after installing the App."
  exit 1
fi
```

The webhook will have already fired and triggered `app-install.yml` automatically.
Skip to Step 5 to monitor the run.

#### If ALREADY installed

Print:
```
✓ App already installed on <TARGET_REPO> (installation ID: <INSTALLATION_ID>)
Triggering reprovisioning...
```

Then proceed to Step 4.

### 4. Trigger provisioning via repository_dispatch

Used when the App is already installed and the user wants to reprovision
(e.g. after changes to the scan template, or for an initial manual trigger).

```bash
gh api repos/ez-appsec/ez-appsec/dispatches \
  -X POST \
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
```

If the API call fails, exit with the error.

### 5. Monitor the provisioner workflow run

Wait 5 seconds for the run to register, then poll `app-install.yml`:

```bash
sleep 5
RUN_ID=$(gh run list \
  --workflow=app-install.yml \
  --repo=ez-appsec/ez-appsec \
  --limit=1 \
  --json databaseId \
  --jq '.[0].databaseId')

echo "Provisioner run: https://github.com/ez-appsec/ez-appsec/actions/runs/${RUN_ID}"
gh run watch "$RUN_ID" --repo=ez-appsec/ez-appsec --exit-status
```

If the run fails, print the log tail:
```bash
gh run view "$RUN_ID" --repo=ez-appsec/ez-appsec --log-failed
```

And exit with:
```
✗ Provisioning failed — see log above.
```

### 6. Verify provisioning succeeded

Confirm the workflow file was pushed to the target repo:

```bash
gh api /repos/${TARGET_REPO}/contents/.github/workflows/ez-appsec-scan.yml \
  --jq '.name' 2>/dev/null
```

If found, print:
```
✓ .github/workflows/ez-appsec-scan.yml pushed to <TARGET_REPO>
```

### 7. Monitor the initial scan

The provisioner triggers a scan automatically. Find and watch it:

```bash
# Allow scan workflow to register (provisioner has a 15s sleep built in)
sleep 20

SCAN_RUN_ID=$(gh run list \
  --workflow=ez-appsec-scan.yml \
  --repo=${TARGET_REPO} \
  --limit=1 \
  --json databaseId \
  --jq '.[0].databaseId')

if [ -n "$SCAN_RUN_ID" ]; then
  echo "Scan run: https://github.com/${TARGET_REPO}/actions/runs/${SCAN_RUN_ID}"
  gh run watch "$SCAN_RUN_ID" --repo=${TARGET_REPO} --exit-status || true
else
  echo "Scan not triggered yet — it will run on the next push or you can trigger manually:"
  echo "  gh workflow run ez-appsec-scan.yml --repo ${TARGET_REPO}"
fi
```

### 8. Report outcome

```
✓ ez-appsec installed on <TARGET_REPO>

  Workflow:   https://github.com/<TARGET_REPO>/blob/main/.github/workflows/ez-appsec-scan.yml
  Secrets:    EZ_APPSEC_APP_ID, EZ_APPSEC_PRIVATE_KEY (set)
  Variable:   EZ_APPSEC_DASHBOARD_REPO = ez-appsec/ez-appsec-dashboard
  Scan run:   https://github.com/<TARGET_REPO>/actions/runs/<SCAN_RUN_ID>
  Dashboard:  https://ez-appsec.github.io/ez-appsec-dashboard/

Scans will run automatically on push and pull_request.
To reprovision: /ez-appsec install-app <TARGET_REPO>
```
