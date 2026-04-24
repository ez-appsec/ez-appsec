Create and configure the `ez-appsec-dashboard` GitHub repository: push dashboard assets,
provision App secrets so `update-assets.yml` can self-update, and enable GitHub Pages.

## Usage

```
/ez-appsec install-dashboard [owner/repo]
```

Defaults to `ez-appsec/ez-appsec-dashboard` if no repo is given.

---

## Steps

### 1. Resolve inputs

```bash
DASHBOARD_REPO="${ARGUMENTS:-ez-appsec/ez-appsec-dashboard}"
OWNER=$(echo "$DASHBOARD_REPO" | cut -d/ -f1)
EZ_APPSEC_REPO="ez-appsec/ez-appsec"
```

Validate `owner/repo` format. If malformed, stop with a usage error.

Locate the ez-appsec source root (for local asset files):
```bash
EZ_APPSEC_SRC=$(git -C "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" rev-parse --show-toplevel 2>/dev/null || echo ".")
```

Read App credentials — try in order:
1. `EZ_APPSEC_APP_ID` / `EZ_APPSEC_PRIVATE_KEY_PATH` env vars
2. `~/../.env` (one level above the repo root): parse `APP_ID=` and look for `*.private-key.pem`
3. If still missing, ask the user for the App ID and path to the PEM file

```bash
# Try to load from .env
ENV_FILE="$(dirname "$EZ_APPSEC_SRC")/.env"
if [ -f "$ENV_FILE" ]; then
  APP_ID_VAL=$(grep -E '^EZ_APPSEC_APP_ID=' "$ENV_FILE" | cut -d= -f2 | tr -d '"' | xargs 2>/dev/null || echo "")
  # also look for any *.private-key.pem in the parent directory
  PEM_PATH=$(ls "$(dirname "$EZ_APPSEC_SRC")"/*.private-key.pem 2>/dev/null | head -1 || echo "")
fi
APP_ID="${EZ_APPSEC_APP_ID:-$APP_ID_VAL}"
PEM="${EZ_APPSEC_PRIVATE_KEY_PATH:-$PEM_PATH}"
```

If `APP_ID` is empty, use the known numeric ID for the `ez-appsec` GitHub App: `3338152`.

If `PEM` is empty, stop and tell the user:
```
App private key not found. Set EZ_APPSEC_PRIVATE_KEY_PATH to the path of your
ez-appsec.private-key.pem file, then retry.
```

### 2. Detect current state (silent — no output yet)

```bash
# Does the repo exist?
REPO_EXISTS=$(gh repo view "$DASHBOARD_REPO" --json name 2>/dev/null | grep -q name && echo yes || echo no)

# Is Pages already enabled?
PAGES_STATUS=$(gh api /repos/$DASHBOARD_REPO/pages --jq '.status' 2>/dev/null || echo "none")

# Is update-assets.yml already installed?
WORKFLOW_SHA=$(gh api /repos/$DASHBOARD_REPO/contents/.github/workflows/update-assets.yml \
  --jq '.sha' 2>/dev/null || echo "")

# Current asset version (from data/config.json if present)
CURRENT_VERSION=$(gh api /repos/$DASHBOARD_REPO/contents/data/config.json \
  --jq '.content' 2>/dev/null | base64 --decode \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('ez_appsec_version','none'))" 2>/dev/null || echo "none")

# Latest ez-appsec release
LATEST_TAG=$(gh api /repos/$EZ_APPSEC_REPO/releases/latest --jq '.tag_name' 2>/dev/null || echo "")
```

### 3. Present plan and ask permission — ONCE

Do not output anything before this step.

```
Dashboard repo:  $DASHBOARD_REPO
Repo:            $( [ "$REPO_EXISTS" = yes ] && echo "exists" || echo "will be created" )
Assets:          $( [ "$CURRENT_VERSION" = none ] && echo "not installed" || echo "v$CURRENT_VERSION (will update to $LATEST_TAG)" )
App workflow:    $( [ -n "$WORKFLOW_SHA" ] && echo "installed (will update)" || echo "not installed (will install)" )
Pages:           $( [ "$PAGES_STATUS" = none ] && echo "not enabled (will enable)" || echo "$PAGES_STATUS" )
App secrets:     will provision EZ_APPSEC_APP_ID + EZ_APPSEC_PRIVATE_KEY
```

Ask: "Ready to install/update the dashboard?"

If no, stop.

### 4. Execute — single script block

```bash
set -euo pipefail
DASHBOARD_REPO="<DASHBOARD_REPO>"
OWNER="<OWNER>"
APP_ID="<APP_ID>"
PEM="<PEM>"
EZ_APPSEC_REPO="ez-appsec/ez-appsec"
EZ_APPSEC_SRC="<EZ_APPSEC_SRC>"
LATEST_TAG="<LATEST_TAG>"
WORKFLOW_SHA="<WORKFLOW_SHA>"
ERRORS=0

# ── 1. Create repo if it doesn't exist ───────────────────────────────────────
REPO_EXISTS=$(gh repo view "$DASHBOARD_REPO" --json name 2>/dev/null | grep -q name && echo yes || echo no)
if [ "$REPO_EXISTS" = no ]; then
  echo "Creating $DASHBOARD_REPO..."
  gh repo create "$DASHBOARD_REPO" \
    --public \
    --description "ez-appsec GitHub security dashboard" 2>/tmp/ez_err \
    && echo "  ✓ Repo created" \
    || { echo "  ✗ Could not create repo: $(cat /tmp/ez_err)"; exit 1; }
fi

# ── 2. Push initial dashboard files ──────────────────────────────────────────
echo "Pushing dashboard assets to $DASHBOARD_REPO..."
DASH_DIR=$(mktemp -d)
GITHUB_ACCESS_TOKEN=$(grep GITHUB_ACCESS_TOKEN "${EZ_APPSEC_SRC}/../.env" 2>/dev/null | cut -d= -f2 || echo "")
TOKEN="${GITHUB_ACCESS_TOKEN:-$(gh auth token)}"

git clone "https://x-access-token:${TOKEN}@github.com/${DASHBOARD_REPO}.git" "${DASH_DIR}/repo"
cd "${DASH_DIR}/repo"
git checkout main 2>/dev/null || git checkout -b main

# Copy local dashboard assets (prefer local source, fall back to downloading from release)
ASSET_SRC="${EZ_APPSEC_SRC}/github/dashboard/public"
if [ -f "${ASSET_SRC}/index.html" ]; then
  cp "${ASSET_SRC}/index.html" index.html
  cp "${ASSET_SRC}/app-github.js" app-github.js
  cp "${ASSET_SRC}/style.css" style.css
  echo "  ✓ Copied local assets"
else
  BASE="https://raw.githubusercontent.com/${EZ_APPSEC_REPO}/${LATEST_TAG}/github/dashboard/public"
  for ASSET in index.html app-github.js style.css; do
    curl -sSfL "${BASE}/${ASSET}" -o "${ASSET}"
  done
  echo "  ✓ Downloaded assets from ${LATEST_TAG}"
fi

# Initialise data directory
mkdir -p data/vulnerabilities
if [ ! -f data/index.json ]; then
  printf '{\n  "last_updated": null,\n  "projects": []\n}\n' > data/index.json
fi
printf '{\n  "ez_appsec_version": "%s"\n}\n' "${LATEST_TAG#v}" > data/config.json

git config user.name "ez-appsec installer"
git config user.email "ci@ez-appsec.ai"
git add index.html app-github.js style.css data/
git diff --staged --quiet && echo "  ✓ Assets already current" || {
  git commit -m "chore: install ez-appsec dashboard assets ${LATEST_TAG}"
  git push origin main
  echo "  ✓ Assets pushed"
}
cd /
rm -rf "${DASH_DIR}"

# ── 3. Provision App secrets ──────────────────────────────────────────────────
echo "Provisioning App secrets on $DASHBOARD_REPO..."
(cd "$EZ_APPSEC_SRC" && python3 scripts/provision.py \
  --token "$TOKEN" \
  --repos "$DASHBOARD_REPO" \
  --app-id "$APP_ID" \
  --private-key "$PEM") \
  && echo "  ✓ EZ_APPSEC_APP_ID + EZ_APPSEC_PRIVATE_KEY provisioned" \
  || { echo "  ✗ Provisioning failed"; ERRORS=$((ERRORS+1)); }

# ── 4. Install update-assets.yml workflow ────────────────────────────────────
echo "Installing update-assets.yml workflow..."
CONTENT=$(gh api "/repos/${EZ_APPSEC_REPO}/contents/github/dashboard/update-assets.yml?ref=${LATEST_TAG}" \
  --jq '.content' 2>/dev/null | tr -d '\n')
if [ -z "$CONTENT" ]; then
  # Fall back to local copy
  CONTENT=$(base64 < "${EZ_APPSEC_SRC}/github/dashboard/update-assets.yml" | tr -d '\n')
fi

if [ -n "$WORKFLOW_SHA" ]; then
  PAYLOAD=$(python3 -c "import json,sys; print(json.dumps({'message':'chore: update dashboard workflow to $LATEST_TAG','content':sys.argv[1],'sha':'$WORKFLOW_SHA'}))" "$CONTENT")
else
  PAYLOAD=$(python3 -c "import json,sys; print(json.dumps({'message':'chore: install dashboard update workflow','content':sys.argv[1]}))" "$CONTENT")
fi

echo "$PAYLOAD" | gh api /repos/${DASHBOARD_REPO}/contents/.github/workflows/update-assets.yml \
  -X PUT --input - >/dev/null \
  && echo "  ✓ update-assets.yml installed" \
  || { echo "  ✗ Could not install workflow"; ERRORS=$((ERRORS+1)); }

# ── 5. Enable GitHub Pages ────────────────────────────────────────────────────
echo "Enabling GitHub Pages..."
gh api --method POST /repos/$DASHBOARD_REPO/pages \
  --field source='{"branch":"main","path":"/"}' >/dev/null 2>&1 \
  || gh api --method PUT /repos/$DASHBOARD_REPO/pages \
       --field source='{"branch":"main","path":"/"}' >/dev/null 2>&1 \
  || true  # already enabled is fine
echo "  ✓ GitHub Pages enabled (branch: main)"

# ── 6. Trigger update-assets.yml ─────────────────────────────────────────────
echo "Triggering update-assets.yml to pull latest assets..."
sleep 8  # let GitHub index the newly pushed workflow
TRIGGERED=0
for attempt in 1 2 3 4 5; do
  if gh workflow run update-assets.yml --repo "$DASHBOARD_REPO" 2>/tmp/ez_err; then
    TRIGGERED=1; break
  fi
  printf "  Not yet indexed — retrying (%d/5)...\r" "$attempt"
  sleep 10
done

if [ $TRIGGERED -eq 1 ]; then
  sleep 5
  RUN_ID=$(gh run list --workflow=update-assets.yml --repo="$DASHBOARD_REPO" \
    --limit=1 --json databaseId --jq '.[0].databaseId' 2>/dev/null || echo "")
  if [ -n "$RUN_ID" ]; then
    echo "  → Run: https://github.com/$DASHBOARD_REPO/actions/runs/$RUN_ID"
    gh run watch "$RUN_ID" --repo "$DASHBOARD_REPO" --exit-status 2>/dev/null \
      && echo "  ✓ Assets updated to latest release" \
      || { echo "  ✗ Workflow run failed (see link above)"; ERRORS=$((ERRORS+1)); }
  fi
else
  echo "  ⚠ Could not trigger workflow — trigger manually:"
  echo "    gh workflow run update-assets.yml --repo $DASHBOARD_REPO"
  ERRORS=$((ERRORS+1))
fi

# ── 7. Summary ────────────────────────────────────────────────────────────────
echo ""
if [ $ERRORS -eq 0 ]; then
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "✓ Dashboard installed"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "⚠ Installed with $ERRORS error(s) — see above"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fi
echo ""
echo "  Repo       https://github.com/$DASHBOARD_REPO"
echo "  Dashboard  https://${OWNER}.github.io/$(echo $DASHBOARD_REPO | cut -d/ -f2)/"
echo "  Workflow   https://github.com/$DASHBOARD_REPO/actions/workflows/update-assets.yml"
echo ""
echo "To add a repo to the dashboard:"
echo "  /ez-appsec install-app owner/repo"
echo ""
```
