Install ez-appsec into a GitHub project by adding the `github-scan.yml` workflow to `.github/workflows/`, setting up a dashboard project, and opening a pull request.

## Steps

### 1. Resolve target project

If the user provided a path in `$ARGUMENTS`, use it as the target project root.
Otherwise, use the current working directory.

Confirm `.github/workflows/` exists in the target project:
```bash
ls "<TARGET>/.github/workflows/"
```

### 2. Determine if we're in a GitHub repository

Check if this is a GitHub repository:
```bash
cd "<TARGET>"
# Check for GitHub remote
git remote -v | grep "github.com"

# Or use gh CLI
gh repo view 2>/dev/null
```

If not a GitHub repository, exit with error.

### 3. Determine ez-appsec workflow reference

Check if ez-appsec is available as a GitHub repository:
```bash
gh repo view ez-appsec/ez-appsec 2>/dev/null
```

- **If `gh repo view` succeeds**: Use a GitHub project include:
  ```yaml
  include:
    - project: 'ez-appsec/ez-appsec'
      ref: main
      file: '.github/workflows/github-scan.yml'
  ```
- **Otherwise**: Use a remote (raw HTTP) include:
  ```yaml
  include:
    - remote: 'https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/.github/workflows/github-scan.yml'
  ```

### 4. Create/update workflow file

Create `.github/workflows/github-scan.yml` in the target project.

**If the file doesn't exist**:
```bash
cat > "<TARGET>/.github/workflows/github-scan.yml" << 'EOF'
name: Security Scan

on:
  push:
    branches:
      - main
  pull_request:

permissions:
  contents: read
  security-events: write

env:
  EZ_APPSEC_VERSION: "latest"

jobs:
  scan:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/ez-appsec/ez-appsec:\${{ env.EZ_APPSEC_VERSION }}
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Run ez-appsec scan
        run: |
          mkdir -p scan-results
          ez-appsec github-scan . --output scan-results/ez-appsec.sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scan-results/ez-appsec.sarif
          continue-on-error: true

      - name: Upload scan results as artifacts
        uses: actions/upload-artifact@v4
        with:
          name: ez-appsec-scan
          path: scan-results/
          retention-days: 7
EOF
```

**If the file exists**, check if it already includes an ez-appsec reference. If not, append the include from Step 3.

### 5. Set EZ_APPSEC_VERSION repository variable

Fetch the latest released version:
```bash
LATEST_VERSION=$(gh api /repos/ez-appsec/ez-appsec/releases/latest --jq '.tag_name' | tr -d 'v' || echo "")
```

Fall back to `"latest"` if empty:

```bash
if [ -z "$LATEST_VERSION" ]; then
  LATEST_VERSION="latest"
fi
```

Set the repository variable:

```bash
TARGET_REPO=$(git remote get-url origin | sed -E 's|.*/github.com[:/]/([^/]+)\.git|\1|')

gh secret set EZ_APPSEC_VERSION "$LATEST_VERSION" --repo="$TARGET_REPO" 2>/dev/null || \
gh api --method PUT "repos/$TARGET_REPO/actions/variables/EZ_APPSEC_VERSION" \
  -f value="$LATEST_VERSION" \
  -f variable_type=env_var
```

### 6. Set up GitHub Pages dashboard (EZ_APPSEC_DASHBOARD_REPO)

This is required for multi-project dashboard views.

#### 6a. Detect target repository's namespace/owner

```bash
TARGET_REPO=$(git remote get-url origin | sed -E 's|.*/github.com[:/]/([^/]+)\.git|\1|')
OWNER=$(echo "$TARGET_REPO" | cut -d'/' -f1)
```

#### 6b. Check if EZ_APPSEC_DASHBOARD_REPO is already configured

Check repository variable:
```bash
gh variable list EZ_APPSEC_DASHBOARD_REPO --repo="$TARGET_REPO" 2>/dev/null | grep "^EZ_APPSEC_DASHBOARD_REPO="
```

#### 6c. If not configured, create or reference dashboard project

If `EZ_APPSEC_DASHBOARD_REPO` is not set, ask the user:
- Do you want to create a new GitHub Pages dashboard repository?
- Or do you have an existing dashboard repository you want to use?

If creating new:
```bash
DASHBOARD_REPO="$OWNER/ez-appsec-dashboard"
gh repo create "$DASHBOARD_REPO" \
  --description="ez-appsec group security dashboard" \
  --public \
  --clone
```

Initialize the dashboard:
```bash
cd ez-appsec-dashboard

# Create basic structure
git checkout -b main

# Copy dashboard files from ez-appsec source
curl -fsSL https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/dashboard/github/public/index.html -o index.html
curl -fsSL https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/dashboard/github/public/style.css -o style.css
curl -fsSL https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/dashboard/github/public/app-github.js -o app-github.js

mkdir -p public/data
echo '{"last_updated":null,"projects":[]}' > public/data/index.json

git add .
git commit -m "feat: initialize ez-appsec GitHub Pages security dashboard"
git push -u origin main
```

Enable GitHub Pages:
```bash
gh api --method PUT "repos/$DASHBOARD_REPO/pages" -f '{"source":{"branch":"main"}}' 2>/dev/null || \
echo "✓ Enable GitHub Pages in Settings > Pages"
```

Set the repository variable:
```bash
gh variable set EZ_APPSEC_DASHBOARD_REPO "$DASHBOARD_REPO" --repo="$TARGET_REPO" 2>/dev/null
```

#### 6d. If using existing dashboard, set up aggregation

The dashboard repository needs an aggregation workflow to collect data from multiple projects. Ensure the dashboard has:
- `dashboard/aggregate-index-github.py` script
- `.github/workflows/deploy-dashboard.yml` workflow

### 7. Create installation branch and commit

Inside the target project directory:
```bash
cd "<TARGET>"
git fetch origin
INSTALL_BRANCH="ez-appsec-install"
git checkout -B "$INSTALL_BRANCH" "origin/$INSTALL_BRANCH" 2>/dev/null || git checkout -B "$INSTALL_BRANCH"
```

Commit the changes:
```bash
git add .github/workflows/github-scan.yml
git commit -m "chore: install ez-appsec security scanning via GitHub Actions"

# If dashboard was set up, also add a placeholder meta.json for future reference
if [ -n "$EZ_APPSEC_DASHBOARD_REPO" ]; then
  mkdir -p data
  echo '{
    "github_url": "https://github.com/'"$TARGET_REPO'",
    "project_path": "'"$TARGET_REPO"'",
    "project_name": "'$(basename $(git rev-parse --show-toplevel))'",
    "default_branch": "$(git rev-parse --abbrev-ref HEAD)",
    "scan_date": null
  }' > data/meta.json

  git add data/meta.json
  git commit --amend --no-edit
fi

git push origin "$INSTALL_BRANCH"
```

If push is rejected due to diverged history, rebase:
```bash
git pull --rebase origin "$INSTALL_BRANCH"
git push origin "$INSTALL_BRANCH"
```

### 8. Create pull request

```bash
gh pr create \
  --title "chore: install ez-appsec security scanning" \
  --body "$(cat <<'EOF'
## Summary

Adds [ez-appsec](https://github.com/ez-appsec/ez-appsec) security scanning pipeline via GitHub Actions.

**What this enables:**
- Secret detection (gitleaks)
- Static analysis / SAST (semgrep)
- Dependency CVE scanning (grype)
- Infrastructure-as-code misconfiguration detection (kics)

**Workflow behaviour:**
- Scans run automatically on pull requests and pushes to \`main\`.
- Results are published to GitHub Security tab (SARIF format).
- Results are uploaded as artifacts for 7 days.
- Dashboard updates supported (requires EZ_APPSEC_DASHBOARD_REPO variable).

No API key or external service required.

**Configuration:**
- \`EZ_APPSEC_VERSION\`: Set to latest release (currently: latest)
- \`EZ_APPSEC_DASHBOARD_REPO\`: Set to your GitHub Pages dashboard repository

**Next steps:**
1. Review the workflow file in \`.github/workflows/github-scan.yml\`
2. Check the first scan results in the Actions tab
3. Optionally, set up a GitHub Pages dashboard for multi-project views
EOF
)" \
  --source-branch "$INSTALL_BRANCH" \
  --base main \
  --remove-source-branch
```

If \`gh\` is not installed or fails, print:
```bash
To create pull request manually, visit:
  https://github.com/$TARGET_REPO/pull/new?pull_request[source_branch]=$INSTALL_BRANCH
```

### 9. Report outcome

Print a summary:
- PR URL (if created)
- \`EZ_APPSEC_VERSION\` set to: \`<version>\`
- Dashboard repository: \`<DASH_REPO>\` (if configured)
- Pages URL: \`https://<OWNER>.github.io/ez-appsec-dashboard/\` (live after dashboard repo pipeline completes)
- Remind the user that \`EZ_APPSEC_DASHBOARD_REPO\` and \`EZ_APPSEC_VERSION\` can be overridden in repository Settings > Secrets and variables

Example output:
```
✓ ez-appsec installed successfully!

  PR URL: https://github.com/owner/repo/pull/1
  EZ_APPSEC_VERSION: latest
  Dashboard repo: owner/ez-appsec-dashboard
  Pages URL: https://owner.github.io/ez-appsec-dashboard/

The next scan will run automatically on your next push or pull request.
You can override variables in Settings > Secrets and variables.
```

### Troubleshooting

#### `gh` CLI not installed
Install GitHub CLI:
```bash
# macOS
brew install gh

# Linux
curl -fsSL https://cli.github.com/packages/gh_2.53.0_linux_amd64.tar.gz | tar xz
sudo mv gh_2.53.0_linux_amd64/usr/local/bin/gh

# Windows (via winget)
winget install --id GitHub.cli
```

#### Workflow not triggering after installation
Check that:
1. The workflow file has proper YAML syntax (no tabs)
2. The `on:` trigger conditions match your branch name
3. Repository has Actions enabled

#### GitHub Pages not deploying
Ensure:
1. The dashboard repository has GitHub Pages enabled in Settings
2. The `deploy-dashboard.yml` workflow has run successfully
3. The source branch for Pages is set to `main`

#### Dashboard not showing project data
Verify that:
1. Projects are scanning successfully
2. The `update-dashboard` job in `github-scan.yml` is running (requires EZ_APPSEC_DASHBOARD_REPO)
3. The dashboard aggregation script is running on schedule
