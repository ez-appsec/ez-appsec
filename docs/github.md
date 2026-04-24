# GitHub Setup Guide

This guide walks through adding ez-appsec to a GitHub repository and setting up the shared security dashboard.

---

## Prerequisites

- [Claude Code](https://claude.ai/code) with the ez-appsec skill installed
- [gh CLI](https://cli.github.com/) authenticated (`gh auth status`)
- The ez-appsec GitHub App installed on your org: https://github.com/apps/ez-appsec/installations/new

### Install the ez-appsec skill (one-time)

```bash
curl -fsSL https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/skills/install.sh | bash
```

---

## Step 1 — Add ez-appsec to a repository

```
/ez-appsec install-app owner/repo
```

The skill will:
1. Check `gh` auth and required scopes
2. Show you exactly what will be created — ask for confirmation
3. Push `.github/workflows/ez-appsec-scan.yml` to the repo
4. Set `EZ_APPSEC_APP_ID`, `EZ_APPSEC_PRIVATE_KEY`, and `EZ_APPSEC_DASHBOARD_REPO` secrets
5. Trigger the first scan

The workflow runs automatically on every push to `main`/`master` and on pull requests.

### What the workflow does

| Step | Description |
|------|-------------|
| Version check | Advisory warning if a newer ez-appsec release is available |
| Security scan | Runs gitleaks, semgrep, kics, grype via the ez-appsec Docker image |
| SARIF upload | Uploads findings to the GitHub Security tab |
| PR comment | Posts a findings summary on pull requests |
| Dashboard push | Commits `vulnerabilities.json` to the dashboard repo |

### Scan behaviour

| Trigger | Severity threshold |
|---------|--------------------|
| Pull request | All severities |
| Push to main/master | Medium and above |
| Manual (`workflow_dispatch`) | Medium and above |

---

## Step 2 — Set up the dashboard

The dashboard is a static GitHub Pages site that aggregates scan results across all your repositories.

```
/ez-appsec install-dashboard [owner/repo]
```

Defaults to `owner/ez-appsec-dashboard` if no repo is given.

The skill will:
1. Create the dashboard repo (if it doesn't exist)
2. Push the dashboard web assets (`index.html`, `app-github.js`, `style.css`)
3. Provision `EZ_APPSEC_APP_ID` and `EZ_APPSEC_PRIVATE_KEY` secrets
4. Install the `update-assets.yml` workflow
5. Enable GitHub Pages (served from `main` branch root)
6. Trigger the first asset update

The dashboard is live at `https://OWNER.github.io/ez-appsec-dashboard/` within a few minutes.

---

## Add more repositories

Repeat Step 1 for each repo you want scanned. Results from all repos accumulate in the dashboard automatically — no dashboard configuration needed.

```
/ez-appsec install-app owner/another-repo
/ez-appsec install-app owner/yet-another-repo
```

---

## Keeping the dashboard up to date

When a new ez-appsec release ships, update the dashboard assets:

```
/ez-appsec update-dashboard [owner/repo]
```

This re-provisions secrets and triggers the `update-assets.yml` workflow to pull the latest release assets.

---

## Remove ez-appsec from a repository

```
/ez-appsec uninstall-app owner/repo
```

Removes the workflow file and prunes the repo's data from the dashboard.

---

## CI variable reference

| Secret / Variable | Where set | Description |
|-------------------|-----------|-------------|
| `EZ_APPSEC_APP_ID` | Repo secret | GitHub App ID — used to mint short-lived tokens |
| `EZ_APPSEC_PRIVATE_KEY` | Repo secret | GitHub App private key (PEM) |
| `EZ_APPSEC_DASHBOARD_REPO` | Repo variable | Dashboard repo to push results to (e.g. `owner/ez-appsec-dashboard`) |
| `EZ_APPSEC_VERSION` | Repo variable | Docker image tag to use (default: `latest`) |
| `EZ_APPSEC_TEAM` | Repo variable | (Optional) Group results under a team subfolder in the dashboard |

All secrets and variables are set automatically by `install-app`. You can override them in **Settings → Secrets and variables → Actions**.

---

## Verify with the test script

```bash
bash github/scripts/github-pipeline-test.sh \
  --repo owner/repo \
  --check-dashboard \
  --check-sarif
```

Exit 0 = pipeline succeeded, findings present, dashboard updated.

---

## Dashboard

See [docs/dashboard.md](dashboard.md) for the full dashboard feature guide and screenshots.
