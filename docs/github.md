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
| `GITHUB_TOKEN` | Auto-provided | GitHub token for PR comments — auto-available in Actions |
| `GITHUB_EVENT_PATH` | Auto-provided | Path to event JSON — used to extract PR number |

All secrets and variables are set automatically by `install-app`. You can override them in **Settings → Secrets and variables → Actions**.

---

## PR Inline Comments

Findings are posted as inline review comments on pull requests automatically. Comments only appear on lines that were changed in the diff.

To post comments manually:

```bash
ez-appsec pr-comment \
  --platform github \
  --findings vulnerabilities.json \
  --repo owner/repo \
  --pr 123
```

The command will automatically use `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, and `GITHUB_EVENT_PATH` if available. Multiple findings on the same file are grouped into a single comment thread.

---

## Configuration Reference (`.ez-appsec.yaml`)

Place an `.ez-appsec.yaml` file in your repository root (or pass `--config path/to/file.yaml` to any scan command).

```yaml
# Target languages (optional — scanners auto-detect if omitted)
languages:
  - python
  - javascript

# Minimum severity to report: all | critical | high | medium | low
severity: medium

# AI analysis model
ai:
  model: gpt-4
  temperature: 0.5

# Ignore rules — suppress known false positives
ignore:
  # Suppress by scanner rule ID
  - rule_id: generic-api-key
    file_path: "tests/**"
    reason: "Test fixtures with dummy credentials"
    permanent: true

  # Suppress by CVE ID with expiration
  - cve_id: CVE-2023-1234
    reason: "Mitigated by WAF rule, revisit in June"
    until: "2025-06-01"

  # Suppress by message substring
  - message: "example.com"
    reason: "Documentation URLs, not real endpoints"
    permanent: true

  # Suppress all findings in vendored code
  - file_path: "vendor/**"
    reason: "Third-party vendored code"
    permanent: true
```

### Ignore rule fields

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | string | Match by scanner rule ID (semgrep check ID, gitleaks RuleID, etc.) |
| `file_path` | string | Match by file path — supports glob patterns (`*`, `**`, `?`) |
| `message` | string | Match by substring in finding message/description (case-insensitive) |
| `cve_id` | string | Match by CVE identifier |
| `permanent` | boolean | If `true`, rule never expires |
| `until` | string | ISO date (`YYYY-MM-DD`) — rule expires after this date and findings resurface |
| `reason` | string | **Required.** Why this finding is being suppressed |

At least one matcher (`rule_id`, `file_path`, `message`, or `cve_id`) is required. Each rule must be either `permanent: true` or have an `until` date.

Suppressed findings appear in scan output as a `[suppressed]` count — they are never silently hidden.

### Validate your config

```bash
ez-appsec check-config                    # validates .ez-appsec.yaml
ez-appsec check-config path/to/config.yaml  # validates a specific file
```

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
