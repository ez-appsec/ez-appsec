# GitLab Setup Guide

This guide walks through adding ez-appsec to a GitLab project and setting up the shared security dashboard.

---

## Prerequisites

- [Claude Code](https://claude.ai/code) with the ez-appsec skill installed
- [glab CLI](https://gitlab.com/gitlab-org/cli) authenticated (`glab auth status`)
- A GitLab group for your projects (e.g. `your-group/ez_appsec`)

### Install the ez-appsec skill (one-time)

```bash
curl -fsSL https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/skills/install.sh | bash
```

---

## Step 1 — Set up the dashboard

The dashboard is a GitLab Pages site that aggregates scan results. Set it up once for your group before installing ez-appsec on individual projects.

```
/ez-appsec install-dashboard your-group/ez_appsec
```

The skill will:
1. Create the `ez-appsec-dashboard` project in your group (if it doesn't exist)
2. Push dashboard web assets (`index.html`, `style.css`, `app.js`)
3. Generate an SSH deploy key and add it to the dashboard project
4. Set `EZ_APPSEC_DASHBOARD_PROJECT` and `EZ_APPSEC_DASHBOARD_DEPLOY_KEY` as group CI/CD variables
5. Enable GitLab Pages
6. Trigger the first Pages pipeline

The dashboard is live at `https://YOUR-GROUP.gitlab.io/ez-appsec-dashboard/` within a few minutes.

---

## Step 2 — Add ez-appsec to a project

```
/ez-appsec install /path/to/local/repo
```

Or, if the repo is already cloned:

```
/ez-appsec install
```

The skill will:
1. Check for `.gitlab-ci.yml` (creates a minimal one if absent)
2. Add the ez-appsec `scan.yml` include:
   ```yaml
   include:
     - remote: 'https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/gitlab/scan.yml'
   ```
3. Set `EZ_APPSEC_VERSION` as a project CI/CD variable
4. Create a branch `ez-appsec-install`, commit, and open a merge request

Merge the MR to activate scanning.

### What the pipeline does

| Job | Trigger | Description |
|-----|---------|-------------|
| `scan:pipeline` | MR events, push to `main` | Full scan — gitleaks, semgrep, kics, grype |
| `update:vulns` | Same as above | Pushes `vulnerabilities.json` to the dashboard via deploy key |
| `cold:scan` | API trigger, manual | Combined scan + dashboard push in one job (used by the test script) |

---

## Add more projects

Repeat Step 2 for each project in the group. The group CI/CD variables (`EZ_APPSEC_DASHBOARD_PROJECT`, `EZ_APPSEC_DASHBOARD_DEPLOY_KEY`) are inherited automatically — no per-project configuration needed.

---

## Remove ez-appsec from a project

```
/ez-appsec uninstall /path/to/repo
```

Opens a merge request that removes the `scan.yml` include from `.gitlab-ci.yml`.

---

## CI variable reference

| Variable | Scope | Description |
|----------|-------|-------------|
| `EZ_APPSEC_DASHBOARD_PROJECT` | Group | Full path of the dashboard project (e.g. `your-group/ez_appsec/ez-appsec-dashboard`) |
| `EZ_APPSEC_DASHBOARD_DEPLOY_KEY` | Group | Base64-encoded ed25519 private key — allows scan jobs to push to the dashboard |
| `EZ_APPSEC_VERSION` | Project | Docker image tag to use (default: `latest`) — set by `install` automatically |

Group variables are set automatically by `install-dashboard`. You can view and update them in **Group → Settings → CI/CD → Variables**.

---

## Manual trigger (cold scan)

To run a scan outside of a normal pipeline (e.g. for testing), trigger via the GitLab API:

```bash
curl -X POST \
  --header "PRIVATE-TOKEN: $GITLAB_ACCESS_TOKEN" \
  "https://gitlab.com/api/v4/projects/PROJECT_ID/pipeline?ref=master"
```

This triggers `CI_PIPELINE_SOURCE=api`, which activates the `cold:scan` job.

---

## Verify with the test script

```bash
bash gitlab/scripts/gitlab-pipeline-test.sh \
  --project your-group/ez_appsec/repo-name \
  --ref master \
  --check-dashboard
```

Exit 0 = pipeline succeeded, findings present, dashboard updated.

---

## Dashboard

See [docs/dashboard.md](dashboard.md) for the full dashboard feature guide and screenshots.
