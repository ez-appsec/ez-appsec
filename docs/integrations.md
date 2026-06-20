# Integrations

## Jira

ez-appsec can automatically create and manage Jira issues for critical and high severity findings. When a finding is resolved (no longer detected), the corresponding Jira ticket is closed automatically.

### Setup

Set the following environment variables:

| Variable | Required | Description |
|---|---|---|
| `EZ_APPSEC_JIRA_URL` | Yes | Jira instance URL (e.g. `https://myteam.atlassian.net`) |
| `EZ_APPSEC_JIRA_EMAIL` | Yes | Email address of the Jira API user |
| `EZ_APPSEC_JIRA_TOKEN` | Yes | Jira API token ([create one here](https://id.atlassian.com/manage-profile/security/api-tokens)) |
| `EZ_APPSEC_JIRA_PROJECT` | Yes | Jira project key (e.g. `SEC`) |
| `EZ_APPSEC_JIRA_ISSUE_TYPE` | No | Issue type name (default: `Bug`) |

Or pass them as CLI flags:

```bash
ez-appsec scan . \
  --jira-url https://myteam.atlassian.net \
  --jira-email bot@example.com \
  --jira-token ATATT3... \
  --jira-project SEC
```

### Behavior

- **Creates issues** for new critical and high findings. Medium and low findings are skipped.
- **Deduplicates** using a fingerprint (rule ID + file path). A fingerprint map is stored at `data/projects/<project>/jira_map.json`.
- **Closes issues** when a finding is no longer detected in the latest scan. A comment is added before transitioning the issue to "Done".
- **Priority mapping**: critical → Highest, high → High.
- **Labels**: Issues are tagged with `security` and `ez-appsec` by default.

### Issue content

Each Jira issue includes:

- Severity and scanner name
- Rule ID and file location
- Finding description
- Remediation guidance (when available)
- Link to the dashboard (when `--dashboard-url` or `EZ_APPSEC_DASHBOARD_URL` is set)

### CI/CD example (GitHub Actions)

```yaml
- name: Scan and sync to Jira
  env:
    EZ_APPSEC_JIRA_URL: ${{ secrets.JIRA_URL }}
    EZ_APPSEC_JIRA_EMAIL: ${{ secrets.JIRA_EMAIL }}
    EZ_APPSEC_JIRA_TOKEN: ${{ secrets.JIRA_TOKEN }}
    EZ_APPSEC_JIRA_PROJECT: SEC
    EZ_APPSEC_DASHBOARD_URL: https://security.example.com
  run: ez-appsec scan .
```

## Slack / Teams Notifications

See the `--slack-webhook` and `--teams-webhook` options on the `scan` command. Set `EZ_APPSEC_SLACK_WEBHOOK` or `EZ_APPSEC_TEAMS_WEBHOOK` environment variables for CI/CD use.

## License Compliance

ez-appsec can check dependency licenses against configurable allowed and denied lists. License data is extracted using [syft](https://github.com/anchore/syft) (bundled with grype).

### Setup

Add a `license_policy` section to your `.ez-appsec.yaml`:

```yaml
license_policy:
  allowed_licenses:
    - MIT
    - Apache-2.0
    - BSD-2-Clause
    - BSD-3-Clause
    - ISC
  denied_licenses:
    - GPL*
    - AGPL*
    - SSPL*
```

### How it works

- **Allowed list**: Licenses that match are permitted. If an allowed list is configured, any license not matching is flagged as "unknown" (medium severity).
- **Denied list**: Licenses that match are rejected (high severity). Denied takes priority over allowed.
- **Wildcards**: Both lists support glob patterns (e.g., `GPL*` matches `GPL-2.0`, `GPL-3.0-only`, etc.).
- **SPDX identifiers**: License values are matched using SPDX identifiers from the syft SBOM output.

### Running a license check

Pass the `--license-check` flag to the `scan` command:

```bash
ez-appsec scan . --license-check
```

License violations appear as `category: license_compliance` findings in the scan output alongside other security findings.

### Scan output

When license checking is enabled, the scan result includes:

| Field | Description |
|---|---|
| `license_summary.total` | Total packages scanned |
| `license_summary.allowed` | Packages with allowed licenses |
| `license_summary.denied` | Packages with denied licenses |
| `license_summary.unknown` | Packages with unrecognized licenses |
| `license_packages` | Full package list with license details |

### Prerequisites

- **syft** must be installed: `brew install syft` or `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh`
- syft is already included in the ez-appsec Docker images that bundle grype

### CI/CD example

```yaml
- name: Scan with license compliance
  run: ez-appsec scan . --license-check --output results.json
```

## REST API

The optional REST API (`api/`, packaged as `ghcr.io/ez-appsec/ez-appsec-api`)
exposes dashboard findings and on-demand scans over HTTP. It is intended for
**trusted, operator-only** networks; it is not hardened for unauthenticated
internet exposure.

### Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | none | Liveness probe |
| `POST` | `/scan` | required | Enqueue a scan; returns `{job_id}` |
| `GET` | `/scan/{job_id}` | required | Poll scan status |
| `GET` | `/projects` | required | List dashboard projects |
| `GET` | `/projects/{slug}/findings` | required | List findings (supports `severity`, `category`, `scanner`, `file` filters) |
| `GET` | `/projects/{slug}/history` | required | Trend history |
| `GET` | `/openapi.json` | required | OpenAPI schema (gated to avoid surface enumeration) |
| `GET` | `/docs` | required | Swagger UI |

### Configuration

| Env var | Required | Description |
|---|---|---|
| `EZ_APPSEC_API_KEY` | yes | API key; the process **fails fast at startup** if unset. Sent via `X-API-Key` header. |
| `EZ_APPSEC_ALLOWED_ROOTS` | no | Colon-separated list of local paths scans may target. When set, `POST /scan` with a local path outside these roots is rejected (HTTP 400). Unset = no restriction. |
| `EZ_DASHBOARD_OWNER` / `EZ_DASHBOARD_REPO` | no | Dashboard GitHub repo to read findings from. |
| `GITHUB_TOKEN` | recommended | Raises the GitHub API rate limit for dashboard reads. |

### Security notes

- Authentication uses `hmac.compare_digest` (constant-time) and is enforced on
  every endpoint except `/health`.
- Scan targets are validated before reaching a subprocess: leading-dash paths
  and SSH-style `git@` URLs are rejected (HTTP/HTTPS clone URLs only).
- `EZ_APPSEC_ALLOWED_ROOTS` confines local scan targets to approved directories.
- Scan jobs are tracked in a bounded, TTL-evicted store and run on a fixed-size
  worker pool to prevent unbounded resource use.
