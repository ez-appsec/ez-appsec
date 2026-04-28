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
