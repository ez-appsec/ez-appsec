# Enterprise: Multi-Tenant Organization Management

ez-appsec supports org-wide deployment across all repositories in a GitHub organization. A single `org-sync` command discovers repos, merges configuration, and installs scan workflows — no per-repo setup required.

## Quick Start

```bash
export GITHUB_TOKEN=ghp_your_token_here

# Preview what would change (no writes)
ez-appsec org-sync --org mycompany --dry-run

# Install/update across all repos
ez-appsec org-sync --org mycompany
```

## Configuration Inheritance

ez-appsec uses a two-tier config model:

1. **Org-level config** — stored in a dedicated config repo (default: `<org>/.ez-appsec-config/.ez-appsec.yaml`)
2. **Repo-level config** — each repo's own `.ez-appsec.yaml`

### Merge rules

- Repo keys **override** org keys (repo wins on conflict)
- Keys present only in org config are **inherited**
- Keys present only in repo config are **kept as-is**

### Example

**Org config** (`mycompany/.ez-appsec-config/.ez-appsec.yaml`):
```yaml
severity: high
languages:
  - python
  - javascript
policy:
  - severity: critical
    action: fail
    max_count: 0
```

**Repo config** (`mycompany/api-service/.ez-appsec.yaml`):
```yaml
severity: medium
languages:
  - python
  - go
```

**Merged result** for `mycompany/api-service`:
```yaml
severity: medium          # repo wins
languages:                # repo wins
  - python
  - go
policy:                   # inherited from org
  - severity: critical
    action: fail
    max_count: 0
```

## Command Reference

### `ez-appsec org-sync`

| Option | Description | Default |
|--------|-------------|---------|
| `--org` | GitHub organization name | *required* |
| `--config-repo` | Repo containing org-level `.ez-appsec.yaml` | `<org>/.ez-appsec-config` |
| `--dry-run` | Preview changes without writing | `false` |

### What it does

1. **Discovers** all non-archived, non-fork repos in the org via `GET /orgs/{org}/repos`
2. **Fetches** org-level config from the config repo
3. **For each repo:**
   - Fetches repo-level config (if any)
   - Merges configs (repo overrides org)
   - Creates or updates `.github/workflows/ez-appsec-scan.yml`

## Required Permissions

The `GITHUB_TOKEN` needs these scopes:

| Scope | Why |
|-------|-----|
| `repo` | Read repo configs, write workflow files |
| `read:org` | List organization repositories |

For GitHub App installations, the app needs:
- **Repository permissions:** Contents (read/write), Metadata (read)
- **Organization permissions:** Members (read)

## Scan Workflow

The installed workflow (`.github/workflows/ez-appsec-scan.yml`) runs:

- On push to `main`
- On pull requests targeting `main`
- Weekly on Monday at 06:00 UTC

Results are uploaded as SARIF to GitHub's Security tab via `github/codeql-action/upload-sarif`.
