# ez-appsec

**AI-powered application security scanning** — free, open-source, works with GitHub and GitLab.

ez-appsec orchestrates four best-in-class scanners (gitleaks, semgrep, kics, grype), normalises their output into a unified schema, and pushes results to a hosted security dashboard. No cloud account or API key required.

```
Your codebase
     │
     ▼  ez-appsec scan
┌────────────────────────────────────────────┐
│  gitleaks · semgrep · kics · grype         │
│  secrets    SAST      IaC    dependencies  │
└──────────────────┬─────────────────────────┘
                   │  unified vulnerability schema
                   ▼
     CLI · JSON · SARIF · GitLab format
                   │
                   ▼
     Security Dashboard (GitHub / GitLab Pages)
```

---

## Quickstart with Claude Code

The fastest way to add ez-appsec to any repository is through the Claude Code skill.

**Step 1 — Install the skill** (one-time, works in every project):

```bash
curl -fsSL https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/skills/install.sh | bash
```

**Step 2 — Add ez-appsec to a repository:**

```
# GitHub
/ez-appsec install-app owner/repo

# GitLab
/ez-appsec install /path/to/repo
```

That's it. The skill provisions the workflow, sets secrets, and triggers the first scan automatically.

---

## Platform Guides

| Platform | Guide |
|----------|-------|
| GitHub | [docs/github.md](docs/github.md) |
| GitLab | [docs/gitlab.md](docs/gitlab.md) |
| Dashboard | [docs/dashboard.md](docs/dashboard.md) |

---

## ez-appsec Skills Reference

The `/ez-appsec` Claude Code skill is a dispatcher — the first word routes to the right subcommand.

### Installation

| Command | Description |
|---------|-------------|
| `/ez-appsec install-app [owner/repo]` | **GitHub** — installs the scan workflow, provisions App secrets, and triggers the first scan |
| `/ez-appsec install [path]` | **GitLab** — patches `.gitlab-ci.yml` with the `scan.yml` include and opens a merge request |
| `/ez-appsec install-dashboard [owner/repo]` | **GitHub** — creates and configures the dashboard repo with GitHub Pages and App secrets |

### Scanning

| Command | Description |
|---------|-------------|
| `/ez-appsec scan [path]` | Run a local security scan using the ez-appsec Docker image (CLI output) |
| `/ez-appsec scan-context [path]` | Scan with Docker and load findings into context for analysis |
| `/ez-appsec load [project]` | Load a project's vulnerabilities from the dashboard into context for analysis |

### Maintenance

| Command | Description |
|---------|-------------|
| `/ez-appsec update-dashboard [owner/repo]` | Re-provision App secrets and update dashboard web assets to the latest release |
| `/ez-appsec uninstall-app [owner/repo]` | **GitHub** — removes the scan workflow and prunes the repo's dashboard data |
| `/ez-appsec uninstall [path]` | **GitLab** — removes the `scan.yml` include via merge request |

### Help

| Command | Description |
|---------|-------------|
| `/ez-appsec help` | Print available subcommands |

---

## Scanners

| Scanner | What it finds |
|---------|--------------|
| [gitleaks](https://github.com/gitleaks/gitleaks) | Secrets and credentials (140+ patterns) |
| [semgrep](https://semgrep.dev/) | SAST — logic bugs, injection, misuse (1000+ rules) |
| [kics](https://www.kics.io/) | Infrastructure-as-code misconfigurations |
| [grype](https://github.com/anchore/grype) | Known CVEs in dependencies and SBOMs |

All findings are normalised into a unified schema with consistent severity levels, file paths, and line numbers.

---

## Docker Images

```bash
# Standard (all scanners)
docker pull ghcr.io/ez-appsec/ez-appsec:latest

# Slim (~300 MB, no semgrep)
docker pull ghcr.io/ez-appsec/ez-appsec:slim

# Micro (secrets + CVEs only)
docker pull ghcr.io/ez-appsec/ez-appsec:micro

# Run a scan
docker run --rm -v $(pwd):/scan ghcr.io/ez-appsec/ez-appsec:latest scan /scan
```

---

## AI Remediation

When `OPENAI_API_KEY` is set in the scanning environment, each finding is enriched with:
- Plain-language risk explanation
- Step-by-step fix instructions
- Code example where applicable

---

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

## Author

Created by [John Felten](https://www.linkedin.com/in/john-felten/) — DevSecOps Engineer, 25+ years experience.
