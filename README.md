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
| `/ez-appsec scan [path]` | Scan with Docker and load findings into context for analysis |
| `/ez-appsec load [project]` | Load a project's vulnerabilities from the dashboard into context for analysis |
| `/ez-appsec remediate [filter]` | Prioritized fix plan balancing severity vs risk — applies safe fixes immediately, confirms risky ones once |

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

Contributions are welcome from humans, AI agents, and human+AI teams.

There are two contribution paths depending on the size of the change.

### Small changes — no plan required

Bug fixes, documentation corrections, minor refactors, and small tweaks can go straight to a PR.

Open a **[Small Change issue](https://github.com/ez-appsec/ez-appsec/issues/new?template=small-change.md)** to track the work, then submit a PR that references it. The bar is: `pytest tests/` passes, no scope creep.

### Significant work — plan first

New features, integrations, and anything that touches multiple modules require a plan before implementation begins. This prevents conflicts between contributors working in parallel and keeps PRs reviewable.

**Option A — Claim an existing roadmap item**

Browse the [ez-appsec Roadmap project](https://github.com/orgs/ez-appsec/projects/2) and pick an unassigned plan. Leave a comment on the issue saying you are claiming it, then self-assign and move it to *In Progress*. The issue already contains scope, technical approach, and done criteria.

**Option B — Propose a new plan**

If your idea is not on the roadmap, open a **[Plan issue](https://github.com/ez-appsec/ez-appsec/issues/new?template=plan.md)** first. Describe what you are building, the scope, technical approach, and test strategy. Wait for a maintainer to acknowledge before opening a draft PR. This avoids duplicate work and surfaces conflicts early.

### Human + AI workflows

AI-assisted contributions are encouraged. When using Claude Code or another agent to implement a plan:

- The plan issue is the agent's scope boundary — it should not touch modules outside the plan
- Use `/ez-appsec test` to verify nothing regressed before opening a PR
- The PR description should note which parts were AI-generated and which were human-reviewed
- All tests must pass; the agent is not exempt from the done criteria

### Ground rules

- **Tests ship with the code.** Every plan lists required test files. PRs without tests for new behavior will not be merged.
- **Plans are independent.** If your change conflicts with another open plan, coordinate in the issue before proceeding.
- **Schema is append-only.** The `vulnerabilities.json` schema may gain new fields but existing fields must not be renamed or removed — downstream tools depend on them.
- **Docker size budget.** Adding a runtime dependency requires verifying the standard image stays under 2 GB.

See [ROADMAP.md](ROADMAP.md) for the full list of planned work and [CONTRIBUTING.md](CONTRIBUTING.md) for environment setup and coding conventions.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the path to feature parity with commercial AppSec platforms — 20 independent plans across developer feedback, compliance, platform expansion, enterprise features, and observability. Each plan is claimable by any contributor (human or AI).

| | |
|---|---|
| GitHub Project | [ez-appsec Roadmap](https://github.com/orgs/ez-appsec/projects/2) |
| GitLab Tracking | [jfelten.work-group/ez_appsec/ez-appsec-roadmap](https://gitlab.com/jfelten.work-group/ez_appsec/ez-appsec-roadmap) |

## License

MIT — see [LICENSE](LICENSE).

## Author

Created by [John Felten](https://www.linkedin.com/in/john-felten/) — DevSecOps Engineer, 25+ years experience.
