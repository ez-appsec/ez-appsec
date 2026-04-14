# ez-appsec Skills

Installs the `/ez-appsec` Claude Code slash command dispatcher and optional AI assistant integrations for GitHub Copilot and Cursor.

## Quick install

**Claude Code — global (works in every project):**
```bash
curl -fsSL https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/skills/install.sh | bash
```

**Everything at once (global Claude + Copilot + Cursor):**
```bash
curl -fsSL https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/skills/install.sh | bash -s -- --all
```

## Install options

```
--global     Install Claude Code skill globally in ~/.claude/commands/ (default)
--project    Install in the current project's .claude/commands/ only
--copilot    Append to .github/copilot-instructions.md
--cursor     Add .cursor/rules/ez-appsec.md
--all        All of the above (global Claude)
--uninstall  Remove installed files
```

## Commands

The `/ez-appsec` skill routes based on the first word of the argument:

| Command | Description |
|---------|-------------|
| `/ez-appsec install-app [owner/repo]` | **GitHub** — installs the scan workflow, provisions App secrets, triggers first scan |
| `/ez-appsec install [path]` | **GitLab** — patches `.gitlab-ci.yml` with the `scan.yml` include, opens merge request |
| `/ez-appsec install-dashboard [owner/repo]` | **GitHub** — creates and configures the dashboard repo with Pages and App secrets |
| `/ez-appsec update-dashboard [owner/repo]` | Re-provision secrets and update dashboard web assets to the latest release |
| `/ez-appsec uninstall-app [owner/repo]` | **GitHub** — removes workflow and prunes dashboard data |
| `/ez-appsec uninstall [path]` | **GitLab** — removes `scan.yml` include via merge request |
| `/ez-appsec scan [path]` | Run a local security scan using the ez-appsec Docker image |
| `/ez-appsec load [project]` | Load a project's vulnerabilities from the dashboard into context for analysis |
| `/ez-appsec help` | Print available subcommands |

## GitHub Copilot / Cursor

Install with `--copilot` or `--cursor` and ask naturally:

```
scan this project for security issues
check for vulnerabilities
run a security audit
```

The assistant instructions configure Copilot and Cursor to use the ez-appsec Docker image automatically.

## Files

```
skills/
  install.sh                          Universal installer
  claude/
    ez-appsec-install-app.md          GitHub App install skill
    ez-appsec-install.md              GitLab install skill
    ez-appsec-install-dashboard.md    GitHub dashboard install skill
    ez-appsec-update-dashboard.md     Dashboard update skill
    ez-appsec-uninstall-app.md        GitHub uninstall skill
    ez-appsec-uninstall.md            GitLab uninstall skill
    ez-appsec-scan.md                 Local scan skill
    ez-appsec-load-vulns.md           Load project vulnerabilities from dashboard into context
  copilot/
    instructions.md                   GitHub Copilot workspace instructions
  cursor/
    ez-appsec.md                      Cursor AI rules
```
