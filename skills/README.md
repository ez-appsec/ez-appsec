# ez-appsec AI Skills

Installs two Claude Code slash commands:

| Command | Description |
|---------|-------------|
| `/ez-appsec-scan` | Run a full security scan on a directory |
| `/ez-appsec-install` | Install ez-appsec into a GitLab project via `scan.yml` include + MR |

Supported frameworks:

| Framework | Files installed |
|-----------|----------------|
| Claude Code | `~/.claude/commands/ez-appsec-scan.md` (global) |
| Claude Code | `~/.claude/commands/ez-appsec-install.md` (global) |
| Claude Code | `.claude/commands/ez-appsec-scan.md` (project) |
| Claude Code | `.claude/commands/ez-appsec-install.md` (project) |
| GitHub Copilot | `.github/copilot-instructions.md` |
| Cursor | `.cursor/rules/ez-appsec.md` |

## Quick install

**Claude Code — global (works in every project):**
```bash
./skills/install.sh
```

**Everything at once:**
```bash
./skills/install.sh --all
```

**One-liner — project `.claude/commands/` (no clone required):**
```bash
curl -fsSL https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/skills/install.sh | bash -s -- --project
```

**One-liner — global `~/.claude/commands/` + Copilot + Cursor:**
```bash
curl -fsSL https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/skills/install.sh | bash -s -- --all
```

## Install options

```
--global     Install Claude Code skill globally (default)
--project    Install Claude Code skill in the current project only
--copilot    Append to .github/copilot-instructions.md
--cursor     Add .cursor/rules/ez-appsec.md
--all        All of the above (global Claude)
--uninstall  Remove installed files
```

## Using the skills

### Claude Code — scan
```
/ez-appsec-scan              # scan current directory
/ez-appsec-scan src/         # scan a subdirectory
```

### Claude Code — install into a GitLab project
```
/ez-appsec-install                        # install into current directory's GitLab repo
/ez-appsec-install /path/to/other/repo    # install into another project
```

This command will:
1. Add an `include:` block referencing `scan.yml` to the project's `.gitlab-ci.yml`
2. Push the changes to a branch named by `EZ_APPSEC_BRANCH` (default: `ez-appsec-pages`)
3. Open a merge request via `glab` (or print a manual MR URL if `glab` is unavailable)

### GitHub Copilot / Cursor
Just ask naturally:
```
scan this project for security issues
check for vulnerabilities
run a security audit
```

The instructions tell the assistant to use the ez-appsec Docker image automatically.

## How it works

The skill runs:
```bash
docker run --rm -v "$(pwd):/scan" ghcr.io/ez-appsec/ez-appsec:latest scan /scan
```

The image bundles four scanners:
- **gitleaks** — hardcoded secrets and credentials
- **semgrep** — static analysis (SAST)
- **grype** — known CVEs in dependencies
- **kics** — infrastructure-as-code misconfigurations

No API key or cloud account required.

## Files

```
skills/
  install.sh                   Universal installer
  claude/
    ez-appsec-scan.md          Claude Code /ez-appsec-scan slash command
    ez-appsec-install.md       Claude Code /ez-appsec-install slash command
  copilot/
    instructions.md            GitHub Copilot workspace instructions
  cursor/
    ez-appsec.md               Cursor AI rules
```
