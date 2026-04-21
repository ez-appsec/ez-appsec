# Contributing to ez-appsec

Thank you for contributing to ez-appsec! This document provides guidelines for contributing to the project.

## Contributing to the Roadmap

You don't need to write code to contribute — proposing a well-scoped problem is equally valuable.

### Rough idea → use Discussions

If you have a rough idea, a complaint, or a "wouldn't it be nice if..." — open a discussion in the [Ideas category](https://github.com/ez-appsec/ez-appsec/discussions/categories/ideas). No structure required. Upvotes help maintainers prioritize.

### Concrete proposal → open a Plan Proposal issue

When your idea is specific enough to describe a problem and a rough solution, open a [Plan Proposal issue](https://github.com/ez-appsec/ez-appsec/issues/new?template=plan-proposal.md). A maintainer will review it and, if accepted, spec it into a full PLAN issue with all the implementation detail needed to implement it.

### What makes a good plan

A proposal is ready to become a plan when it satisfies all of these:

| Criterion | Why it matters |
|---|---|
| **One primary new module** — the feature lives in a single new file (`ez_appsec/<feature>.py`) | Prevents merge conflicts; each plan owns its module |
| **Additive-only changes to shared files** — only appends to `cli.py`, `scanner.py`, `external_scanners.py` | Multiple plans can touch shared files without blocking each other |
| **Testable without a running scanner** — unit tests use mocks, not real Docker processes | CI runs fast; tests pass in any environment |
| **Append-only schema changes** — adds new fields to `vulnerabilities.json`, never renames or removes | Existing consumers don't break when the plan merges |
| **Independent or single-dependency** — either standalone or depends on exactly one other named plan | Avoids cascading merge dependencies |
| **Named test files** — the done criteria list the exact test file names and what each covers | Makes it clear when the plan is complete |

If your proposal doesn't fit these constraints yet, that's fine — note it in the proposal and a maintainer will help shape it.

### Improving an existing plan

If you spot a gap in an existing plan issue (missing edge case, incorrect file name, unclear conflict guard), comment on the issue directly. If it's a significant change to scope, open a new Plan Proposal referencing the original.

---

## Claiming a Plan (human or AI-assisted)

Each roadmap item in the [GitHub Project](https://github.com/orgs/ez-appsec/projects/2) is a self-contained, atomic plan with exact file ownership, conflict guards, and done criteria. The issue body is the complete specification — you can implement it manually or hand it directly to any AI coding assistant.

### Prerequisites

| Requirement | Why | How to satisfy |
|---|---|---|
| **GitHub account** | Fork the repo, open PRs | [github.com](https://github.com) |
| **`gh` CLI** | Authenticate, create PRs | `brew install gh` or [cli.github.com](https://cli.github.com) |
| **GitHub token scopes** | Read issues, write project board, open PRs | Run `gh auth login` and choose browser-based auth — it grants all required scopes automatically. If your org enforces SSO, you must also authorize the token for that org at [github.com/settings/tokens](https://github.com/settings/tokens). If using a PAT instead: create at [github.com/settings/tokens/new](https://github.com/settings/tokens/new) and check `repo` (full), `project`, and `read:org`. |
| **`git` identity** | Sign commits | `git config --global user.email "you@example.com"` and `git config --global user.name "Your Name"` |
| **Python 3.10+** | Run the test suite | [python.org](https://python.org) or `brew install python` |
| **Docker** | Scanner tests that invoke external tools | [Docker Desktop](https://www.docker.com/products/docker-desktop) — start it before running `pytest` |

### Quickstart

**Step 1 — Fork and clone** (external contributors must fork; org members can clone directly)

```bash
# External contributor:
gh repo fork ez-appsec/ez-appsec --clone --remote
cd ez-appsec

# Org member:
git clone https://github.com/ez-appsec/ez-appsec
cd ez-appsec
```

**Step 2 — Install the package in development mode**

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

**Step 3 — Verify the baseline test suite passes**

```bash
pytest tests/ -x -q
```

All tests should pass before you write a single line. If they don't, open an issue rather than starting work on top of a broken baseline.

**Step 4 — Claim a plan**

```bash
bash scripts/claim-plan.sh <issue-number>
```

`claim-plan.sh` checks prerequisites, fetches the plan to `.plan-context.md`, moves the issue to "In Progress", creates your branch, and prints a ready-to-paste AI prompt. It exits immediately with a clear error if anything is missing.

> **Note on issue assignment:** The script attempts to self-assign the issue. This requires you to be an org member or collaborator. If you are an external contributor, the script will warn and continue — comment on the issue instead to signal that you are working on it.

**Example output:**

```
$ bash scripts/claim-plan.sh 21

Checking prerequisites...
OK:    All prerequisites satisfied (Python 3.11, gh authenticated)

Fetching issue #21...
OK:    Issue: [PLAN-21] Reusable Security Agent with MCP & Multi-Transport
OK:    Branch: feat/plan-21-reusable-security-agent-with-mcp-multi-transport
OK:    Saved plan to .plan-context.md
OK:    Moved issue to 'In Progress' on the project board
OK:    Created branch: feat/plan-21-reusable-security-agent-with-mcp-multi-transport

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Ready. Copy the prompt below into your AI assistant.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Read the plan in .plan-context.md.
[... full prompt follows ...]
```

### The AI prompt (printed by the script)

The script prints this prompt with the issue title and number already filled in. Paste it into any AI coding assistant — Claude Code, Cursor, Copilot Workspace, Gemini Code Assist, or any other tool:

```
Read the plan in .plan-context.md.

Implement it exactly as specified:
- Create only the files listed under "New files"
- Add only what "Modified files" specifies — append, never restructure
- Do not touch any file listed under "Conflict guard"
- Read the files listed under "Read first" before writing any code
- Write the tests in "Done criteria" first, then the implementation
- After each new file: run `pytest tests/ -x -q` and fix all failures before continuing
- Before opening the PR: run `black ez_appsec/ tests/` to format
- When every done criterion is met:
    git add -p   # stage only your changes, file by file
    git commit -m "feat: [PLAN TITLE]"
    git push origin [BRANCH NAME]
    gh pr create --draft --title "[PLAN TITLE]" --body "Closes #[N]" --repo ez-appsec/ez-appsec

Do not ask for confirmation at any step. If pytest fails 3 times on the
same file, stop and report exactly which assertion is failing and why.
```

The plan is fetched to a local `.plan-context.md` file (gitignored) so the AI reads it from disk rather than fetching a URL, keeping the session cheaper and faster.

### Implementing manually (no AI assistant)

1. Complete steps 1–3 in Quickstart above (fork/clone, install, verify baseline)
2. Run `bash scripts/claim-plan.sh <issue-number>` to claim and branch
3. Read the files listed under "Read first" in the issue
4. Create files listed under "New files"; add only what "Modified files" specifies
5. Do not touch files listed under "Conflict guard"
6. Write tests first; run `pytest tests/ -x -q` after each file
7. Run `black ez_appsec/ tests/` before opening a PR
8. Open a draft PR when all done criteria pass

### When a dependency plan hasn't merged yet

Some plans depend on a module created by another plan (e.g., PLAN-17 imports from PLAN-04's `fix_pr.py`). If the dependency hasn't merged when you start:

1. Check if the dependency branch exists: `git branch -r | grep feat/plan-04`
2. If it exists, rebase onto it locally so you can import from it
3. If it doesn't exist, stub the import with a `try/except ImportError` fallback and document this in your PR description
4. When the dependency merges, remove the fallback and rebase

### Why issues are structured this way

Each issue specifies:
- **Read first** — files to understand before writing any code
- **New files** — safe to create with no merge risk
- **Modified files** — exactly what to add and where, nothing to restructure
- **Conflict guard** — files owned by other plans that must not be touched
- **Done criteria** — exact test file names and what each test must cover

This lets multiple contributors (human or AI-assisted) work on different plans simultaneously without stepping on each other.

### Conflict avoidance rules

- Each plan owns its **primary new module** (`ez_appsec/<feature>.py`). Never modify another plan's primary module.
- Additions to shared files (`cli.py`, `scanner.py`, `external_scanners.py`) are always **appended** — new functions or isolated `if` blocks at the bottom. Never restructure existing code in these files.
- The `vulnerabilities.json` schema is **append-only**. Add new fields; never rename or remove existing ones.
- If two plans both need a utility (e.g., the finding fingerprint hash), the second to merge imports it from the first. If it hasn't merged yet, see "When a dependency plan hasn't merged yet" above.

---

## Version Management with Semantic Release

ez-appsec uses **semantic-release** for automated versioning and release management. This means version numbers are automatically determined based on your commit messages using [Conventional Commits](https://www.conventionalcommits.org/).

### How It Works

1. **Automated Version Bumping**: Based on your commit types, semantic-release automatically increments:
   - `MAJOR` (x.0.0) for breaking changes
   - `MINOR` (0.x.0) for new features
   - `PATCH` (0.0.x) for bug fixes

2. **Automatic Releases**: When commits are pushed to `main`, semantic-release:
   - Analyzes commits since the last release
   - Determines the next version number
   - Creates a git tag (e.g., v0.1.19)
   - Generates a changelog
   - Creates a GitHub release
   - Triggers Docker image builds

### Commit Message Format

Use the Conventional Commits format:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

#### Commit Types

| Type | Description | Version Bump |
|------|-------------|--------------|
| `feat` | New feature | MINOR |
| `fix` | Bug fix | PATCH |
| `docs` | Documentation only | No bump |
| `style` | Code style changes (formatting) | No bump |
| `refactor` | Code refactoring | No bump |
| `perf` | Performance improvements | PATCH |
| `test` | Adding or updating tests | No bump |
| `chore` | Maintenance tasks | No bump |
| `ci` | CI/CD changes | No bump |
| `build` | Build system or dependencies | No bump |

#### Examples

```bash
# Feature - triggers MINOR version bump (0.1.18 → 0.1.19)
git commit -m "feat: add support for custom security scanners"

# Bug fix - triggers PATCH version bump (0.1.18 → 0.1.19)
git commit -m "fix: resolve memory leak in scanner initialization"

# Breaking change - triggers MAJOR version bump (0.1.18 → 1.0.0)
git commit -m "feat!: change scanner API to use async/await"

# Documentation - no version bump
git commit -m "docs: update installation guide for GitHub Container Registry"

# Refactoring - no version bump
git commit -m "refactor: optimize scanner configuration loading"

# Breaking change with footer
git commit -m "feat: add new dependency scanner

BREAKING CHANGE: The scanner output format has changed"
```

### Development Workflow

#### For New Features

```bash
# 1. Create a feature branch
git checkout -b feat/new-scanner-support

# 2. Make your changes
# ... work on your feature ...

# 3. Commit with semantic message
git add .
git commit -m "feat: add support for custom security scanners"

# 4. Push and create PR
git push origin feat/new-scanner-support
# Then create PR on GitHub
```

#### For Bug Fixes

```bash
# 1. Create a fix branch
git checkout -b fix/scanner-crash

# 2. Make your changes
# ... fix the bug ...

# 3. Commit with semantic message
git add .
git commit -m "fix: resolve crash when scanning large files"

# 4. Push and create PR
git push origin fix/scanner-crash
# Then create PR on GitHub
```

### Release Process

1. **Push to main**: When you merge a PR to `main`:
   - Semantic-release analyzes commits
   - Creates a new version tag if needed
   - Generates changelog
   - Creates GitHub release
   - Triggers Docker image builds

2. **No manual versioning**: Never manually edit the `VERSION` file or create tags manually

3. **Preview next version**: To see what version will be released:
   ```bash
   npx semantic-release --dry-run
   ```

### Testing Releases

For testing the release process without affecting the main branch:

```bash
# Create a test branch
git checkout -b test/release

# Make some commits with semantic messages
git commit -m "feat: test feature for release"

# Run semantic-release in dry-run mode
npx semantic-release --dry-run --branches test
```

### Troubleshooting

#### Release Not Creating

Check:
1. Commit messages follow Conventional Commits format
2. Commits have proper types (`feat`, `fix`, etc.)
3. Not a documentation-only commit (`docs`, `chore`, etc.)
4. Branch is `main` (not a feature branch)

#### Wrong Version

Semantic-release analyzes all commits since the last tag. Check:
1. Commit history for unexpected commit types
2. Previous tags exist: `git tag -l`
3. Run dry-run to see what version will be created: `npx semantic-release --dry-run`

#### Rollback a Release

If a bad release was created:

```bash
# Delete the tag (requires force push)
git push origin :refs/tags/v0.1.19 --force

# Delete the GitHub release (manually via GitHub UI or gh CLI)
gh release delete v0.1.19 --yes
```

### Additional Resources

- [Conventional Commits Specification](https://www.conventionalcommits.org/)
- [Semantic Release Documentation](https://semantic-release.gitbook.io/semantic-release/)
- [Commitlint](https://commitlint.js.org/) - Lint commit messages (optional but recommended)

### Recommended Tools

#### Commitlint (Optional)

To enforce Conventional Commits:

```bash
# Install commitlint
npm install --save-dev @commitlint/cli @commitlint/config-conventional

# Add configuration
echo "module.exports = { extends: ['@commitlint/config-conventional'] };" > commitlint.config.js

# Add husky for pre-commit hooks
npm install --save-dev husky
npx husky install
npx husky add .husky/commit-msg 'npx --no -- commitlint --edit "$1"'
```

This will prevent non-conventional commits from being pushed.

## Code Quality

- Write tests for new features
- Ensure all tests pass: `pytest tests/`
- Run linting: `black ez_appsec/ tests/`
- Update documentation as needed

## Questions?

Feel free to open an issue or start a discussion if you have questions about contributing!
