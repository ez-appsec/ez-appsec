# Contributing to ez-appsec

Thank you for contributing to ez-appsec! This document provides guidelines for contributing to the project.

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
