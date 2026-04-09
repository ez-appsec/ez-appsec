# Version Management

ez-appsec uses **semantic-release** for automated version management.

## Quick Start

To trigger a new release, simply push commits with conventional commit messages to the `main` branch:

```bash
# Feature release (minor version bump)
git commit -m "feat: add new scanner support"
git push origin main

# Bug fix release (patch version bump)
git commit -m "fix: resolve memory leak in scanner"
git push origin main
```

## Version Bump Rules

| Commit Type | Version Bump | Example |
|-------------|--------------|---------|
| `feat` | MINOR (0.x.0) | `feat: add custom scanner support` |
| `fix` | PATCH (0.0.x) | `fix: resolve scanner timeout issue` |
| `BREAKING CHANGE` | MAJOR (x.0.0) | `feat!: change scanner API` |
| `docs`, `chore`, `style`, `refactor`, `test`, `ci`, `build` | No bump | `docs: update installation guide` |

## Automatic Release Process

When you push to `main`:

1. ✅ Semantic-release analyzes your commits
2. ✅ Determines the next version number
3. ✅ Creates a git tag (e.g., `v0.1.19`)
4. ✅ Updates `CHANGELOG.md` automatically
5. ✅ Creates a GitHub release with notes
6. ✅ Triggers Docker image builds for all variants

## Examples

```bash
# New feature → 0.1.18 → 0.1.19
git commit -m "feat: add support for Python 3.12"
git push origin main

# Bug fix → 0.1.18 → 0.1.19
git commit -m "fix: handle empty scan results gracefully"
git push origin main

# Breaking change → 0.1.18 → 1.0.0
git commit -m "feat!: remove deprecated scanner API"
git push origin main

# Documentation (no version bump)
git commit -m "docs: update API documentation"
git push origin main
```

## Preview Next Version

To see what version would be created without actually releasing:

```bash
npx semantic-release --dry-run
```

## Current Version

Check the latest version:

```bash
# From git tags
git describe --tags --abbrev=0

# From VERSION file
cat VERSION

# From npm package
npm version
```

## See Also

- [CONTRIBUTING.md](CONTRIBUTING.md) - Full contributing guide
- [CHANGELOG.md](CHANGELOG.md) - Complete changelog
- [Semantic Release Documentation](https://semantic-release.gitbook.io/semantic-release/)
