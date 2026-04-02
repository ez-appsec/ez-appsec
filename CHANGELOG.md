# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.18] - 2026-04-02

### Added
- GitHub Actions workflow for Docker build and publish to GitHub Container Registry
- Semantic release automation for version management
- Comprehensive test suite with coverage reporting
- Security scanning integration with GitHub Advanced Security
- Support for GitHub Container Registry (ghcr.io)

### Changed
- Migrated from GitLab CI to GitHub Actions
- Updated Docker image references to use GitHub Container Registry
- Improved version handling with semantic-release
- Removed manual version bumping in favor of Conventional Commits

### Fixed
- Removed pinned semgrep version for better multi-architecture compatibility
- Fixed YAML syntax issues in GitHub Actions workflows

### Infrastructure
- Moved infrastructure documentation to separate repository (ez-appsec/ez-appsec-infra)

## [0.1.17] - 2026-03-25

### Features
- Initial ez-appsec release
- Support for gitleaks, semgrep, kics, and grype scanners
- GitLab and GitHub SARIF format support
- Multiple Docker image variants (standard, slim, micro, semgrep)

## [0.1.0] - 2026-03-25

### Added
- AI-powered security scanning with OpenAI LLM remediation guidance
- External scanner integration: gitleaks, semgrep, kics, grype
- Multiple output formats: JSON, SARIF, GitLab Vulnerability Format
- Multi-architecture Docker images: standard, slim, micro, semgrep variants
- GitLab CI/CD scan template (`scan.yml`) for easy project integration
- Claude Code slash commands `/ez-appsec-scan` and `/ez-appsec-install`
- Web dashboard for scan results
- CLI with `--version`, `--help`, and `scan` subcommand

[0.1.18]: https://github.com/ez-appsec/ez-appsec/compare/v0.1.17...v0.1.18
[0.1.17]: https://github.com/ez-appsec/ez-appsec/compare/v0.1.0...v0.1.17
[0.1.0]: https://github.com/ez-appsec/ez-appsec/releases/tag/v0.1.0
