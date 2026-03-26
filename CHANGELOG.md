# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
