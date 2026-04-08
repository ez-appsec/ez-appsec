# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do not report security vulnerabilities via public GitHub issues.**

Please email **security@ez-appsec.ai** with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

We will acknowledge your report within 48 hours and aim to release a fix within 30 days for critical issues.

## Responsible Disclosure

We follow responsible disclosure practices. After a fix is released, you are welcome to publish details of the vulnerability. Please coordinate timing with us so users have time to update.

## Scope

In scope:
- ez-appsec CLI (`ez_appsec/` package)
- GitHub Actions workflow template (`.github/workflows/github-scan.yml`)
- GitLab CI template (`gitlab/scan.yml`)
- Docker images (`ghcr.io/ez-appsec/ez-appsec`)

Out of scope:
- Vulnerabilities in the intentionally-vulnerable test projects used for integration testing
- Vulnerabilities in upstream scanners (gitleaks, semgrep, kics, grype) — report those to their respective maintainers
