---
description: Security scanning with ez-appsec (gitleaks + semgrep + grype + kics)
globs: ["**/*"]
alwaysApply: false
---

When the user asks to scan for security issues, check for vulnerabilities, or audit the codebase,
use ez-appsec via Docker.

Pull the image if needed:
```bash
docker pull ghcr.io/ez-appsec/ez-appsec:latest
```

Run the scan:
```bash
docker run --rm -v "$(pwd):/scan" ghcr.io/ez-appsec/ez-appsec:latest scan /scan
```

Interpret results:
- Group findings by severity: critical, high, medium, low
- For each finding include: scanner name, file path, line number, description
- Suggest specific fixes for the top issues
- If a scanner reports "not installed", run `docker run --rm ghcr.io/ez-appsec/ez-appsec:latest status`
