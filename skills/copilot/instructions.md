## Security Scanning with ez-appsec

This project uses [ez-appsec](https://github.com/jfelten/ez-appsec) for automated security scanning.
It runs gitleaks (secrets), semgrep (SAST), grype (CVEs), and kics (IaC) via a single Docker image.

When asked to run a security scan, check for vulnerabilities, audit the code, or find security issues:

1. Pull the scanner image if not already present:
   ```bash
   docker pull jfelten/ez-appsec:latest
   ```

2. Run the scan against the target directory:
   ```bash
   docker run --rm -v "$(pwd):/scan" jfelten/ez-appsec:latest scan /scan
   ```

3. Summarize findings grouped by severity (critical → high → medium → low) and suggest
   concrete remediation steps for each finding.

4. If the scan fails, check scanner status:
   ```bash
   docker run --rm jfelten/ez-appsec:latest status
   ```
