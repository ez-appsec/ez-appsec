Run an ez-appsec security scan on the target directory and report findings.

## Steps

1. Determine the scan target. If the user provided a path argument (`$ARGUMENTS`), use it. Otherwise default to the current working directory.

2. Ensure the `jfelten/ez-appsec:latest` Docker image is available:
   ```bash
   docker image inspect jfelten/ez-appsec:latest >/dev/null 2>&1
   ```
   If not present, pull it:
   ```bash
   docker pull jfelten/ez-appsec:latest
   ```
   If the pull fails, tell the user and suggest they check Docker Hub or build from source:
   ```bash
   docker build -t jfelten/ez-appsec:latest https://github.com/jfelten/ez-appsec.git
   ```

3. Run the scan by mounting the resolved target path:
   ```bash
   docker run --rm \
     -v "$(realpath <TARGET_PATH>):/scan" \
     jfelten/ez-appsec:latest \
     scan /scan
   ```

4. Display the full output and summarize:
   - Total issues found
   - Breakdown by severity: critical / high / medium / low
   - Top 5 findings with file, line number, and description
   - Which scanners ran: gitleaks, semgrep, grype, kics

5. If the scan exits non-zero (scanner error, not findings), report the error and run diagnostics:
   ```bash
   docker run --rm jfelten/ez-appsec:latest status
   ```
   Report which scanners are missing and how to fix them.
