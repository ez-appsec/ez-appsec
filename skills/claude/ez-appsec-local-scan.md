Run an ez-appsec security scan on a local directory using the micro Docker image and report findings.

## Steps

### 1. Resolve the scan target

If the user provided a path in `$ARGUMENTS`, use it as the scan target.
Otherwise default to the current working directory.

Resolve to an absolute path:
```bash
realpath "<TARGET>"
```

### 2. Ensure the micro image is available

```bash
docker image inspect registry.gitlab.com/jfelten.work-group/ez_appsec/ez_appsec:micro >/dev/null 2>&1
```

If not present, pull it:
```bash
docker pull registry.gitlab.com/jfelten.work-group/ez_appsec/ez_appsec:micro
```

If the pull fails, offer to build it locally:
```bash
docker build -f /Users/johnfelten/git/2026/ez-appsec/Dockerfile.micro \
  -t registry.gitlab.com/jfelten.work-group/ez_appsec/ez_appsec:micro \
  /Users/johnfelten/git/2026/ez-appsec
```

### 3. Run the scan

```bash
docker run --rm \
  -v "<RESOLVED_TARGET>:/scan" \
  registry.gitlab.com/jfelten.work-group/ez_appsec/ez_appsec:micro \
  gitlab-scan /scan --output /scan/ez-appsec-results.json
```

The output file `ez-appsec-results.json` is written into the target directory.

### 4. Parse and report findings

Read `<RESOLVED_TARGET>/ez-appsec-results.json` and summarize:
- Total vulnerabilities found
- Breakdown by severity: critical / high / medium / low / info
- Top findings (up to 10): scanner, severity, title, file, line number
- Which scanners produced results: gitleaks, grype, kics (semgrep is not in micro)

### 5. Handle errors

If the container exits non-zero (tool error, not findings):
```bash
docker run --rm \
  registry.gitlab.com/jfelten.work-group/ez_appsec/ez_appsec:micro \
  status
```
Report which scanners are available and any diagnostics.

### 6. Report outcome

Print a summary of findings and the path to the full JSON report:
- `<RESOLVED_TARGET>/ez-appsec-results.json`
