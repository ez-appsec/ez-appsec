Trigger the `scan:pipeline` job in a GitLab project's CI pipeline and report the findings.

## Steps

### 1. Resolve the target project

If the user provided a path in `$ARGUMENTS`, use it as the target project root.
Otherwise use the current working directory.

Confirm it is a GitLab-backed git repo:
```bash
cd "<TARGET>"
git remote get-url origin
```
Extract the project path (e.g. `mygroup/myproject`) from the remote URL.

### 2. Resolve the default branch and latest commit

```bash
git remote show origin | grep "HEAD branch"
git rev-parse HEAD
```

### 3. Trigger the pipeline via `glab`

Try `glab` first:
```bash
glab ci run --branch "$(git rev-parse --abbrev-ref HEAD)" "<TARGET>"
```

If `glab` is not available, trigger via the GitLab API using `CI_JOB_TOKEN` or a token in the environment:
```bash
curl --request POST \
  --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
  --form "ref=$(git rev-parse --abbrev-ref HEAD)" \
  "https://gitlab.com/api/v4/projects/<URL_ENCODED_PROJECT_PATH>/pipeline"
```
URL-encode the project path (replace `/` with `%2F`).

### 4. Wait for the `scan:pipeline` job to complete

Poll the pipeline status every 15 seconds until it finishes (passed, failed, or canceled):
```bash
glab ci status
```
Or with the API:
```bash
curl -s --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
  "https://gitlab.com/api/v4/projects/<PROJECT_ID>/pipelines/<PIPELINE_ID>/jobs" \
  | python3 -c "import sys,json; [print(j['name'], j['status']) for j in json.load(sys.stdin)]"
```

Report progress to the user as you wait.

### 5. Fetch the scan artifact

Once `scan:pipeline` succeeds, download the vulnerability report artifact:
```bash
glab ci artifact scan:pipeline scan-results/vulnerabilities.json
```

Or via API:
```bash
curl -s --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
  --output vulnerabilities.json \
  "https://gitlab.com/api/v4/projects/<PROJECT_ID>/jobs/<JOB_ID>/artifacts/scan-results/vulnerabilities.json"
```

### 6. Parse and report findings

Read `vulnerabilities.json` and summarize:
- Total vulnerabilities found
- Breakdown by severity: critical / high / medium / low / info
- Top findings (up to 10): scanner, severity, title, file, line number
- Which scanners produced results: gitleaks, semgrep, grype, kics

### 7. Handle failures

If `scan:pipeline` failed (not findings — job error):
- Show the last 50 lines of the job log:
  ```bash
  glab ci trace scan:pipeline
  ```
- Suggest checking that `EZ_APPSEC_IMAGE` is reachable from the runner and that the project includes `scan.yml`.

### 8. Report outcome

Print a summary including:
- Pipeline URL
- Job status
- Finding counts by severity
- Any actionable remediation notes for critical/high findings
