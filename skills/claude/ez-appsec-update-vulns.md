Trigger the `update:vulns` job in a GitLab project's CI pipeline to publish the latest vulnerability report to the ez-appsec Pages branch.

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

### 2. Check for a recent scan artifact

The `update:vulns` job depends on `scan:pipeline` output. Check whether a recent
`scan-results/vulnerabilities.json` artifact exists on the current branch:
```bash
glab ci artifact scan:pipeline scan-results/vulnerabilities.json 2>/dev/null
```

If no artifact is found, inform the user and offer to run `/ez-appsec-pipeline-scan` first to produce one.

### 3. Trigger the pipeline

Try `glab` first:
```bash
glab ci run --branch "$(git rev-parse --abbrev-ref HEAD)"
```

If `glab` is not available, trigger via the GitLab API:
```bash
curl --request POST \
  --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
  --form "ref=$(git rev-parse --abbrev-ref HEAD)" \
  "https://gitlab.com/api/v4/projects/<URL_ENCODED_PROJECT_PATH>/pipeline"
```
URL-encode the project path (replace `/` with `%2F`).

### 4. Wait for `update:vulns` to complete

Poll every 15 seconds until the job status is passed, failed, or canceled:
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

### 5. Handle failures

If `update:vulns` failed:
- Show the last 50 lines of the job log:
  ```bash
  glab ci trace update:vulns
  ```
- Common causes:
  - `scan:pipeline` artifact expired or missing — run `/ez-appsec-pipeline-scan` first
  - The `EZ_APPSEC_BRANCH` branch does not exist yet — run `/ez-appsec-install` to initialize it
  - Push permission denied — check that `CI_JOB_TOKEN` has write access to the branch

### 6. Report outcome

Print a summary including:
- Pipeline URL
- Job status
- The Pages branch the report was published to (default: `ez-appsec-pages`)
- URL to the published vulnerability dashboard if GitLab Pages is enabled
