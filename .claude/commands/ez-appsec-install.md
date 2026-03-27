Install ez-appsec into a GitLab project by adding the `scan.yml` include to `.gitlab-ci.yml`, pushing a dedicated branch, and opening a merge request.

## Steps

### 1. Resolve the target project

If the user provided a path in `$ARGUMENTS`, use it as the target project root.
Otherwise use the current working directory.

Confirm `.gitlab-ci.yml` exists there:
```bash
ls "<TARGET>/.gitlab-ci.yml"
```
If it does not exist, create a minimal one:
```yaml
stages: []
```

### 2. Read the EZ_APPSEC_BRANCH variable

Open `<TARGET>/.gitlab-ci.yml` and look for a `variables.EZ_APPSEC_BRANCH` key.
If found, use that value as the branch name.
If not found, default to `ez-appsec-pages`.

Store the result as `BRANCH`.

### 3. Determine the ez-appsec `scan.yml` reference

Detect whether ez-appsec is available as a GitLab project in the same instance:
```bash
glab repo view jfelten/ez-appsec 2>/dev/null
```

- **If `glab` succeeds**: use a GitLab project include:
  ```yaml
  include:
    - project: 'jfelten/ez-appsec'
      ref: main
      file: 'scan.yml'
  ```
- **Otherwise**: use a remote (raw HTTP) include:
  ```yaml
  include:
    - remote: 'https://raw.githubusercontent.com/jfelten/ez-appsec/main/scan.yml'
  ```

### 4. Create the branch

Inside the target project directory:
```bash
cd "<TARGET>"
git fetch origin
git checkout -B "$BRANCH" "origin/$BRANCH" 2>/dev/null || git checkout -B "$BRANCH"
```

### 5. Patch `.gitlab-ci.yml`

Read `.gitlab-ci.yml`.

**If an `include:` block already exists**, append the ez-appsec entry to it.
**If no `include:` block exists**, prepend the block at the top of the file (after any leading comments) so it is the first top-level key.

Ensure the final file does **not** duplicate an existing ez-appsec include (check for `scan.yml` already present).

**Stages — always add an explicit `stages:` block to the project file** that merges:
- The stages already present in the project's `stages:` list (if any)
- The ez-appsec stages: `initialize`, `scan`, `deploy`
- The standard GitLab template stages so built-in templates (Dependency-Scanning, SAST, etc.) continue to work: `build`, `test`
- GitLab's implicit bookend stages: `.pre`, `.post`

The merged list must preserve the standard GitLab ordering. Use this as the canonical order, including only stages relevant to the project:

```yaml
stages:
  - .pre
  - ez-appsec
  - build
  - test
  - deploy
  - .post
```

If the project already has a `stages:` key, replace it with the merged list above (retaining any project-specific stages in their natural position). This prevents `chosen stage X does not exist` errors when any included template references a stage not declared in the project.

### 6. Set EZ_APPSEC_VERSION CI variable in the target project

Fetch the latest released version of ez-appsec:
```bash
LATEST_VERSION=$(glab api "projects/jfelten.work-group%2Fez_appsec%2Fez_appsec/releases/permalink/latest" \
  --field tag_name 2>/dev/null | tr -d '"v' || echo "")
```

If `LATEST_VERSION` is empty or `glab` is unavailable, fall back to `"latest"`.

Set it as a CI/CD variable on the target project (masked, not protected, so it applies to all branches):
```bash
TARGET_PROJECT_ID=$(glab api "projects/$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=""))' "<TARGET_PROJECT_PATH>")" --field id)

glab api --method POST "projects/${TARGET_PROJECT_ID}/variables" \
  --field key=EZ_APPSEC_VERSION \
  --field value="${LATEST_VERSION}" \
  --field masked=false \
  --field protected=false \
  --field variable_type=env_var 2>/dev/null || \
glab api --method PUT "projects/${TARGET_PROJECT_ID}/variables/EZ_APPSEC_VERSION" \
  --field value="${LATEST_VERSION}" \
  --field masked=false \
  --field protected=false 2>/dev/null || \
echo "Could not set EZ_APPSEC_VERSION automatically — set it manually in Settings > CI/CD > Variables to the desired ez-appsec image tag (e.g. ${LATEST_VERSION:-latest})"
```

The target project path can be read from `glab repo view --format='{{.FullName}}'` inside the target directory.

### 7. Commit and push

```bash
cd "<TARGET>"
git add .gitlab-ci.yml
git commit -m "chore: install ez-appsec security scanning via scan.yml include"
git push origin "$BRANCH"
```

If the push fails because the remote branch already exists and is diverged, rebase:
```bash
git pull --rebase origin "$BRANCH"
git push origin "$BRANCH"
```

### 8. Create the merge request

Try with `glab` first:
```bash
glab mr create \
  --title "chore: install ez-appsec security scanning" \
  --description "$(cat <<'EOF'
## Summary

Adds the [ez-appsec](https://github.com/jfelten/ez-appsec) security scanning pipeline via a `scan.yml` include.

**What this enables:**
- Secret detection (gitleaks)
- Static analysis / SAST (semgrep)
- Dependency CVE scanning (grype)
- Infrastructure-as-code misconfiguration detection (kics)

**Pipeline behaviour:**
- Scans run automatically on merge requests and pushes to `main`.
- Results are published to GitLab Pages on the `$EZ_APPSEC_BRANCH` branch.
- Vulnerability JSON artifacts are retained for 7 days.

No API key or external service required.
EOF
)" \
  --source-branch "$BRANCH" \
  --target-branch main \
  --remove-source-branch
```

If `glab` is not installed or fails, print instructions for the user:
```
To create the merge request manually, visit:
  <GitLab project URL>/-/merge_requests/new?merge_request[source_branch]=<BRANCH>
```

### 9. Report outcome

Print a summary:
- Branch pushed: `<BRANCH>`
- MR URL (if created)
- `EZ_APPSEC_VERSION` set to: `<version>` (or note if it could not be set automatically)
- Remind the user that the **Rescan button** links to the GitLab pipelines page — no token or secret is required
- Remind the user that `EZ_APPSEC_BRANCH` and `EZ_APPSEC_VERSION` can be overridden in Settings > CI/CD > Variables
