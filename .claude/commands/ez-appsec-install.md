Install ez-appsec into a GitLab project by adding the `scan.yml` include to `.gitlab-ci.yml`, setting up the group dashboard project, and opening a merge request.

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

### 2. Determine the ez-appsec `scan.yml` reference

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

### 3. Create the branch

Inside the target project directory:
```bash
cd "<TARGET>"
git fetch origin
INSTALL_BRANCH="ez-appsec-install"
git checkout -B "$INSTALL_BRANCH" "origin/$INSTALL_BRANCH" 2>/dev/null || git checkout -B "$INSTALL_BRANCH"
```

### 4. Patch `.gitlab-ci.yml`

Read `.gitlab-ci.yml`.

**If an `include:` block already exists**, append the ez-appsec entry to it.
**If no `include:` block exists**, prepend the block at the top of the file (after any leading comments).

Ensure the final file does **not** duplicate an existing ez-appsec include (check for `scan.yml` already present).

**Stages — always add an explicit `stages:` block** using the canonical order:

```yaml
stages:
  - .pre
  - ez-appsec
  - build
  - test
  - deploy
  - .post
```

If the project already has a `stages:` key, replace it with the merged list (retaining any project-specific stages in their natural position).

### 5. Set EZ_APPSEC_VERSION CI variable

Fetch the latest released version:
```bash
LATEST_VERSION=$(glab api "projects/jfelten.work-group%2Fez_appsec%2Fez_appsec/releases/permalink/latest" \
  --field tag_name 2>/dev/null | tr -d '"v' || echo "")
```
Fall back to `"latest"` if empty.

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
echo "Could not set EZ_APPSEC_VERSION — set it manually in Settings > CI/CD > Variables"
```

### 6. Set up the group dashboard (EZ_APPSEC_DASHBOARD_PROJECT)

This is required for `update:vulns` to publish scan results.

#### 6a. Detect the target project's namespace

```bash
TARGET_NAMESPACE=$(glab api "projects/${TARGET_PROJECT_ID}" | \
  python3 -c "import json,sys; print(json.load(sys.stdin)['namespace']['full_path'])")
```

#### 6b. Check if EZ_APPSEC_DASHBOARD_PROJECT is already configured

Check the group variable first, then fall back to a project-level variable:
```bash
GROUP_ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "${TARGET_NAMESPACE}")
DASH_PROJECT=$(glab api "groups/${GROUP_ENCODED}/variables/EZ_APPSEC_DASHBOARD_PROJECT" 2>/dev/null | \
  python3 -c "import json,sys; print(json.load(sys.stdin).get('value',''))" 2>/dev/null || \
glab api "projects/${TARGET_PROJECT_ID}/variables/EZ_APPSEC_DASHBOARD_PROJECT" 2>/dev/null | \
  python3 -c "import json,sys; print(json.load(sys.stdin).get('value',''))" 2>/dev/null || \
echo "")
```

#### 6c. If not configured, create the dashboard project

If `DASH_PROJECT` is empty, create the dashboard:

- Resolve the group ID:
  ```bash
  GROUP_ID=$(glab api "groups/${GROUP_ENCODED}" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
  ```

- Check if `ez-appsec-dashboard` already exists in the group:
  ```bash
  ENCODED_DASH=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "${TARGET_NAMESPACE}/ez-appsec-dashboard")
  EXISTING=$(glab api "projects/${ENCODED_DASH}" --silent 2>/dev/null && echo "exists" || echo "not_found")
  ```

- If `not_found`, create it:
  ```bash
  RESPONSE=$(glab api --method POST "groups/${GROUP_ID}/projects" \
    --field name="ez-appsec-dashboard" \
    --field description="ez-appsec group security dashboard" \
    --field visibility="private" \
    --field initialize_with_readme=false \
    --field pages_access_level="enabled")
  DASH_REPO_URL=$(echo "$RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin)['http_url_to_repo'])")
  DASH_PROJECT_ID=$(echo "$RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
  ```

- If `exists`, read the URL and ID:
  ```bash
  DASH_REPO_URL=$(glab api "projects/${ENCODED_DASH}" | python3 -c "import json,sys; print(json.load(sys.stdin)['http_url_to_repo'])")
  DASH_PROJECT_ID=$(glab api "projects/${ENCODED_DASH}" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
  ```

- Populate the dashboard with the web app and configure Pages:
  ```bash
  EZ_APPSEC_SRC=$(git -C "<TARGET>" rev-parse --show-toplevel 2>/dev/null || echo "")
  TMPDIR=$(mktemp -d)
  git clone "${DASH_REPO_URL}" "${TMPDIR}/dash"
  cd "${TMPDIR}/dash"
  git checkout -B main
  mkdir -p public/data
  # Copy web app from local source if available, otherwise fetch from GitHub
  if [ -n "${EZ_APPSEC_SRC}" ] && [ -f "${EZ_APPSEC_SRC}/web/index.html" ]; then
    cp -r "${EZ_APPSEC_SRC}/web/." public/
  else
    for FILE in index.html style.css app.js; do
      curl -fsSL "https://raw.githubusercontent.com/jfelten/ez-appsec/main/web/${FILE}" -o "public/${FILE}"
    done
  fi
  [ -f public/data/index.json ] || \
    printf '{\n  "last_updated": null,\n  "projects": []\n}\n' > public/data/index.json
  ```

- Write `.gitlab-ci.yml` for the dashboard project:
  ```yaml
  # ez-appsec group security dashboard — managed by ez-appsec
  pages:
    stage: deploy
    script:
      - echo "Publishing ez-appsec dashboard to GitLab Pages"
    artifacts:
      paths:
        - public
    rules:
      - if: '$CI_COMMIT_BRANCH == "main"'
        when: always
  ```

- Commit, push, and trigger the first pipeline:
  ```bash
  git config user.email "ez-appsec-install@ez-appsec.ai"
  git config user.name "ez-appsec installer"
  git add .
  git commit -m "feat: initialize ez-appsec group security dashboard"
  git push origin main || git push --force-with-lease origin main
  rm -rf "${TMPDIR}"
  ```

- Set `DASH_PROJECT` to the new path:
  ```bash
  DASH_PROJECT="${TARGET_NAMESPACE}/ez-appsec-dashboard"
  ```

#### 6d. Set EZ_APPSEC_DASHBOARD_PROJECT as a group variable

```bash
glab api --method POST "groups/${GROUP_ID}/variables" \
  --field key="EZ_APPSEC_DASHBOARD_PROJECT" \
  --field value="${DASH_PROJECT}" \
  --field masked=false \
  --field protected=false \
  --field variable_type=env_var 2>/dev/null || \
glab api --method PUT "groups/${GROUP_ID}/variables/EZ_APPSEC_DASHBOARD_PROJECT" \
  --field value="${DASH_PROJECT}" \
  --field masked=false \
  --field protected=false 2>/dev/null || \
echo "Could not set group variable — set EZ_APPSEC_DASHBOARD_PROJECT manually in the group's Settings > CI/CD > Variables."
```

### 7. Commit and push the target project changes

```bash
cd "<TARGET>"
git add .gitlab-ci.yml
git commit -m "chore: install ez-appsec security scanning via scan.yml include"
git push origin "$INSTALL_BRANCH"
```

If the push is rejected due to diverged history, rebase:
```bash
git pull --rebase origin "$INSTALL_BRANCH"
git push origin "$INSTALL_BRANCH"
```

### 8. Create the merge request

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
- Results are published to the group dashboard at `$EZ_APPSEC_DASHBOARD_PROJECT`.
- Vulnerability JSON artifacts are retained for 7 days.

No API key or external service required.
EOF
)" \
  --source-branch "$INSTALL_BRANCH" \
  --target-branch main \
  --remove-source-branch
```

If `glab` is not installed or fails, print:
```
To create the merge request manually, visit:
  <GitLab project URL>/-/merge_requests/new?merge_request[source_branch]=<INSTALL_BRANCH>
```

### 9. Report outcome

Print a summary:
- MR URL (if created)
- `EZ_APPSEC_VERSION` set to: `<version>`
- Dashboard project: `<DASH_PROJECT>`
- Pages URL: `https://<top-group>.gitlab.io/<rest-path>/ez-appsec-dashboard` (live after the dashboard pipeline completes)
- Remind the user that `EZ_APPSEC_DASHBOARD_PROJECT` and `EZ_APPSEC_VERSION` can be overridden in group or project Settings > CI/CD > Variables
