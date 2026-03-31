Create an `ez-appsec-dashboard` GitLab project inside the group given by `$ARGUMENTS`, populate it with the web dashboard app, and configure GitLab Pages to host it.

## Input

`$ARGUMENTS` must be a GitLab group path (e.g. `my-org` or `my-org/security`).
If `$ARGUMENTS` is empty, stop and ask the user for the group path.

Store it as `GROUP_PATH`.

The dashboard project will be created at `GROUP_PATH/ez-appsec-dashboard`.

---

## Steps

### 1. Resolve the ez-appsec source directory

Locate the `web/` directory that ships with ez-appsec:
```bash
EZ_APPSEC_SRC=$(git -C "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" rev-parse --show-toplevel 2>/dev/null || echo ".")
WEB_DIR="${EZ_APPSEC_SRC}/web"
```

Confirm `web/index.html` exists:
```bash
ls "${WEB_DIR}/index.html"
```

If it does not exist, stop and tell the user the web directory was not found.

---

### 2. Check if the project already exists

```bash
ENCODED_PATH=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "${GROUP_PATH}/ez-appsec-dashboard")
EXISTING=$(glab api "projects/${ENCODED_PATH}" --silent 2>/dev/null && echo "exists" || echo "not_found")
```

If `EXISTING` is `"exists"`:
- Print: `Project ${GROUP_PATH}/ez-appsec-dashboard already exists — skipping creation.`
- Store the project ID:
  ```bash
  DASHBOARD_ID=$(glab api "projects/${ENCODED_PATH}" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
  DASHBOARD_URL=$(glab api "projects/${ENCODED_PATH}" | python3 -c "import json,sys; print(json.load(sys.stdin)['http_url_to_repo'])")
  ```

If `EXISTING` is `"not_found"`:
- Resolve the group ID:
  ```bash
  GROUP_ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "${GROUP_PATH}")
  GROUP_ID=$(glab api "groups/${GROUP_ENCODED}" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
  ```
- Create the project:
  ```bash
  RESPONSE=$(glab api --method POST "groups/${GROUP_ID}/projects" \
    --field name="ez-appsec-dashboard" \
    --field description="ez-appsec group security dashboard" \
    --field visibility="private" \
    --field initialize_with_readme=false \
    --field pages_access_level="enabled")
  DASHBOARD_ID=$(echo "$RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
  DASHBOARD_URL=$(echo "$RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin)['http_url_to_repo'])")
  ```

---

### 3. Clone the new project into a temp directory

```bash
TMPDIR=$(mktemp -d)
git clone "${DASHBOARD_URL}" "${TMPDIR}/ez-appsec-dashboard"
cd "${TMPDIR}/ez-appsec-dashboard"
git checkout -B main
```

---

### 4. Populate with the web app

Copy the `web/` contents to `public/` (GitLab Pages serves from `public/`):
```bash
mkdir -p public
cp -r "${WEB_DIR}/." public/
```

Ensure `public/data/index.json` exists with an empty projects list (do not overwrite if it already has data):
```bash
if [ ! -f public/data/index.json ]; then
  mkdir -p public/data
  printf '{\n  "last_updated": null,\n  "projects": []\n}\n' > public/data/index.json
fi
```

---

### 5. Create `.gitlab-ci.yml`

Write the following file to `${TMPDIR}/ez-appsec-dashboard/.gitlab-ci.yml`:

```yaml
# ez-appsec group security dashboard
# This project is managed by ez-appsec. Do not edit manually.
# Consuming projects push scan data here via update:vulns in scan.yml.

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

---

### 6. Commit and push

```bash
cd "${TMPDIR}/ez-appsec-dashboard"
git config user.email "ez-appsec-install@ez-appsec.ai"
git config user.name "ez-appsec installer"
git add .
git commit -m "feat: initialize ez-appsec group security dashboard"
git push origin main
```

If the push is rejected (branch already exists upstream with different history), force-push:
```bash
git push --force-with-lease origin main
```

---

### 7. Store the dashboard project path as a CI/CD variable in the group

This allows consuming projects to discover the dashboard automatically via `$EZ_APPSEC_DASHBOARD_PROJECT`.

```bash
glab api --method POST "groups/${GROUP_ID}/variables" \
  --field key="EZ_APPSEC_DASHBOARD_PROJECT" \
  --field value="${GROUP_PATH}/ez-appsec-dashboard" \
  --field masked=false \
  --field protected=false \
  --field variable_type=env_var 2>/dev/null || \
glab api --method PUT "groups/${GROUP_ID}/variables/EZ_APPSEC_DASHBOARD_PROJECT" \
  --field value="${GROUP_PATH}/ez-appsec-dashboard" \
  --field masked=false \
  --field protected=false 2>/dev/null || \
echo "Could not set group variable automatically — set EZ_APPSEC_DASHBOARD_PROJECT manually in the group's Settings > CI/CD > Variables."
```

---

### 8. Enable GitLab Pages (if not already enabled via project creation)

```bash
glab api --method PUT "projects/${DASHBOARD_ID}" \
  --field pages_access_level="enabled" 2>/dev/null || true
```

---

### 9. Trigger the initial Pages deploy

```bash
glab api --method POST "projects/${DASHBOARD_ID}/pipeline" \
  --field ref=main 2>/dev/null && echo "Pages pipeline triggered." || \
echo "Could not trigger pipeline automatically — push a commit or run the pipeline manually."
```

---

### 10. Derive the Pages URL

GitLab Pages URL format: `https://<group>.gitlab.io/ez-appsec-dashboard`

For nested groups (e.g. `org/security`), the top-level group is used: `https://org.gitlab.io/security/ez-appsec-dashboard`

Print the expected URL:
```bash
TOP_GROUP=$(echo "${GROUP_PATH}" | cut -d'/' -f1)
REST_PATH=$(echo "${GROUP_PATH}" | cut -d'/' -f2-)
if [ "${TOP_GROUP}" = "${GROUP_PATH}" ]; then
  PAGES_URL="https://${TOP_GROUP}.gitlab.io/ez-appsec-dashboard"
else
  PAGES_URL="https://${TOP_GROUP}.gitlab.io/${REST_PATH}/ez-appsec-dashboard"
fi
```

---

### 11. Clean up temp directory

```bash
rm -rf "${TMPDIR}"
```

---

### 12. Report outcome

Print a summary:

```
✓ Dashboard project created:  <GitLab project URL>
✓ Pages URL (available after first pipeline):  <PAGES_URL>
✓ Group variable set:  EZ_APPSEC_DASHBOARD_PROJECT = <GROUP_PATH>/ez-appsec-dashboard

Next steps:
  1. Wait for the pipeline to complete, then visit <PAGES_URL>
  2. Run /ez-appsec-install in each project you want to scan
  3. Ensure each project's scan.yml sets EZ_APPSEC_DASHBOARD_PROJECT
     (it will be picked up automatically from the group variable)
```

If `glab` is unavailable at any step, print the equivalent API call the user can run manually.
