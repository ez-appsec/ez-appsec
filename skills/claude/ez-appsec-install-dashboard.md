Create an `ez-appsec-dashboard` GitLab project inside the group given by `$ARGUMENTS`, populate it with the ez-appsec web dashboard app, and configure GitLab Pages to host it.

The dashboard provides an aggregated group-level security view plus per-project drill-down, navigable via a left-sidebar folder tree.

## Input

`$ARGUMENTS` must be a GitLab group path (e.g. `my-org` or `my-org/security`).
If `$ARGUMENTS` is empty, stop and ask the user for the group path.

Store it as `GROUP_PATH`.

The dashboard project will be created at `GROUP_PATH/ez-appsec-dashboard`.

---

## Steps

### 1. Locate the web app source

Pull the dashboard files from the ez-appsec GitHub release:
```bash
EZ_APPSEC_WEB_URL="https://raw.githubusercontent.com/jfelten/ez-appsec/main/web"
```

Alternatively, if the user is running this from inside a local ez-appsec checkout, prefer the local `web/` directory:
```bash
LOCAL_WEB=$(git rev-parse --show-toplevel 2>/dev/null)/web
[ -f "${LOCAL_WEB}/index.html" ] && WEB_SOURCE="local:${LOCAL_WEB}" || WEB_SOURCE="remote:${EZ_APPSEC_WEB_URL}"
```

---

### 2. Check if the project already exists

```bash
ENCODED_PATH=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "${GROUP_PATH}/ez-appsec-dashboard")
EXISTING=$(glab api "projects/${ENCODED_PATH}" --silent 2>/dev/null && echo "exists" || echo "not_found")
```

If `EXISTING` is `"exists"`:
- Print: `Project ${GROUP_PATH}/ez-appsec-dashboard already exists — skipping creation.`
- Read `DASHBOARD_ID` and `DASHBOARD_URL` from the API response.

If `"not_found"`:
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

### 3. Clone into a temp directory

```bash
TMPDIR=$(mktemp -d)
git clone "${DASHBOARD_URL}" "${TMPDIR}/ez-appsec-dashboard"
cd "${TMPDIR}/ez-appsec-dashboard"
git checkout -B main
```

---

### 4. Populate `public/` with the web app

If `WEB_SOURCE` starts with `local:`:
```bash
cp -r "${LOCAL_WEB}/." public/
```

If `WEB_SOURCE` starts with `remote:`:
```bash
mkdir -p public/data
for FILE in index.html style.css app.js; do
  curl -fsSL "${EZ_APPSEC_WEB_URL}/${FILE}" -o "public/${FILE}"
done
printf '{\n  "last_updated": null,\n  "projects": []\n}\n' > public/data/index.json
```

Ensure `public/data/index.json` is present (do not overwrite if already populated):
```bash
[ -f public/data/index.json ] || \
  printf '{\n  "last_updated": null,\n  "projects": []\n}\n' > public/data/index.json
```

---

### 5. Write `.gitlab-ci.yml`

```yaml
# ez-appsec group security dashboard
# Managed by ez-appsec. Consuming projects push scan data via update:vulns in scan.yml.

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
git push origin main || git push --force-with-lease origin main
```

---

### 7. Set group-level CI variable

So consuming projects can discover the dashboard automatically:
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
echo "Could not set group variable — set EZ_APPSEC_DASHBOARD_PROJECT manually in group Settings > CI/CD > Variables."
```

---

### 8. Trigger the initial Pages pipeline

```bash
glab api --method POST "projects/${DASHBOARD_ID}/pipeline" --field ref=main 2>/dev/null || \
echo "Could not trigger pipeline — run it manually from the project's CI/CD > Pipelines page."
```

---

### 9. Derive and report the Pages URL

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

### 10. Clean up

```bash
rm -rf "${TMPDIR}"
```

---

### 11. Report outcome

```
✓ Dashboard project:   <GitLab project URL>
✓ Pages URL:           <PAGES_URL>  (live after first pipeline completes)
✓ Group variable:      EZ_APPSEC_DASHBOARD_PROJECT = <GROUP_PATH>/ez-appsec-dashboard

Next steps:
  1. Wait for the pipeline at <GitLab project URL>/-/pipelines, then visit <PAGES_URL>
  2. Run /ez-appsec-install in each project you want to include in the dashboard
  3. Each scan will automatically push findings to this dashboard via the
     EZ_APPSEC_DASHBOARD_PROJECT group variable
```
