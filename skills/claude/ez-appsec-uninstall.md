Remove ez-appsec from a GitLab project — strips the `scan.yml` include from `.gitlab-ci.yml`,
deletes CI variables, prunes dashboard data, and opens a merge request.

## Usage

```
/ez-appsec uninstall [path]
```

---

## Steps

### 1. Resolve and validate the target project

If the user provided a path in `$ARGUMENTS`, use it as the target project root.
Otherwise use the current working directory.

**Validation — stop with the appropriate message if any check fails:**

```bash
TARGET=$(realpath "${ARGUMENTS:-$(pwd)}")

# Directory must exist
if [ ! -d "$TARGET" ]; then
  echo "Error: directory '$TARGET' not found."
  exit 1
fi

# Must be a git repository
if ! git -C "$TARGET" rev-parse --git-dir 2>/dev/null; then
  echo "Error: '$TARGET' is not a git repository."
  exit 1
fi

# Must have a GitLab remote
if ! git -C "$TARGET" remote -v | grep -q "gitlab"; then
  echo "Error: no GitLab remote found in '$TARGET'."
  echo "This command is for GitLab projects. For GitHub repos, use:"
  echo "  /ez-appsec uninstall-app owner/repo"
  exit 1
fi

# glab CLI must be available and authenticated
if ! glab auth status 2>/dev/null; then
  echo "Error: glab CLI is not authenticated."
  echo "Run: glab auth login"
  exit 1
fi

# .gitlab-ci.yml must exist
if [ ! -f "$TARGET/.gitlab-ci.yml" ]; then
  echo "ez-appsec is not installed on this project — no .gitlab-ci.yml found."
  exit 0
fi
```

### 2. Detect current state (silent — no output yet)

```bash
# Derive project path from git remote
PROJECT_PATH=$(git -C "$TARGET" remote get-url origin \
  | sed -E 's|.*gitlab[^/]*/||; s|\.git$||')
PROJECT_ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$PROJECT_PATH")
TARGET_PROJECT_ID=$(glab api "projects/${PROJECT_ENCODED}" 2>/dev/null \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")

# Is the ez-appsec include present?
HAS_INCLUDE=$(grep -c "gitlab/scan.yml\|ez-appsec.*scan" "$TARGET/.gitlab-ci.yml" 2>/dev/null || echo 0)

# Is EZ_APPSEC_VERSION set at project level?
HAS_VERSION_VAR=0
if [ -n "$TARGET_PROJECT_ID" ]; then
  glab api "projects/${TARGET_PROJECT_ID}/variables/EZ_APPSEC_VERSION" 2>/dev/null | \
    grep -q "value" && HAS_VERSION_VAR=1 || true
fi

# What is the dashboard project?
TARGET_NAMESPACE=$(glab api "projects/${PROJECT_ENCODED}" 2>/dev/null \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['namespace']['full_path'])" 2>/dev/null || echo "")
GROUP_ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$TARGET_NAMESPACE" 2>/dev/null || echo "")
DASH_PROJECT=$(glab api "groups/${GROUP_ENCODED}/variables/EZ_APPSEC_DASHBOARD_PROJECT" 2>/dev/null \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('value',''))" 2>/dev/null || \
  glab api "projects/${TARGET_PROJECT_ID}/variables/EZ_APPSEC_DASHBOARD_PROJECT" 2>/dev/null \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('value',''))" 2>/dev/null || echo "")

# Does dashboard data exist for this project?
PROJECT_NAME=$(basename "$PROJECT_PATH")
DASH_DATA_PATH=""
if [ -n "$DASH_PROJECT" ]; then
  DASH_ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$DASH_PROJECT")
  for CANDIDATE in \
    "public/data/vulnerabilities/${PROJECT_NAME}.json" \
    "public/data/${PROJECT_NAME}.json"; do
    if glab api "projects/${DASH_ENCODED}/repository/files/$(python3 -c \
      "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$CANDIDATE")?ref=main" \
      2>/dev/null | grep -q "file_name"; then
      DASH_DATA_PATH="$CANDIDATE"
      break
    fi
  done
fi
```

### 3. Present plan and ask permission — ONCE

Do not output anything before this step.

**If nothing is installed** (`HAS_INCLUDE` is 0, no variables, no dashboard data):
```
ez-appsec does not appear to be installed on this project.
Nothing to remove.
```
Stop — do not ask permission.

**Otherwise**, list exactly what will be removed:

```
ez-appsec is installed on <PROJECT_PATH>.

This will:
  1. Remove the ez-appsec include from .gitlab-ci.yml     [file change → MR]
  2. Remove the ez-appsec stage from stages:              [file change → MR]
  3. Delete CI variable: EZ_APPSEC_VERSION               [if present]
  4. Remove dashboard data: <DASH_DATA_PATH>              [if found]

Note: EZ_APPSEC_DASHBOARD_PROJECT is a group-level variable shared by all projects
      in the group — it will NOT be removed.

Proceed with uninstall?
```

Only show items that are actually present. Use AskUserQuestion with yes/no. If no, stop.

### 4. Execute — single script block

Replace all `<...>` placeholders with actual values before running.

```bash
set -euo pipefail
TARGET="<TARGET>"
PROJECT_PATH="<PROJECT_PATH>"
PROJECT_ENCODED="<PROJECT_ENCODED>"
TARGET_PROJECT_ID="<TARGET_PROJECT_ID>"
TARGET_NAMESPACE="<TARGET_NAMESPACE>"
GROUP_ENCODED="<GROUP_ENCODED>"
DASH_PROJECT="<DASH_PROJECT>"
DASH_DATA_PATH="<DASH_DATA_PATH>"
HAS_VERSION_VAR=<HAS_VERSION_VAR>
ERRORS=0

UNINSTALL_BRANCH="ez-appsec-uninstall"

# ── 1. Create branch ──────────────────────────────────────────────────────────
echo "Creating branch ${UNINSTALL_BRANCH}..."
cd "$TARGET"
git fetch origin
git checkout -B "$UNINSTALL_BRANCH" "origin/${UNINSTALL_BRANCH}" 2>/dev/null \
  || git checkout -B "$UNINSTALL_BRANCH"
echo "  ✓ Branch ${UNINSTALL_BRANCH} ready"

# ── 2. Patch .gitlab-ci.yml ───────────────────────────────────────────────────
echo "Updating .gitlab-ci.yml..."
python3 - "$TARGET/.gitlab-ci.yml" <<'PYEOF'
import sys, re

path = sys.argv[1]
with open(path) as f:
    content = f.read()

original = content

# Remove the ez-appsec include entry.
# Handles both project-style and remote-style includes, with any indentation.
# Removes the entire multi-line include entry (project/ref/file or remote).
content = re.sub(
    r'\n?[ \t]*-[ \t]+(project:[ \t]*[\'"]?[^\n]*ez-appsec[^\n]*[\'"]?\n'
    r'(?:[ \t]+\S[^\n]*\n)*'
    r'|remote:[ \t]*[^\n]*(?:ez-appsec|gitlab/scan\.yml)[^\n]*\n?)',
    '',
    content,
)

# If the include: block is now empty (only whitespace after the key), remove it.
content = re.sub(r'\ninclude:[ \t]*\n(?=\S|\Z)', '\n', content)

# Remove 'ez-appsec' from the stages list.
content = re.sub(r'[ \t]*-[ \t]*ez-appsec\n', '', content)

# Clean up consecutive blank lines left behind.
content = re.sub(r'\n{3,}', '\n\n', content)

if content == original:
    print("  ⚠ No ez-appsec include found in .gitlab-ci.yml — file unchanged")
else:
    with open(path, 'w') as f:
        f.write(content)
    print("  ✓ ez-appsec include and stage removed from .gitlab-ci.yml")
PYEOF

# ── 3. Commit and push ────────────────────────────────────────────────────────
echo "Committing changes..."
git add .gitlab-ci.yml
if git diff --staged --quiet; then
  echo "  ⚠ No changes to commit — .gitlab-ci.yml was already clean"
else
  git commit -m "chore: remove ez-appsec security scanning"
  if ! git push origin "$UNINSTALL_BRANCH" 2>/tmp/ez_err; then
    # Retry with rebase on diverged history
    git pull --rebase origin "$UNINSTALL_BRANCH" 2>/dev/null && \
      git push origin "$UNINSTALL_BRANCH" || {
      echo "  ✗ Push failed: $(cat /tmp/ez_err)"
      echo "    Resolve conflicts and push manually, then open an MR from ${UNINSTALL_BRANCH} to main."
      ERRORS=$((ERRORS + 1))
    }
  fi
  echo "  ✓ Changes pushed to ${UNINSTALL_BRANCH}"
fi

# ── 4. Delete CI variable EZ_APPSEC_VERSION ──────────────────────────────────
if [ "$HAS_VERSION_VAR" -eq 1 ]; then
  echo "Removing CI variables..."
  if glab api --method DELETE \
    "projects/${TARGET_PROJECT_ID}/variables/EZ_APPSEC_VERSION" 2>/tmp/ez_err; then
    echo "  ✓ CI variable EZ_APPSEC_VERSION removed"
  else
    echo "  ✗ Could not remove EZ_APPSEC_VERSION: $(cat /tmp/ez_err)"
    echo "    Remove manually: Settings > CI/CD > Variables"
    ERRORS=$((ERRORS + 1))
  fi
fi

# ── 5. Remove dashboard data ──────────────────────────────────────────────────
if [ -n "$DASH_DATA_PATH" ] && [ -n "$DASH_PROJECT" ]; then
  echo "Removing dashboard data..."
  DASH_ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$DASH_PROJECT")
  FILE_ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$DASH_DATA_PATH")
  DASH_CLONE_URL=$(glab api "projects/${DASH_ENCODED}" 2>/dev/null \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['http_url_to_repo'])" 2>/dev/null || echo "")

  if [ -n "$DASH_CLONE_URL" ]; then
    TMPDIR=$(mktemp -d)
    if git clone "$DASH_CLONE_URL" "${TMPDIR}/dash" 2>/tmp/ez_err; then
      cd "${TMPDIR}/dash"
      if [ -f "$DASH_DATA_PATH" ]; then
        git rm "$DASH_DATA_PATH"

        # Regenerate index.json
        curl -sSfL \
          "https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/scripts/aggregate-index.py" \
          -o /tmp/aggregate-index.py 2>/dev/null && \
          python3 /tmp/aggregate-index.py "$(dirname $(dirname "$DASH_DATA_PATH"))" 2>/dev/null && \
          git add public/data/index.json 2>/dev/null || true

        git config user.name "ez-appsec uninstall"
        git config user.email "ci@ez-appsec.ai"
        git commit -m "chore: remove scan data for ${PROJECT_PATH}"
        git push origin main && \
          echo "  ✓ Dashboard data removed and index regenerated" || {
          echo "  ✗ Could not push dashboard changes."
          echo "    Remove manually: ${DASH_PROJECT}/-/blob/main/${DASH_DATA_PATH}"
          ERRORS=$((ERRORS + 1))
        }
      else
        echo "  ⚠ Dashboard data file not found in clone — may have already been removed"
      fi
      cd "$TARGET"
      rm -rf "$TMPDIR"
    else
      echo "  ✗ Could not clone dashboard repo: $(cat /tmp/ez_err)"
      echo "    Remove manually: ${DASH_PROJECT}/-/blob/main/${DASH_DATA_PATH}"
      ERRORS=$((ERRORS + 1))
    fi
  else
    echo "  ✗ Could not resolve dashboard repo URL."
    echo "    Remove manually from: ${DASH_PROJECT}"
    ERRORS=$((ERRORS + 1))
  fi
fi

# ── 6. Open MR ────────────────────────────────────────────────────────────────
echo "Opening merge request..."
MR_URL=""
if MR_URL=$(glab mr create \
  --title "chore: remove ez-appsec security scanning" \
  --description "$(cat <<'EOF'
## Summary

Removes the [ez-appsec](https://github.com/ez-appsec/ez-appsec) security scanning pipeline.

**What this removes:**
- `scan.yml` include from `.gitlab-ci.yml`
- `ez-appsec` stage from the pipeline stages

**What to do after merging:**
- Pipelines will stop running ez-appsec scans
- Historical scan artifacts remain until their retention period expires
- To reinstall: `/ez-appsec install`
EOF
)" \
  --source-branch "$UNINSTALL_BRANCH" \
  --target-branch main \
  --remove-source-branch \
  2>/tmp/ez_err); then
  echo "  ✓ MR created: ${MR_URL}"
else
  echo "  ✗ Could not create MR: $(cat /tmp/ez_err)"
  GL_URL=$(git remote get-url origin | sed 's/\.git$//')
  echo "    Create manually: ${GL_URL}/-/merge_requests/new?merge_request[source_branch]=${UNINSTALL_BRANCH}"
  ERRORS=$((ERRORS + 1))
fi

# ── 7. Summary ────────────────────────────────────────────────────────────────
echo ""
if [ $ERRORS -eq 0 ]; then
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "✓ ez-appsec removed from ${PROJECT_PATH}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "⚠ Uninstall completed with ${ERRORS} error(s) — see above"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fi
echo ""
[ -n "$MR_URL" ] && echo "  MR       ${MR_URL}"
echo "  Project  $(git remote get-url origin | sed 's/\.git$//')"
[ -n "$DASH_PROJECT" ] && \
  echo "  Note     EZ_APPSEC_DASHBOARD_PROJECT is a group variable — it was left in place for other projects"
echo ""
echo "Merge the MR to complete the uninstall. Scans will stop once the MR is merged."
```
