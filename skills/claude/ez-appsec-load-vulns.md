Load a project's vulnerability data from the ez-appsec dashboard into the conversation context so you can analyse, triage, or help remediate findings.

## Usage

```
/ez-appsec load [project]
```

`project` is the repo slug or `owner/repo` path. Omit to auto-detect from the current git remote.

---

## Steps

### 1. Resolve the project slug

```bash
# If $ARGUMENTS is provided, extract the slug from it
# (last path component of owner/repo, or the whole thing if no slash)
# If empty, detect from the current git remote:
REPO_ARG="${ARGUMENTS:-}"
if [ -z "$REPO_ARG" ]; then
  REPO_ARG=$(git remote get-url origin 2>/dev/null \
    | sed 's/.*github\.com[:/]//' \
    | sed 's/.*gitlab\.com[:/]//' \
    | sed 's/\.git$//')
fi
SLUG=$(echo "$REPO_ARG" | awk -F/ '{print $NF}' | tr '[:upper:]' '[:lower:]')
```

If `SLUG` is still empty, stop and ask the user: `Which project? Pass a slug or owner/repo.`

### 2. Fetch index.json from the GitHub dashboard

```bash
DASHBOARD_REPO="${EZ_APPSEC_DASHBOARD_REPO:-ez-appsec/ez-appsec-dashboard}"
INDEX=$(gh api "repos/${DASHBOARD_REPO}/contents/data/index.json" \
  --jq '.content' 2>/dev/null | base64 --decode 2>/dev/null || echo "")
```

If empty, fall back to a direct path guess (skip index lookup). If the gh CLI is not available or not authenticated, try fetching from the public Pages URL instead:

```bash
OWNER=$(echo "$DASHBOARD_REPO" | cut -d/ -f1)
REPO_NAME=$(echo "$DASHBOARD_REPO" | cut -d/ -f2)
INDEX=$(curl -sf "https://${OWNER}.github.io/${REPO_NAME}/data/index.json" 2>/dev/null || echo "")
```

### 3. Resolve the vuln file path from index.json

```python
import json, sys

index = json.loads(sys.argv[1]) if sys.argv[1] else {"projects": []}
slug = sys.argv[2]

project = next(
    (p for p in index.get("projects", [])
     if p.get("slug") == slug or p.get("slug", "").lower() == slug.lower()),
    None
)

if project and project.get("path"):
    print("data/" + project["path"])
else:
    print(f"data/vulnerabilities/{slug}.json")
```

### 4. Fetch vulnerabilities.json

Try the GitHub Contents API first:

```bash
VULN_PATH="<resolved path from step 3>"
CONTENT=$(gh api "repos/${DASHBOARD_REPO}/contents/${VULN_PATH}" \
  --jq '.content' 2>/dev/null | base64 --decode 2>/dev/null || echo "")
```

If empty, try the Pages URL:

```bash
CONTENT=$(curl -sf "https://${OWNER}.github.io/${REPO_NAME}/${VULN_PATH}" 2>/dev/null || echo "")
```

If still empty, stop with:
```
No vulnerability data found for '<SLUG>' in <DASHBOARD_REPO>.

Checked:
  • repos/<DASHBOARD_REPO>/contents/<VULN_PATH>
  • https://<OWNER>.github.io/<REPO_NAME>/<VULN_PATH>

Run a scan first:
  /ez-appsec install-app <owner>/<SLUG>     # GitHub
  /ez-appsec install /path/to/<SLUG>        # GitLab
```

### 5. Parse and load into context

Run this Python inline, passing `$CONTENT` as stdin:

```python
import json, sys

data = json.load(sys.stdin)
vulns = data.get("vulnerabilities", data) if isinstance(data, dict) else data

# Severity order
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
vulns_sorted = sorted(vulns, key=lambda v: SEV_ORDER.get(v.get("severity", "unknown").lower(), 5))

# Counts by severity
from collections import Counter
counts = Counter(v.get("severity", "unknown").lower() for v in vulns_sorted)

# Metadata
meta = {
    "project_name": data.get("project_name", "") if isinstance(data, dict) else "",
    "scan_date":    data.get("scan_date", "")    if isinstance(data, dict) else "",
    "github_url":   data.get("github_url", "")   if isinstance(data, dict) else "",
    "total":        len(vulns_sorted),
    "counts":       dict(counts),
    "vulnerabilities": vulns_sorted,
}
print(json.dumps(meta, indent=2))
```

### 6. Present a summary, then hold the full data in context

Do NOT print the raw JSON dump. Instead:

**Print this summary:**

```
Project:    <project_name>
Scanned:    <scan_date>
Repository: <github_url>

Findings: <total> total
  Critical  <n>
  High      <n>
  Medium    <n>
  Low       <n>
  Info      <n>

Top findings:
  [CRITICAL] <name> — <file>:<line>  (<scanner>)
  [CRITICAL] <name> — <file>:<line>  (<scanner>)
  [HIGH]     <name> — <file>:<line>  (<scanner>)
  ... (up to 10 findings, critical-first)

Vulnerability data loaded. Ask me anything:
  • "show all critical findings"
  • "explain finding #3"
  • "how do I fix the JWT hardcoding?"
  • "which files have the most issues?"
  • "show all secrets"
  • "generate a remediation plan"
```

For the top-findings table, resolve the file path with:
```python
def file_loc(v):
    loc = v.get("location", {})
    if isinstance(loc, dict):
        f = loc.get("file", {})
        fname = f.get("file_name", f) if isinstance(f, dict) else str(f)
        line = loc.get("start_line", f.get("line", "") if isinstance(f, dict) else "")
        return f"{fname}:{line}" if line else str(fname)
    return str(loc)
```

**Hold the full parsed `vulns_sorted` list in your context** (do not summarize it away). Reference it when answering follow-up questions. Each vulnerability object has these fields available:

| Field | Content |
|-------|---------|
| `id` | UUID |
| `name` | Finding title |
| `message` | One-line description |
| `description` | Full explanation |
| `severity` | critical / high / medium / low / info |
| `scanner.name` | Gitleaks / Semgrep / KICS / Grype |
| `location.file` | File path (may be nested object for KICS) |
| `location.start_line` | Line number |
| `cve` | CVE identifier (if applicable) |
| `solution` | Remediation guidance |
| `ai_analysis` | AI-generated fix instructions (if available) |

When the user asks follow-up questions, answer using this loaded data directly — do not re-fetch.
