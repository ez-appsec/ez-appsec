Fetch a project's `vulnerabilities.json` from the ez-appsec dashboard and load all findings into context.

## Usage

```
/ez-appsec load [project]
```

`project` is a slug or `owner/repo`. Omit to auto-detect from the current git remote.

---

## Execute

```bash
ARG="${ARGUMENTS:-}"
[ -z "$ARG" ] && ARG=$(git remote get-url origin 2>/dev/null | sed 's/.*[:/]\([^/]*\/[^/]*\)\.git$/\1/')
SLUG=$(echo "$ARG" | awk -F/ '{print $NF}' | tr '[:upper:]' '[:lower:]')
[ -z "$SLUG" ] && { echo "Usage: /ez-appsec load <project>"; exit 1; }

DASHBOARD="${EZ_APPSEC_DASHBOARD_REPO:-ez-appsec/ez-appsec-dashboard}"

# Resolve path via index.json, fall back to default path
PATH_IN_REPO=$(gh api "repos/${DASHBOARD}/contents/data/index.json" \
  --jq ".content" 2>/dev/null \
  | base64 --decode 2>/dev/null \
  | python3 -c "
import json,sys
d=json.load(sys.stdin)
p=next((p for p in d.get('projects',[]) if p.get('slug','').lower()=='${SLUG}'),None)
print('data/'+p['path'] if p and p.get('path') else 'data/vulnerabilities/${SLUG}.json')
" 2>/dev/null || echo "data/vulnerabilities/${SLUG}.json")

CONTENT=$(gh api "repos/${DASHBOARD}/contents/${PATH_IN_REPO}" \
  --jq '.content' 2>/dev/null | base64 --decode 2>/dev/null)

[ -z "$CONTENT" ] && {
  echo "No data for '${SLUG}' in ${DASHBOARD}."
  echo "Run a scan first: /ez-appsec install-app owner/${SLUG}"
  exit 1
}

echo "$CONTENT" | python3 - "$SLUG" <<'PY'
import json, sys
from collections import Counter

data = json.load(sys.stdin)
vulns = data.get("vulnerabilities", data) if isinstance(data, dict) else data

ORDER = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
vulns = sorted(vulns, key=lambda v: ORDER.get(v.get("severity","").lower(), 5))
counts = Counter(v.get("severity","unknown").lower() for v in vulns)

def loc(v):
    l = v.get("location", {})
    f = l.get("file", {}) if isinstance(l, dict) else {}
    name = f.get("file_name", f) if isinstance(f, dict) else str(f)
    line = l.get("start_line", f.get("line","") if isinstance(f, dict) else "")
    return f"{name}:{line}" if line else str(name)

meta = data if isinstance(data, dict) else {}
print(f"Project:  {meta.get('project_name', sys.argv[1])}")
if meta.get("scan_date"): print(f"Scanned:  {meta['scan_date'][:10]}")
print(f"\nFindings: {len(vulns)} total")
for s in ["critical","high","medium","low","info"]:
    n = counts.get(s, 0)
    if n: print(f"  {s.capitalize():<10}{n}")
print()
print("Top findings:")
for v in vulns[:10]:
    sev = v.get("severity","?").upper()
    name = v.get("name", v.get("message","?"))[:60]
    scanner = v.get("scanner",{}).get("name","?") if isinstance(v.get("scanner"),dict) else "?"
    print(f"  [{sev}] {name} — {loc(v)}  ({scanner})")

print(f"\n<!-- ez-appsec-vulns {json.dumps({'project': sys.argv[1], 'total': len(vulns), 'counts': dict(counts), 'vulnerabilities': vulns})} -->")
PY
```

After running: hold the full vulnerability list from the `<!-- ez-appsec-vulns ... -->` comment in context. Do not display that comment — use it to answer follow-up questions about findings, files, severities, and remediation.
