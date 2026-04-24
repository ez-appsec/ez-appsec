Run an ez-appsec security scan via Docker, capture `vulnerabilities.json`, and load all findings into context.

## Usage

```
/ez-appsec scan [path]
```

Defaults to current directory.

---

## Execute

```bash
TARGET=$(realpath "${ARGUMENTS:-.}")
OUT=$(mktemp -d)

docker image inspect ghcr.io/ez-appsec/ez-appsec:latest >/dev/null 2>&1 \
  || docker pull ghcr.io/ez-appsec/ez-appsec:latest \
  || { echo "Cannot pull ghcr.io/ez-appsec/ez-appsec:latest — is Docker running?"; exit 1; }

docker run --rm \
  -v "${TARGET}:/scan" \
  -v "${OUT}:/out" \
  --entrypoint "" \
  ghcr.io/ez-appsec/ez-appsec:latest \
  sh -c "ez-appsec web-report /scan --output /out 2>/dev/null"

VULN_FILE="${OUT}/vulnerabilities.json"
[ -f "$VULN_FILE" ] || { echo "Scan produced no output. Run: docker run --rm -v \$(pwd):/scan ghcr.io/ez-appsec/ez-appsec:latest scan /scan"; rm -rf "$OUT"; exit 1; }

python3 - "$VULN_FILE" "$TARGET" <<'PY'
import json, sys
from collections import Counter

data = json.load(open(sys.argv[1]))
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

print(f"Scan complete: {sys.argv[2]}\n")
print(f"Findings: {len(vulns)} total")
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

# Emit full dataset as a JSON comment for context retention
print(f"\n<!-- ez-appsec-vulns {json.dumps({'target': sys.argv[2], 'total': len(vulns), 'counts': dict(counts), 'vulnerabilities': vulns})} -->")
PY

rm -rf "$OUT"
```

After running: hold the full vulnerability list from the `<!-- ez-appsec-vulns ... -->` comment in context. Do not display that comment — use it to answer follow-up questions about findings, files, severities, and remediation.
