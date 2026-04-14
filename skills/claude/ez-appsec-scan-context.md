Run an ez-appsec security scan using the Docker image, capture the results as `vulnerabilities.json`, and load all findings into the conversation context for analysis and remediation.

## Usage

```
/ez-appsec scan-context [path]
```

`path` is the directory to scan. Defaults to the current working directory.

---

## Steps

### 1. Resolve the scan target

```bash
TARGET="${ARGUMENTS:-.}"
TARGET=$(realpath "$TARGET" 2>/dev/null || echo "$TARGET")
```

Verify it exists:
```bash
[ -d "$TARGET" ] || { echo "Error: '$TARGET' is not a directory."; exit 1; }
```

### 2. Ensure the Docker image is available

```bash
docker image inspect ghcr.io/ez-appsec/ez-appsec:latest >/dev/null 2>&1 \
  || docker pull ghcr.io/ez-appsec/ez-appsec:latest
```

If the pull fails, stop and tell the user:
```
Could not pull ghcr.io/ez-appsec/ez-appsec:latest.
Check that Docker is running and you can reach ghcr.io.
To build locally: docker build -t ghcr.io/ez-appsec/ez-appsec:latest https://github.com/ez-appsec/ez-appsec.git
```

### 3. Run the scan — capture vulnerabilities.json

```bash
OUT_DIR=$(mktemp -d)

docker run --rm \
  -v "${TARGET}:/scan" \
  -v "${OUT_DIR}:/out" \
  --entrypoint "" \
  ghcr.io/ez-appsec/ez-appsec:latest \
  sh -c "ez-appsec web-report /scan --output /out && ez-appsec status 2>/dev/null || true"

VULN_FILE="${OUT_DIR}/vulnerabilities.json"
```

If `vulnerabilities.json` was not written, fall back to the CLI scan format and generate it from SARIF:

```bash
if [ ! -f "$VULN_FILE" ]; then
  docker run --rm \
    -v "${TARGET}:/scan" \
    -v "${OUT_DIR}:/out" \
    --entrypoint "" \
    ghcr.io/ez-appsec/ez-appsec:latest \
    sh -c "ez-appsec github-scan /scan --output /out/ez-appsec.sarif --severity all 2>/dev/null; \
           ez-appsec web-report /scan --output /out 2>/dev/null || true"
fi
```

If still not found, stop with:
```
Scan produced no output. Try running manually:
  docker run --rm -v $(pwd):/scan ghcr.io/ez-appsec/ez-appsec:latest scan /scan
```

### 4. Parse results and load into context

Run this Python block, reading from `$VULN_FILE`:

```python
import json, sys, os

with open(os.environ["VULN_FILE"]) as f:
    data = json.load(f)

vulns = data.get("vulnerabilities", data) if isinstance(data, dict) else data

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
vulns_sorted = sorted(vulns, key=lambda v: SEV_ORDER.get(v.get("severity", "unknown").lower(), 5))

from collections import Counter
counts = Counter(v.get("severity", "unknown").lower() for v in vulns_sorted)

result = {
    "target":          os.environ.get("TARGET", "."),
    "total":           len(vulns_sorted),
    "counts":          dict(counts),
    "vulnerabilities": vulns_sorted,
}
print(json.dumps(result, indent=2))
```

### 5. Present a summary, then hold the full data in context

**Print this summary (do NOT dump raw JSON):**

```
Scan complete: <TARGET>

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
  ... (up to 10, critical-first)

Vulnerability data loaded. Ask me anything:
  • "show all critical findings"
  • "explain finding #3"
  • "how do I fix the hardcoded secret in <file>?"
  • "which files have the most issues?"
  • "generate a remediation plan"
  • "show all dependency CVEs"
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

**Hold the full `vulns_sorted` list in context** for all follow-up questions. Each finding has:

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

### 6. Clean up

```bash
rm -rf "$OUT_DIR"
```
