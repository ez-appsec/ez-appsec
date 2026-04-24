Run the ez-appsec command test harness — verifies every subcommand end-to-end with minimal
side effects and maximum parallelism.

## Usage

```
/ez-appsec test [suite ...]
```

Suites: `smoke` `scan` `load` `remediate` `github` `gitlab` `dashboard` `all`

Default (no argument): `smoke scan load` — safe, no pipeline changes.

Multiple suites may be given: `/ez-appsec test scan github`

---

## Test Targets (fixed)

| Variable            | Value                                              |
|---------------------|----------------------------------------------------|
| GH_TEST_REPO        | `ez-appsec/juice-shop-public`                      |
| GH_DASHBOARD_REPO   | `ez-appsec/ez-appsec-dashboard`                    |
| GL_GROUP            | `jfelten.work-group/ez_appsec`                     |
| GL_PROJECTS         | `juice-shop` `bwapp` `webgoat` `dvwa`              |
| LOCAL_SCAN_TARGET   | `/Users/johnfelten/git/2026/ez-appsec`             |

---

## Execution Model

Work through each requested suite in order. For each test:

1. Print `  Running: <test name>` before executing
2. Run the command(s)
3. Evaluate pass/fail criteria
4. Record result — do NOT stop on failure, continue to next test
5. Print final summary table at the end

Track results in a list: `results = []` — append `(suite, name, status, detail)` tuples.

---

## Suite 0 — Smoke

Always run first, even if not explicitly requested.

### S0-1: VERSION readable

```bash
cat /Users/johnfelten/git/2026/ez-appsec/VERSION
```

PASS if exit 0 and output matches `[0-9]+\.[0-9]+\.[0-9]+`.

### S0-2: gh CLI authenticated

```bash
gh auth status 2>&1
```

PASS if output contains `Logged in to github.com`.

### S0-3: Docker available

```bash
docker info --format '{{.ServerVersion}}' 2>&1
```

PASS if exit 0 and output is non-empty (a version string).

### S0-4: glab CLI authenticated (required for gitlab suite)

```bash
glab auth status 2>&1
```

PASS if output contains `Logged in`. SKIP (not FAIL) if glab not installed — note it and skip the
`gitlab` suite automatically.

### S0-5: ez-appsec Docker image available or pullable

```bash
docker image inspect ghcr.io/ez-appsec/ez-appsec:latest --format '{{.Id}}' 2>/dev/null \
  || docker pull ghcr.io/ez-appsec/ez-appsec:latest 2>&1 | tail -3
```

PASS if image ID or "Pull complete" found. SKIP the `scan` suite if this fails.

---

## Suite 1 — Scan

Tests `/ez-appsec scan` end-to-end. Requires Docker (smoke S0-3 and S0-5 must pass).

### S1-1: Scan produces vulnerabilities.json

```bash
OUT=$(mktemp -d)
docker run --rm \
  -v "/Users/johnfelten/git/2026/ez-appsec:/scan" \
  -v "${OUT}:/out" \
  --entrypoint "" \
  ghcr.io/ez-appsec/ez-appsec:latest \
  sh -c "ez-appsec web-report /scan --output /out 2>/dev/null"
ls -lh "${OUT}/vulnerabilities.json"
TOTAL=$(python3 -c "import json; d=json.load(open('${OUT}/vulnerabilities.json')); v=d.get('vulnerabilities',d); print(len(v) if isinstance(v,list) else 0)")
echo "total_findings=$TOTAL"
rm -rf "$OUT"
```

PASS if `vulnerabilities.json` exists and `total_findings` is an integer ≥ 0.

### S1-2: Scan skill summary format

Invoke the `ez-appsec-scan` skill via the Skill tool with argument
`/Users/johnfelten/git/2026/ez-appsec`.

PASS if the output contains:
- `Scan complete:`
- `Findings:` with a number
- The hidden `<!-- ez-appsec-vulns` comment in the returned text (check that it is present in
  the raw skill output — you will hold it in context but not display it)

---

## Suite 2 — Load

Tests `/ez-appsec load` end-to-end. Requires gh CLI (smoke S0-2 must pass).

### S2-1: Dashboard index.json readable

```bash
gh api "repos/ez-appsec/ez-appsec-dashboard/contents/data/index.json" \
  --jq '.content' | base64 --decode | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('projects',[])),'projects')"
```

PASS if output contains `projects`.

### S2-2: Load juice-shop vulnerabilities

```bash
SLUG="juice-shop-public"
DASHBOARD="ez-appsec/ez-appsec-dashboard"
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

echo "$CONTENT" | python3 -c "
import json,sys
data=json.load(sys.stdin)
vulns=data.get('vulnerabilities',data) if isinstance(data,dict) else data
from collections import Counter
counts=Counter(v.get('severity','?').lower() for v in vulns)
print(f'total={len(vulns)} counts={dict(counts)}')
"
```

PASS if `total=` is a positive integer.

### S2-3: Load skill context payload

Invoke the `ez-appsec-load-vulns` skill via the Skill tool with argument `juice-shop-public`.

PASS if the output contains:
- `Findings:` with a number
- `Top findings:` section
- The hidden `<!-- ez-appsec-vulns` comment in the raw skill output

---

## Suite 3 — Remediate

Tests `/ez-appsec remediate`. Requires Suite 2 (load) to have run first so vuln data is in context.

If Suite 2 was not run or did not pass, run S2-3 first to load juice-shop vulns, then proceed.

### S3-1: Graceful error without context

Simulate missing context: invoke the `ez-appsec-remediate` skill with no vulnerability data
available. Check that it outputs:

```
No vulnerability data in context.
```

Skip this test and note it — it's hard to test graceful error while also having data loaded.
Instead, proceed directly to S3-2.

### S3-2: Remediation plan from loaded context

With juice-shop vulns in context from Suite 2 (or loaded fresh via S2-3):

Invoke the `ez-appsec-remediate` skill with argument `high`.

PASS if the output contains:
- `Remediation plan` header
- A table with columns: `Priority`, `Sev`, `Risk`, `Effort`, `Finding`, `File`
- At least one `HIGH` row
- Summary footer with `Safe/low`, `Medium risk`, `High risk` counts

Do NOT apply any fixes — if prompted to apply medium or high risk changes, answer `no`.

---

## Suite 4 — GitHub Pipeline

Tests the GitHub scan pipeline on `ez-appsec/juice-shop-public`.
Requires gh CLI (smoke S0-2 must pass). Takes ~5 minutes.

### S4-1: Scan workflow exists on test repo

```bash
gh api repos/ez-appsec/juice-shop-public/contents/.github/workflows/ez-appsec-scan.yml \
  --jq '.name' 2>&1
```

PASS if output is `ez-appsec-scan.yml`.

### S4-2: Trigger scan and verify completion

```bash
/Users/johnfelten/git/2026/ez-appsec/github/scripts/github-pipeline-test.sh \
  --repo ez-appsec/juice-shop-public \
  --workflow "ez-appsec-scan.yml" \
  --ref master \
  --check-dashboard \
  --dashboard-repo ez-appsec/ez-appsec-dashboard \
  --timeout 600
```

PASS if exit code 0 and output contains `PASS:`.

### S4-3: Dashboard has juice-shop data post-scan

```bash
gh api "repos/ez-appsec/ez-appsec-dashboard/contents/data/index.json" \
  --jq '.content' | base64 --decode \
  | python3 -c "
import json,sys
d=json.load(sys.stdin)
p=[p for p in d.get('projects',[]) if 'juice-shop' in p.get('slug','').lower()]
print('found' if p else 'missing', p[0].get('slug','') if p else '')
"
```

PASS if output starts with `found`.

---

## Suite 5 — GitLab Pipeline

Tests all 4 GitLab projects. Requires glab (smoke S0-4 must pass). Takes ~10 minutes.

Run all 4 projects sequentially (the test script handles one at a time):

```bash
GL_SCRIPT="/Users/johnfelten/git/2026/ez-appsec/gitlab/scripts/gitlab-pipeline-test.sh"
GL_GROUP="jfelten.work-group/ez_appsec"

for proj in juice-shop bwapp webgoat dvwa; do
  echo "══ Testing ${proj} ══"
  "$GL_SCRIPT" \
    --project "${GL_GROUP}/${proj}" \
    --check-dashboard \
    --timeout 600
done
```

PASS per project if exit code 0 and output contains `PASS: GitLab pipeline test succeeded`.
Report each project separately in the results table.

---

## Suite 6 — Dashboard

Tests `/ez-appsec update-dashboard`. Requires gh CLI. Takes ~3 minutes.

### S6-1: Dashboard repo accessible

```bash
gh repo view ez-appsec/ez-appsec-dashboard --json name,updatedAt --jq '"name=\(.name) updated=\(.updatedAt)"'
```

PASS if output contains `name=ez-appsec-dashboard`.

### S6-2: Dashboard assets present

```bash
for f in index.html style.css app-github.js; do
  gh api "repos/ez-appsec/ez-appsec-dashboard/contents/${f}" \
    --jq ".name" 2>/dev/null || echo "MISSING: $f"
done
```

PASS if none of the outputs contain `MISSING:`.

### S6-3: update-dashboard workflow triggers and succeeds

Invoke the `ez-appsec-update-dashboard` skill with argument `ez-appsec/ez-appsec-dashboard`.

PASS if the skill completes without errors and reports that assets were updated or already current.

---

## Output Format

After all suites complete, print:

```
ez-appsec test results
══════════════════════════════════════════════════════════════
Suite   Test    Status   Detail
──────  ──────  ───────  ──────────────────────────────────────
smoke   S0-1    PASS     v1.7.1
smoke   S0-2    PASS     Logged in to github.com as ez-appsec
smoke   S0-3    PASS     Docker 27.4.0
smoke   S0-4    PASS     Logged in to gitlab.com
smoke   S0-5    PASS     image cached locally
scan    S1-1    PASS     47 findings
scan    S1-2    PASS     context payload loaded
load    S2-1    PASS     12 projects in index
load    S2-2    PASS     total=89
load    S2-3    PASS     context payload loaded
...
──────  ──────  ───────  ──────────────────────────────────────
Total   17 tests:  14 PASS  1 FAIL  2 SKIP
```

List all FAILed tests after the table with a brief diagnosis.

Exit with a non-zero signal (note it in text) if any test FAILed.
