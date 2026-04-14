Generate a prioritized remediation plan from vulnerability data already in context, balancing severity against fix complexity and risk. Then apply fixes grouped by file — safe changes immediately, risky changes with a single confirmation per tier.

## Usage

```
/ez-appsec remediate [filter]
```

`filter` is optional — a severity level (`critical`, `high`, `medium`, `low`) or a scanner name (`secrets`, `sast`, `iac`, `cve`). Omit to remediate all findings.

Requires vulnerability data in context from `/ez-appsec scan` or `/ez-appsec load`.

---

## Step 1 — Extract and score findings

Read the `<!-- ez-appsec-vulns {...} -->` payload from context. If absent, stop:
```
No vulnerability data in context. Run /ez-appsec scan or /ez-appsec load first.
```

Score each finding using this Python logic — run inline, no subprocess:

```python
SEV   = {"critical": 40, "high": 30, "medium": 20, "low": 10, "info": 0}
EFFORT = {
    # Low effort (quick wins) — score bonus +20
    "secret_detection": 20, "dependency_scanning": 15,
    # Medium effort — score bonus +10
    "sast": 10,
    # Higher effort (structural) — score bonus 0
    "iac": 5,
}
RISK = {
    # Risk level per category: safe / low / medium / high
    "secret_detection":    "safe",   # remove/rotate secret, no logic change
    "dependency_scanning": "low",    # bump version in lock file
    "sast":                "medium", # code logic change
    "iac":                 "low",    # config change
}

def score(v):
    cat = v.get("category", "").lower()
    sev = v.get("severity", "").lower()
    return SEV.get(sev, 0) + EFFORT.get(cat, 0)

def risk(v):
    cat = v.get("category", "").lower()
    # Escalate risk for auth/crypto/session findings
    msg = (v.get("message","") + v.get("name","")).lower()
    base = RISK.get(cat, "medium")
    if any(w in msg for w in ["jwt","auth","session","token","password","crypto","cipher","eval","exec","deserializ"]):
        bump = {"safe":"low","low":"medium","medium":"high","high":"high"}
        return bump.get(base, base)
    return base

def effort_label(v):
    cat = v.get("category","").lower()
    e = EFFORT.get(cat, 0)
    return "quick" if e >= 20 else "moderate" if e >= 10 else "involved"
```

Apply the `filter` argument if present (skip non-matching findings).

Sort findings by `score()` descending — high severity + low effort first.

Group by risk tier:
- **safe** — apply without asking
- **low** — apply without asking  
- **medium** — show plan, ask once: "Apply N medium-risk fixes?"
- **high** — show plan, ask once: "Apply N high-risk fixes?"

---

## Step 2 — Print the remediation plan (always, before touching any file)

```
Remediation plan  (<total> findings, <n_files> files)

Priority  Sev       Risk     Effort    Finding                          File
────────  ────────  ───────  ────────  ───────────────────────────────  ──────────────────
1         CRITICAL  safe     quick     Hardcoded AWS key                config/secrets.py:4
2         CRITICAL  safe     quick     JWT secret in source             app.js:8
3         HIGH      low      quick     lodash 4.17.15 CVE-2021-23337   package.json
4         HIGH      medium   moderate  SQL query built by string concat  db/queries.py:42
5         MEDIUM    low      moderate  Missing Content-Security-Policy   server/middleware.js
...

Safe/low (apply now): N findings
Medium risk (ask):    N findings
High risk (ask):      N findings
Skipped (info/iac):   N findings
```

Keep the table to 15 rows max — summarise the rest as "… and N more (same risk tier)".

---

## Step 3 — Apply fixes by risk tier

### Safe and low-risk fixes — apply immediately, no prompt

For each finding in the safe/low tier, in priority order:

1. Read the affected file (use the `file_name` from `location`)
2. Determine the minimal fix:
   - **secret_detection**: replace the literal value with `os.environ.get("VAR_NAME")` or equivalent for the language; add a `# TODO: set VAR_NAME env var` comment
   - **dependency_scanning (CVE)**: bump the version in `package.json`, `requirements.txt`, `go.mod`, `Gemfile`, or `pom.xml` to the patched version from the CVE description or `solution` field
   - **iac (missing attribute)**: add the required key/value to the config file
3. Apply with Edit — one edit per finding, grouped by file (batch all edits to the same file before moving on)
4. After each file: print `  ✓ <file> — <n> fix(es) applied`

Do not add comments explaining the vulnerability beyond the `# TODO` for secrets. Keep diffs minimal.

### Medium-risk fixes — one confirmation

Present:
```
Medium-risk fixes (N):
  • SQL injection in db/queries.py:42 — parameterize query
  • Unsafe eval() in utils.js:17 — replace with JSON.parse
  • ...

These modify application logic. Apply? (yes/no)
```

Use AskUserQuestion. If no, skip and note in summary.

If yes: apply each fix in priority order, same approach as safe tier.

### High-risk fixes — one confirmation

Present:
```
High-risk fixes (N):
  • JWT secret rotation in app.js:8 — changes auth flow
  • MD5 password hashing in auth/hash.py — requires migration
  • ...

These change security-critical logic and may require testing. Apply? (yes/no)
```

Use AskUserQuestion. If no, skip and note in summary.

If yes: apply, but after each file also print a brief warning:
`  ⚠  Test auth/affected flows before deploying`

---

## Step 4 — Summary

```
Remediation complete

  ✓ Applied    <n> fixes  (<n> files modified)
  ✗ Skipped   <n> findings  (declined or info-only)

Files changed:
  config/secrets.py  (2 fixes)
  app.js             (1 fix)
  package.json       (3 CVE bumps)

Next steps:
  • Rotate any exposed secrets immediately
  • Run tests before committing
  • Re-scan to verify: /ez-appsec scan
```

Only include sections that have content. Keep it to under 15 lines.
