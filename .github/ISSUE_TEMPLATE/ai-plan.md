---
name: AI Plan
about: Claim and track a ROADMAP plan (human or AI contributor)
title: "[PLAN-XX] <title from ROADMAP>"
labels: roadmap
assignees: ''
---

## Plan

**PLAN ID:** <!-- e.g. PLAN-01 -->
**ROADMAP phase:** <!-- Phase 1 / 2 / 3 / 4 / 5 / 6 / 7 -->
**Estimated effort:** <!-- e.g. 2–4 hours -->
**Depends on:** <!-- e.g. PLAN-04 must be merged first, or "none" -->

---

## Getting started

```bash
# 1. Fork (external) or clone (org member), install, verify baseline
gh repo fork ez-appsec/ez-appsec --clone --remote && cd ez-appsec
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -x -q          # must be green before you start

# 2. Claim this plan, create branch, get AI prompt
bash scripts/claim-plan.sh <this-issue-number>
```

Paste the printed prompt into any AI coding assistant (Claude Code, Cursor, Copilot Workspace, Gemini Code Assist, or any other tool). See [CONTRIBUTING.md](../../CONTRIBUTING.md) for full prerequisites and the dependency-plan fallback workflow.

---

## Before you start

**Read these files first** (understand them before writing any code):
<!-- List 2–4 files the implementer needs to read to understand the context.
     Be specific — include the function or class name if relevant.
     Example:
- `ez_appsec/scanner.py` — `SecurityScanner.scan()` method (lines 25–55): this is where your hook goes
- `ez_appsec/config.py` — `Config` class: add your new field here
-->
- <!-- file: why -->
- <!-- file: why -->

**Finding schema** (what a finding dict looks like — all plans that process findings use this shape):

```python
{
    "id":           "abc123",           # stable fingerprint hash
    "title":        "Hardcoded secret", # human-readable title
    "severity":     "critical",         # critical | high | medium | low
    "category":     "secrets",          # secrets | sast | iac | dependency_scanning
    "rule_id":      "generic-api-key",  # scanner rule identifier
    "file_name":    "src/config.py",    # relative path from repo root
    "start_line":   42,                 # 1-indexed
    "description":  "...",
    "solution":     "...",              # present on CVE findings with a known fix
    "scanner":      "gitleaks",         # gitleaks | semgrep | kics | grype
    "suppressed_by": None,             # set by PLAN-02 ignore rules, else None
}
```

**Baseline test run** (confirm this passes before writing a single line):

```bash
pytest tests/ -x -q
# Expected: all green. If not, open an issue before starting.
```

---

---

## Approach

<!-- Briefly describe how you plan to implement this — module structure, key design decisions, anything that deviates from the ROADMAP technical approach. -->

## Test strategy

<!-- List the test file(s) you will create and what each covers. Must satisfy the Done Criteria in ROADMAP.md. -->

- [ ] `tests/test_<module>.py` — <!-- what it covers -->
- [ ] Existing test suite passes (`pytest tests/`)

## Checklist

- [ ] All done criteria from the plan issue satisfied
- [ ] New tests added (see above)
- [ ] `pytest tests/` passes with no regressions
- [ ] No files in the conflict guard section were modified
- [ ] Docker image size checked if new dependencies added
- [ ] Docs updated if user-facing behavior changed
- [ ] Draft PR opened and linked to this issue

## PR

<!-- Link the draft PR here once opened -->
