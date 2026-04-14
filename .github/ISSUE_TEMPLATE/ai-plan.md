---
name: AI Plan
about: Claim and track a ROADMAP plan (human or AI contributor)
title: "[PLAN-XX] <title from ROADMAP>"
labels: roadmap
assignees: ''
---

## Plan

**PLAN ID:** <!-- e.g. PLAN-01 -->
**ROADMAP phase:** <!-- Phase 1 / 2 / 3 / 4 / 5 -->

## Approach

<!-- Briefly describe how you plan to implement this — module structure, key design decisions, anything that deviates from the ROADMAP technical approach. -->

## Test strategy

<!-- List the test file(s) you will create and what each covers. Must satisfy the Done Criteria in ROADMAP.md. -->

- [ ] `tests/test_<module>.py` — <!-- what it covers -->
- [ ] Existing test suite passes (`pytest tests/`)

## Checklist

- [ ] All done criteria from `ROADMAP.md` satisfied
- [ ] New tests added (see above)
- [ ] `pytest tests/` passes with no regressions
- [ ] Docker image size checked if new dependencies added
- [ ] Docs updated if user-facing behavior changed
- [ ] Draft PR opened and linked to this issue

## PR

<!-- Link the draft PR here once opened -->
