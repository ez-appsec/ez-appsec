---
name: Plan (new feature / significant work)
about: Propose and claim a new feature, integration, or significant body of work. Required before starting. Human and human+AI workflows both use this template.
title: "[PLAN] "
labels: plan
assignees: ''
---

## What

<!-- One paragraph: what capability does this add, and what user problem does it solve? Be specific — "improve security" is not a plan. -->

## Why now

<!-- Why is this the right thing to work on? Link to a related issue, user report, or roadmap item if applicable.
If this is a ROADMAP plan, write: "Implements PLAN-XX from ROADMAP.md." -->

## Scope

**In scope:**
-
-

**Out of scope:**
-
-

## Technical approach

<!-- How will you implement this? Name the module(s) you will create or modify, key data structures, and any external dependencies being added. Keep it to the point — this is a plan, not a design doc. -->

## Tests

<!-- List the test file(s) and what each covers. New features must ship with tests. -->

- `tests/test_<module>.py` —
- Existing test suite passes (`pytest tests/`)

## Done criteria

<!-- A concrete, verifiable checklist. "It works" is not a criterion. -->

- [ ]
- [ ] `pytest tests/` passes with no regressions
- [ ] Docs updated (if user-facing)
- [ ] Docker image size unchanged or justified (if new deps added)

## Conflicts / dependencies

<!-- Does this touch the same files as another open plan? If so, coordinate. Plans should be independent — if this one can't be, explain why. -->

None.

## AI workflow notes (if applicable)

<!-- If you are using Claude Code or another AI agent to implement this:
- Which /ez-appsec skills or external tools will the agent use?
- What is the agent's scope — what should it NOT touch?
- How will you review the agent's output? -->

---

**Before opening a PR:** Verify no other open plan covers the same scope. Check the [roadmap](https://github.com/ez-appsec/ez-appsec/blob/main/ROADMAP.md) and [open plan issues](https://github.com/ez-appsec/ez-appsec/labels/plan).
