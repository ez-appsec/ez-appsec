---
name: Plan Proposal
about: Propose a new item for the ez-appsec roadmap
title: "[PROPOSAL] <short description of the problem>"
labels: proposal
assignees: ''
---

<!-- A proposal describes a problem and a rough solution.
     A maintainer will review it, spec it into a full plan, and convert it to a PLAN-XX issue.
     You don't need a complete design — a clear problem statement is enough to start. -->

## Problem

<!-- What is broken, missing, or painful? Who experiences it and when?
     One paragraph. Be specific — "it's hard to do X in situation Y" is more useful than "X is bad". -->

## Proposed solution

<!-- What would fix it? Keep this brief — a sentence or two is fine.
     Don't worry about implementation details yet; those get worked out if the proposal is accepted. -->

## Why it belongs in ez-appsec

<!-- Does it fit the project's goal: free, open-source, AI-native AppSec?
     Which user (developer, security team, auditor) does it benefit? -->

## Rough scope check

<!-- Answer yes/no. This helps maintainers evaluate whether it fits the atomic-plan model. -->

- [ ] Can this be implemented in a single new Python module (`ez_appsec/<feature>.py`) without restructuring existing code?
- [ ] Can it be tested without a running scanner or network access (i.e., mocked in unit tests)?
- [ ] Is it independent of other unmerged plans, or does it depend on one specific plan?
- [ ] Does it add new fields to `vulnerabilities.json` rather than changing existing ones?

## Related plans or issues

<!-- Link any existing plans this builds on or might conflict with. -->

## Alternatives considered

<!-- What other approaches did you think about? Why did you rule them out? -->
