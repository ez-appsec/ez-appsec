# SSO and Enterprise Procurement Deferrals

**Version:** 1.0  
**Date:** 2026-06-25  
**Milestone:** M003-lp54mb — Self-Service Commercial Launch  
**Slice:** S07 — Enterprise Ready Foundations  
**Status:** Planning artifact (not yet implemented)

---

## Purpose

This document defines how ez-appsec should handle SSO, SCIM, custom contracts, procurement questionnaires, invoicing, enterprise SLAs, and private deployment requests **before these capabilities are built**. It provides:

- Safe customer-facing response language for each category
- Trigger thresholds that signal when to build each capability
- Risks of building too early
- Demand tracking so the team can measure actual pipeline

All capabilities in this document are classified **Deferred (D)** in the [Enterprise Readiness Capability Map](./enterprise-readiness-capability-map.md) unless otherwise noted. The tier model is: L=Launch Blocker, F=Early Foundation, FF=Fast-Follow, D=Deferred.

---

## 1. SSO / SAML / OIDC

### Current State

Ez-appsec uses email+password and OAuth (Google/GitHub) for authentication. No SAML or OIDC federation is implemented. The `account` table includes `auth_provider` and `external_identity_id` columns (Early Foundation, F) so SSO can be wired in without a schema migration when it ships.

### Tier: D (Deferred)

**Risks of building too early:**
- SAML libraries carry significant CVE surface; each IdP has quirks requiring sustained maintenance.
- Implementing before there is a committed enterprise contract means the implementation will be untested in production and likely needs rework once a real IdP requirement arrives.
- OIDC and SAML have different session lifetime and logout semantics that affect all auth middleware, not just login.

**Trigger thresholds — build when ANY one of these is true:**
1. A prospect with ≥ $50K ARR potential makes SSO a hard blocker in a deal call.
2. Three distinct qualified prospects within a 60-day window request SSO on intake forms.
3. The company commits to a SOC 2 Type II audit (which auditors will ask about IdP federation).

### Customer-Facing Response Language

> "Ez-appsec currently supports email/password and Google or GitHub OAuth for login. We don't offer SAML or OIDC federation today, but our authentication layer is architected to support it. If SSO is a requirement for your evaluation, please contact us at [enterprise@ez-appsec.com] and we'll let you know our current roadmap timing. We track all SSO requests to prioritize this based on actual demand."

**What NOT to say:**
- Do not promise a specific delivery date.
- Do not say "it's coming soon" unless the trigger threshold has been crossed and engineering has committed.
- Do not offer to scope a custom auth integration for a single prospect without executive sign-off.

### Demand Tracking

Log every SSO request in the CRM under tag `feature-request:sso`. Monthly: count distinct organizations requesting SSO, note ARR potential per account, and review against trigger thresholds above.

**Observability metric:** `enterprise_feature_request_count{feature="sso"}` — increment on each new request; emit to product analytics dashboard.

---

## 2. SCIM User Provisioning / Deprovisioning

### Current State

No SCIM endpoint exists. Member invite/removal is manual (owner sends an email invite; member accepts; owner removes). This is sufficient for small teams.

### Tier: D (Deferred, depends on SSO)

SCIM is only meaningful once SSO is live — IdPs push SCIM events using the SSO identity link. Building SCIM before SSO is built is architecturally backwards.

**Risks of building too early:**
- SCIM spec (RFC 7644) has substantial surface area: bulk operations, filtering, etags, concurrent deprovisioning edge cases.
- IdP connectors (Okta, Azure AD, Google Workspace) each require separate integration testing and ongoing certification.
- Premature SCIM implementation locks the member data model before the membership schema is fully validated by real usage patterns.

**Trigger thresholds — build when ALL of these are true:**
1. SSO (§1) has been shipped and is in production with at least one customer.
2. A prospect with ≥ $50K ARR potential makes SCIM provisioning a hard requirement.

### Customer-Facing Response Language

> "We manage team membership through manual invitations today. Automated provisioning via SCIM is on our roadmap for after SSO is live. If automated user management is a hard requirement for your organization, please let us know so we can track that demand and reach out when it's available."

### Demand Tracking

Log SCIM requests under CRM tag `feature-request:scim`. Do not count separately from SSO requests for threshold purposes — a SCIM request implies SSO is also required.

---

## 3. Custom Contracts (MSA, DPA, BAA)

### Current State

Ez-appsec's terms of service and privacy policy are clickthrough agreements. No custom Master Service Agreements (MSA), Data Processing Agreements (DPA), or Business Associate Agreements (BAA) are offered.

### Tier: D (Deferred)

**DPA note:** A standard DPA template covering GDPR Article 28 obligations is listed as Early Foundation (F) in the [compliance evidence document](./data-retention-export-compliance-evidence.md). This is a fixed template the customer accepts, not a negotiated custom contract.

**Risks of custom contract negotiation too early:**
- Every redline requires legal review (estimated 2–10 hours per negotiation cycle).
- Precedent set by first custom contract constrains all future negotiations.
- BAA triggers HIPAA compliance requirements across the entire platform, not just for the requesting customer.

**Trigger thresholds for custom MSA:**
1. A prospect has ARR potential ≥ $100K and legal negotiation is gating the deal.
2. CEO or Head of Sales explicitly approves diverting legal bandwidth to that deal.

**Trigger thresholds for BAA (HIPAA):**
1. A prospect explicitly handles Protected Health Information (PHI) in their vendor scan workflow AND the ARR potential is ≥ $75K.
2. Legal has conducted a HIPAA gap assessment for the platform (minimum prerequisite).

### Customer-Facing Response Language

**Custom MSA:**
> "Our standard Terms of Service govern all accounts. We don't offer custom MSA negotiation at this stage, but if your procurement team has a specific requirement, please reach out to [enterprise@ez-appsec.com] so we can understand what's needed."

**DPA (GDPR):**
> "We have a Data Processing Agreement available that covers our GDPR Article 28 obligations. You can find it at [link] or request a signed copy by emailing [privacy@ez-appsec.com]."

**BAA (HIPAA):**
> "We don't currently offer a Business Associate Agreement. Ez-appsec is not designed for environments that process Protected Health Information. If your use case involves PHI, please consult with your compliance team before using the platform."

### Demand Tracking

Log every custom contract request under CRM tag `feature-request:custom-contract` with sub-tags: `msa`, `dpa`, `baa`. Flag BAA requests to legal immediately regardless of deal size.

---

## 4. Security and Vendor Questionnaires

### Current State

No questionnaire response library exists. Each questionnaire is answered ad hoc. The [compliance evidence document](./data-retention-export-compliance-evidence.md) §8 defines the Security Questionnaire Readiness Inventory as Fast-Follow (FF).

### Tier: FF (Fast-Follow, target within 90 days of launch)

**Rationale:** Security questionnaires block procurement at nearly every company above 100 employees. The barrier to building a response library is low (a Google Sheet or Notion database suffices initially), and the cost of not having one is repeated engineering distraction answering the same questions.

**Risks of not having a library:**
- Engineering time is diverted to writing prose answers under deal deadlines.
- Inconsistent answers across deals create audit risk.
- Prospects lose confidence when responses are slow or incomplete.

**Minimum viable questionnaire library (FF):**
- VSA (Vendor Security Assessment) standard questions covering: encryption at rest/transit, access controls, incident response, vulnerability management, penetration testing, data residency, subprocessor list.
- Shared Assessments SIG Lite mapping.
- SOC 2 Type I or II readiness statement.
- Answer cache in an internal wiki or CRM knowledge base.

### Customer-Facing Response Language

**While questionnaire library is being built:**
> "We take security questionnaires seriously and are building a formal response library. If you've sent a questionnaire, our team will respond within 5 business days. For urgent procurement timelines, please flag the deadline in your email to [security@ez-appsec.com]."

**Once library is live:**
> "We maintain a security questionnaire response library that covers standard VSA and SIG Lite questions. Email [security@ez-appsec.com] with your questionnaire and we'll return completed answers within 2 business days."

### Demand Tracking

Log all questionnaire requests under CRM tag `procurement:questionnaire`. Track: date received, questionnaire type (SIG/VSA/custom), deadline, ARR potential, completion date. Aggregate weekly to measure volume trend.

**Observability metric:** `enterprise_feature_request_count{feature="questionnaire"}` — increment on each new request.

---

## 5. Enterprise Invoicing and Purchase Orders

### Current State

Ez-appsec uses Stripe for subscription billing with credit card or ACH. No purchase order (PO) workflow, NET-30/60/90 invoicing, or accounts payable integration exists.

### Tier: D (Deferred)

**Risks of building too early:**
- PO-based invoicing requires AP workflow that extends billing engineering scope substantially.
- NET-30/60 payment terms create cash flow risk without AR tooling.
- Manual invoice reconciliation is operationally expensive at low volume.

**Trigger thresholds:**
1. A prospect with ≥ $50K ARR will not use a credit card and explicitly requires PO-based invoicing.
2. Three qualified enterprise prospects in a 90-day window request PO invoicing.

### Customer-Facing Response Language

> "We currently process subscriptions by credit card or ACH through Stripe. We don't offer purchase order or NET-30 invoicing at this time. If your procurement process requires invoiced billing, please contact us at [billing@ez-appsec.com] so we can understand your needs and track demand for this feature."

**Interim workaround (before feature is built):** For high-value deals where credit card is an absolute blocker, sales can manually issue an invoice via Stripe's invoice feature and set due date to NET-30. This is a one-off exception that requires CEO approval; it is not a general capability.

### Demand Tracking

Log every PO/invoice request under CRM tag `procurement:invoice`. Track: ARR potential, deal stage, whether credit card was an absolute blocker. Aggregate monthly.

---

## 6. Enterprise SLAs

### Current State

Ez-appsec's terms of service do not include an SLA. There is no uptime commitment, incident response time commitment, or support response time commitment.

### Tier: D (Deferred)

**Risks of offering SLAs too early:**
- An SLA is a contractual obligation with financial penalties (credits) that requires monitoring, alerting, and incident management infrastructure to enforce honestly.
- Publishing an SLA before the reliability infrastructure is in place creates legal exposure.
- SLA negotiation consumes the same legal bandwidth as custom contracts (§3).

**Trigger thresholds:**
1. The platform has demonstrated 99.5%+ uptime for 3 consecutive months with instrumented measurement.
2. A prospect with ≥ $75K ARR makes an SLA a hard contract requirement.
3. The team has on-call rotation, incident runbooks, and a status page before the SLA is offered.

**Prerequisites before any SLA:**
- Status page (public, auto-updating from health checks).
- On-call rotation with defined escalation path.
- Incident response runbook with defined severity levels and response time targets.
- Automated uptime measurement with dashboard (not just "it seems fine").

### Customer-Facing Response Language

> "We're committed to high availability and monitor our platform continuously, but we don't currently offer a formal SLA with contractual uptime guarantees. If a specific uptime commitment is required for your procurement process, please contact us at [enterprise@ez-appsec.com] so we understand the requirement. We'll flag this to our engineering team and track it against our reliability roadmap."

**What NOT to say:**
- Do not verbally commit to "99.9%" uptime or any specific number without a signed, tracked SLA document.
- Do not offer SLA credits without legal review.

### Demand Tracking

Log SLA requests under CRM tag `procurement:sla`. Note whether the prospect specified a minimum uptime percentage and whether credits were required.

---

## 7. Private / On-Premises Deployment

### Current State

Ez-appsec is SaaS-only. There is no containerized on-premises distribution, private cloud deployment guide, or customer-managed infrastructure option.

### Tier: D (Deferred indefinitely unless pipeline validates)

**Risks of building too early:**
- On-premises deployment multiplies the support surface dramatically: customer-managed upgrades, network configurations, TLS certificate management, database provisioning, and customer-specific bugs.
- Each customer's environment is different; on-prem support is operationally expensive at low deal count.
- Security scanning SaaS has strong trust arguments (air-gap the analysis, not the platform) that often overcome on-prem objections once articulated.

**Trigger thresholds (high bar — both required):**
1. Three distinct enterprise prospects with ≥ $100K ARR each specifically require on-premises deployment and cannot be convinced by the trust argument.
2. The company has validated the on-prem delivery and support model (packaging, upgrade path, support contract) before committing to the first customer.

### Customer-Facing Response Language

> "Ez-appsec is a cloud-hosted SaaS platform. We don't offer on-premises or private cloud deployment today. Our security model is designed so that your source code and proprietary data never leave your environment — we receive only what you explicitly upload for scanning. If a specific on-premises requirement is blocking your evaluation, please let us know the constraint and we'll see if there's a way to address it."

**Trust argument (use proactively):**
> "Many customers find that SaaS-based scanning actually reduces their attack surface relative to hosting the scanner themselves, because you control exactly what is uploaded, and the analysis environment is isolated from your network. We're happy to walk through our data isolation model."

### Demand Tracking

Log on-prem requests under CRM tag `procurement:on-prem`. For each request, record: industry vertical, deal size, specific regulatory driver (if stated). Aggregate quarterly.

---

## 8. Triage Criteria Summary

| Category | Tier | Build When | Max Response Time |
|----------|------|-----------|-------------------|
| SSO / SAML / OIDC | D | 1 committed deal ≥ $50K ARR **or** 3 requests in 60 days | Reply within 2 business days |
| SCIM provisioning | D | SSO shipped + 1 committed deal ≥ $50K ARR | Reply within 2 business days |
| Custom MSA | D | 1 deal ≥ $100K ARR + CEO approval | Acknowledge same day; respond in 5 days |
| DPA (GDPR standard) | F | Available now as standard template | Same day — send template |
| BAA (HIPAA) | D | Legal gap assessment complete + deal ≥ $75K ARR | Escalate to legal same day |
| Questionnaire library | FF | Within 90 days of launch | 5 business days (pre-library), 2 (post) |
| PO / NET-30 invoicing | D | 1 deal ≥ $50K ARR where CC is absolute blocker | Reply within 2 business days |
| Enterprise SLA | D | 99.5% uptime demonstrated for 3 months + deal ≥ $75K ARR | Reply within 2 business days |
| On-premises deployment | D | 3 deals ≥ $100K ARR each, all hard blockers | Reply within 2 business days |

---

## 9. Demand Tracking Implementation

### Minimum Viable Tracking (launch day)

Until a formal CRM is in use, maintain a shared spreadsheet with the following columns:

| Column | Values |
|--------|--------|
| Date | ISO date |
| Organization | Company name |
| ARR Potential | $ estimate |
| Feature Category | One of: sso, scim, msa, dpa, baa, questionnaire, invoice, sla, on-prem |
| Deal Stage | Lead / Qualified / Proposal / Blocked / Closed-Won / Closed-Lost |
| Trigger Threshold Met? | Yes / No / Partial |
| Notes | Free text |

**Owner:** Head of Sales or first sales hire. Review weekly with product team.

### Trigger Review Cadence

- **Weekly:** Count new requests per category. Flag any category where trigger threshold is newly met.
- **Monthly:** Review deal pipeline ARR against thresholds. Decide whether to begin scoping any deferred feature.
- **Quarterly:** Reassess Tier D decisions. Promote to FF if two or more trigger thresholds have been crossed.

### Product Analytics Events

Emit these events to the product analytics system to enable automated threshold monitoring:

```
enterprise_feature_request_created {
  feature: "sso" | "scim" | "msa" | "dpa" | "baa" | "questionnaire" | "invoice" | "sla" | "on-prem",
  org_id: "<crm-org-id>",         # CRM identifier, not internal org_id
  arr_potential_usd: <number>,
  deal_stage: "<stage>",
  date: "<ISO8601>"
}
```

Dashboards to build (FF, within 90 days):
- Rolling 60-day SSO request count by deal ARR
- Running total by feature category
- Threshold proximity indicators (e.g., "SSO: 2 of 3 required requests in the last 60 days")

---

## 10. Failure Modes

This document is a planning artifact with no runtime dependencies. The failure modes apply to the **demand tracking process** rather than a software system:

| Dependency | Failure Path | Mitigation |
|------------|-------------|------------|
| CRM tagging discipline | Sales forgets to tag requests → trigger thresholds are never met in data even when demand is real | Weekly review cadence; designated owner checks for untagged deals |
| Customer-facing language drift | Sales reps freelance commitments not in this doc → legal exposure | Train new sales hires on this doc; include in onboarding checklist |
| Trigger threshold stale | ARR thresholds set here become too conservative as deal size grows | Quarterly reassessment cadence (§9) |
| Spreadsheet as tracking tool | Spreadsheet is lost or not shared → demand data lost | Store in shared drive with edit history; migrate to CRM as first priority when sales team grows past 2 people |

---

## 11. Risks of Building Too Early (Summary)

| Capability | Primary Early-Build Risk |
|-----------|-------------------------|
| SSO/SAML | CVE surface + IdP-specific bugs + session semantics rewrite |
| SCIM | Schema lock-in before membership model validated by real usage |
| Custom MSA | Legal bandwidth drain + precedent risk for all future negotiations |
| BAA | Full HIPAA compliance scope triggered across entire platform |
| PO invoicing | Cash flow risk from NET-30+ without AR tooling |
| Enterprise SLA | Legal liability without reliability infrastructure to back the commitment |
| On-premises | Support surface explosion; each customer environment is unique |

**Core principle:** Deferred capabilities should be explicitly and consistently declined — not vaguely promised — until a trigger threshold is crossed. Vague promises create expectation mismatches that damage trust more than a clean "not yet."

---

## Related Documents

- [Enterprise Readiness Capability Map](./enterprise-readiness-capability-map.md) — tier classification for all enterprise capabilities
- [Roles, Permissions, and Audit Events](./roles-permissions-audit-events.md) — RBAC model and audit event catalog
- [Data Retention, Export, and Compliance Evidence](./data-retention-export-compliance-evidence.md) — retention schedules, GDPR/CCPA/SOC2 framework boundaries, evidence pack assembly
