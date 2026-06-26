# Enterprise Readiness Capability Map

**Version:** 1.0  
**Date:** 2026-06-25  
**Milestone:** M003-lp54mb — Self-Service Commercial Launch  
**Slice:** S07 — Enterprise Ready Foundations  
**Status:** Planning artifact (not yet implemented)

---

## Purpose

This document classifies every enterprise capability into one of four readiness tiers so that the product team can ship the self-service launch without overbuilding, while leaving clear on-ramps for larger accounts.

| Tier | Label | Meaning |
|------|-------|---------|
| **L** | Launch Blocker | Must exist at GA or no customer can safely use the product. |
| **F** | Early Foundation | Not required at launch but must be architected correctly now so the upgrade path is not a rewrite. Typically adds a column, an event, or a policy boundary. |
| **FF** | Fast-Follow | Implement within the first 90 days post-launch as the first enterprise customer signals arrive. |
| **D** | Deferred | Explicitly out of scope until meaningful enterprise pipeline appears. Safe to skip. |

---

## 1. Roles and Permissions

| # | Capability | Tier | Rationale | Dependency |
|---|-----------|------|-----------|------------|
| R01 | Organization owner role (full admin access to org settings, billing, members, all projects) | **L** | Self-service requires at least one owner per org or the org is abandoned on payment failure. | S03 org/membership model |
| R02 | Project admin role (manage project members, tokens, uploads within a project) | **L** | Contractor workflow requires delegated project scope without billing access. | S03 token scoping |
| R03 | Viewer role (read-only dashboard and report access) | **F** | Needed when a buyer shares a report with a non-billing stakeholder. Add a membership role enum now; enforce in API gates. | S04 portfolio dashboard |
| R04 | Billing admin role (separate from org owner — manage payment method and invoices, no project access) | **FF** | Finance team access pattern emerges once an account has 5+ projects. | S03 billing custody |
| R05 | Contractor role (upload-only, no dashboard, no report download) | **L** | Upload token already scopes contractors to upload-only; make this role explicit in membership so it appears in audit logs. | S03 token authorization |
| R06 | Support/operator role (internal read-only view of org/project/scan state, no PII beyond IDs) | **F** | Needed from day one for support diagnostics but should be an internal role with access controls. | S03 support diagnostics |
| R07 | RBAC policy engine (attribute-based, fine-grained permission rules) | **D** | Unjustified until there are role conflicts the fixed role set cannot express. Deferred to enterprise tier. | None |

**Audit events required at launch (L):** `member_invited`, `member_role_changed`, `member_removed`, `owner_transferred`.  
**Audit events required as foundation (F):** `support_operator_accessed_org`.

---

## 2. Organization and Project Membership

| # | Capability | Tier | Rationale | Dependency |
|---|-----------|------|-----------|------------|
| M01 | Single-org, single-owner creation (current signup flow) | **L** | Core primitive established in S03. | S03 |
| M02 | Multi-member org (invite by email, role assignment, accept/decline) | **FF** | Required once a buyer wants a colleague to access reports without sharing login. | S03 membership model |
| M03 | Project-scoped membership (member in project P but not project Q within same org) | **FF** | Required for contractor segmentation across multiple vendor projects. | S03 project ownership |
| M04 | Org-level SSO directory sync (SCIM user provisioning/deprovisioning) | **D** | Explicit deferral. Requires SAML/OIDC SSO as prerequisite. See §4. | SSO (§4) |
| M05 | Cross-org collaboration (shared report link, guest access token) | **D** | No validated demand. Deferred until a specific buyer request. | None |

**Foundation requirement:** Membership table must include `role` column and `invited_by_account_id` from the start (S03 specified this). Do not add membership as a side effect of org creation; model it as a first-class join with status (`pending`, `active`, `revoked`).

---

## 3. Audit Log

| # | Capability | Tier | Rationale | Dependency |
|---|-----------|------|-----------|------------|
| A01 | Structured event log for all admin actions (billing changes, member changes, token lifecycle, project/policy changes) | **L** | Required for any security questionnaire. Without it, no enterprise prospect will trust the product even informally. | S03 token/billing events |
| A02 | Support/operator access events (logged when an operator reads an org or scan record) | **F** | Add event type and internal audit table; not customer-visible at launch but required before first security review. | S03 diagnostics |
| A03 | Customer-visible audit log UI (self-serve access to own org events) | **FF** | Buyers ask "can I see who accessed my reports?" quickly after first paid use. | A01 |
| A04 | Audit log export (CSV/JSON download with date range filter) | **FF** | Required for compliance-conscious buyers within 90 days. Depends on A01. | A01 |
| A05 | Immutable audit log with retention lock | **D** | SOC 2 Type II controls requirement — not needed for self-service launch. Deferred to compliance tier. | A01 |
| A06 | SIEM webhook integration (push audit events to Splunk/Datadog) | **D** | Enterprise-only. No self-service buyer needs this. | A01 |

**Mandatory event shape (all events):**
```
{
  "event_id": "<uuid>",
  "event_type": "<namespace>.<action>",
  "occurred_at": "<ISO8601>",
  "actor_account_id": "<id or 'system'>",
  "org_id": "<id>",
  "resource_type": "<account|org|project|token|upload|report|subscription|policy>",
  "resource_id": "<id>",
  "outcome": "<success|failure>",
  "failure_reason": "<enum or null>",
  "ip_address": "<hashed or null — no plaintext PII in logs>"
}
```

**Auditable events at launch (L):**

| Event Type | Trigger |
|-----------|---------|
| `account.created` | New account registered |
| `account.email_verified` | Email confirmed |
| `account.password_changed` | Password reset or update |
| `account.mfa_enrolled` | TOTP/passkey added |
| `account.mfa_removed` | TOTP/passkey removed |
| `org.created` | Org created (first account creates org) |
| `org.subscription_activated` | Entitlement gate opened after verified webhook |
| `org.subscription_cancelled` | Customer-initiated cancellation |
| `org.subscription_past_due` | Payment failure after grace period |
| `org.member_invited` | Invitation sent |
| `org.member_role_changed` | Role updated |
| `org.member_removed` | Member deprovisioned |
| `project.created` | New project created |
| `project.deleted` | Project deleted |
| `token.issued` | Upload token created |
| `token.rotated` | Upload token rotated |
| `token.revoked` | Upload token revoked |
| `upload.received` | Scan artifact received and validated |
| `upload.rejected` | Scan artifact rejected (with `failure_reason`) |
| `report.generated` | Acceptance report rendered |
| `report.downloaded` | Report PDF/link accessed |
| `report.shared` | Report shared via link |
| `policy.applied` | Policy evaluated with outcome |
| `support.access_granted` | Support operator viewed a case (internal) |

---

## 4. SSO and Identity Federation

| # | Capability | Tier | Rationale | Dependency |
|---|-----------|------|-----------|------------|
| S01 | Email/password authentication with MFA (TOTP) | **L** | Required for all accounts. | None |
| S02 | OAuth social login (GitHub, Google) | **FF** | Reduces friction for developer-first buyers. | Auth provider |
| S03 | SAML 2.0 SSO (customer IdP integration) | **D** | Explicit deferral. See §SSO Deferral Handling below. | None |
| S04 | OIDC / OpenID Connect SSO | **D** | Explicit deferral. Same deferral path as SAML. | None |
| S05 | Just-in-Time (JIT) provisioning on SSO login | **D** | Requires SSO prerequisite. | S03/S04 |
| S06 | SCIM directory sync | **D** | Requires SSO + multi-member org. High implementation cost. | S03/S04, M04 |
| S07 | Passkey (WebAuthn) authentication | **FF** | Strong MFA replacement, increasingly expected by security buyers. | Auth provider |

**SSO Deferral Handling:**

When a prospect asks about SSO before it is built, use this language:

> "ez-appsec currently supports email/password with MFA and is adding OAuth social login. SAML SSO is on our roadmap for accounts with 20+ seats or a compliance requirement. If SSO is a hard gate for procurement, please contact us — we track demand to prioritize it."

**Trigger criteria for un-deferring SSO:**
- Three or more prospects block purchase on SSO requirement, or  
- Single account >20 seats requests SSO, or  
- Enterprise security questionnaire flags SSO as mandatory control.

**Architecture invariant:** The `auth_provider` field must exist on the account or session record from launch. Hard-coding `email` now means a future SSO migration rewrites session handling. Add `auth_provider: enum('email', 'github_oauth', 'google_oauth', 'saml', 'oidc')` and `external_identity_id: nullable string` as foundation columns (F).

---

## 5. Data Retention and Export

| # | Capability | Tier | Rationale | Dependency |
|---|-----------|------|-----------|------------|
| DR01 | Default retention: scan/upload data 90 days raw, 365 days aggregated metrics (per S06 ops model) | **L** | Required to avoid unlimited storage accumulation and to set customer expectations. Publish in TOS/privacy policy. | S05 data model |
| DR02 | Report PDF stored for 12 months post-generation | **L** | Buyers need to retrieve reports after contractor work is accepted. | S05 storage |
| DR03 | Customer-initiated data export (org + project + upload + report metadata as JSON/CSV) | **FF** | GDPR/CCPA data portability. Required within 90 days. | S03 ownership model |
| DR04 | Deletion on cancellation (hard delete of PII, anonymize aggregates within 30 days) | **F** | GDPR/CCPA deletion. Policy must be in TOS at launch; implementation can follow within 30 days. | S03 account lifecycle |
| DR05 | Right-to-erasure for individual accounts | **FF** | GDPR Article 17. Required for EU customers. | DR04 |
| DR06 | Retention lock (hold data beyond retention period for legal/litigation) | **D** | Enterprise legal feature. No demand at self-service launch. | DR01 |
| DR07 | Cross-region data residency (EU-only or US-only storage selection) | **D** | Requires multi-region infrastructure. Defer until EU enterprise demand. | None |

**Retention defaults to publish at launch (L):**

| Data Type | Default Retention | Action at Expiry |
|-----------|-----------------|----------------|
| Raw scan upload artifacts | 90 days | Hard delete |
| Scan findings (normalized) | 90 days | Hard delete |
| Report PDFs | 12 months from generation | Hard delete |
| Aggregate metrics (counts) | 365 days | Hard delete |
| Audit events | 365 days | Hard delete |
| Billing history (invoice refs) | 7 years | Anonymize non-billing fields |
| Account PII (name, email) | Until deletion request or 30 days post-cancellation | Hard delete |

---

## 6. Security Questionnaire Evidence

| # | Capability | Tier | Rationale | Dependency |
|---|-----------|------|-----------|------------|
| Q01 | Vendor security summary (1–2 page document: architecture, data custody, encryption, audit controls, vulnerability disclosure) | **F** | Needed for the first enterprise prospect inquiry. Can be generated from existing S02–S06 artifacts. | S02, S03, S05 |
| Q02 | Sub-processor list (Stripe, AWS, any email/SaaS tooling) | **F** | GDPR Article 28, standard DPA requirement. Publish on docs page. | S03 billing custody |
| Q03 | Penetration test certificate or bug bounty statement | **FF** | Required by most InfoSec teams before approving SaaS use. Schedule within 90 days. | None |
| Q04 | SOC 2 Type I report | **D** | 6–12 month preparation. Defer until enterprise pipeline justifies cost (~$15–30K). | A01, DR01 |
| Q05 | SOC 2 Type II report | **D** | 12–18 month timeline. Deferred. | SOC 2 Type I |
| Q06 | ISO 27001 certification | **D** | 18–24 month timeline. Deferred. | SOC 2 Type II |
| Q07 | HIPAA BAA | **D** | Health data. Out of scope for contractor code assurance. Permanent deferral unless product pivots. | N/A |

**Questionnaire evidence producible from current architecture (S02–S06):**

| Question | Source | Readiness |
|----------|--------|-----------|
| What data do you store about our developers? | S03 account/org model, S05 data model | Ready |
| How are upload tokens protected? | S03 token lifecycle (write-only, hashed, scoped) | Ready |
| How are reports protected? | S05 storage, S02 report boundaries | Ready |
| What are your data retention periods? | DR01–DR02 (§5 above) | Ready at launch |
| Who can access our data at your company? | A02 support access events | Foundation (F) |
| Do you have audit logs? | A01 event log | Ready at launch |
| What is your vulnerability disclosure process? | Q03 bug bounty statement | Fast-follow |
| What compliance certifications do you have? | None yet | Deferred — honest answer |

---

## 7. DPA Posture (Data Processing Agreement)

| # | Capability | Tier | Rationale | Dependency |
|---|-----------|------|-----------|------------|
| DPA01 | Standard DPA template (covering GDPR Article 28 obligations: processor role, purpose limitation, sub-processors, deletion obligations, security measures, audit rights) | **FF** | Required for any EU customer or any customer whose legal team is engaged. Prepare template early; do not negotiate on the first request. | Q02 sub-processor list |
| DPA02 | Counter-party DPA review and negotiation | **D** | Custom DPA negotiation is a high-touch legal activity. Defer until annual contract value justifies it ($10K+ ACV). | DPA01 |
| DPA03 | EU Standard Contractual Clauses (SCCs) addendum | **FF** | Required for EU data transfers. Can be attached to standard DPA. | DPA01 |
| DPA04 | US State Privacy law addendums (CCPA, VCDPA, etc.) | **FF** | Required for US-based enterprise customers with California employees or users. | DR04 deletion |

**DPA response guidance before DPA01 is available:**

> "We are finalizing our standard Data Processing Agreement. In the interim, our data handling is governed by our Privacy Policy, which covers your GDPR obligations. We can share our sub-processor list and security summary on request. Custom DPA negotiation is available for accounts above [threshold]."

---

## 8. Compliance Framework Mapping

| # | Framework | Tier | Mapping Scope | Non-Goals |
|---|-----------|------|--------------|-----------|
| CF01 | GDPR (Regulation EU 2016/679) | **F** | Data minimization (S03), deletion (DR04), DPA (DPA01), sub-processor disclosure (Q02), audit logs (A01). Publish privacy policy at launch. | Not a GDPR certification. ez-appsec is a data processor, not a controller, for scan artifact content. |
| CF02 | CCPA / CPRA (California) | **FF** | Data subject access rights (DR03), deletion (DR04), do-not-sell disclosure. | Selling data is not part of the business model; CCPA compliance reduces to disclosure + deletion path. |
| CF03 | SOC 2 Trust Services Criteria | **D** | Security (CC6–CC9), Availability (A1), Confidentiality (C1). Requires A01 immutable log, DR01 retention controls, formal access review, and vendor management. | Not required at self-service launch. |
| CF04 | ISO 27001 | **D** | Information security management system. Requires formal ISMS, risk registry, and evidence program. | 18–24 months from decision to certification. |
| CF05 | NIST CSF / 800-53 | **D** | US federal/defense-adjacent customers. Out of scope unless customer industry requires it. | |
| CF06 | PCI DSS | **D** | Payment card data. ez-appsec does not store card data (S03 hosted billing custody). Zero scope. | Permanent deferral. |
| CF07 | FedRAMP | **D** | US government cloud authorization. Multi-year effort. Not a current market. | |

**Compliance evidence surfaces available from M003 primitives (S02–S06):**

| Evidence Type | Source Primitive | Available At |
|--------------|-----------------|-------------|
| Data flow map | S03 custody model + S05 data model | Foundation (F) — draft at launch |
| Sub-processor list | S03 billing: Stripe; S05 storage: AWS S3/RDS | Foundation (F) |
| Data retention schedule | DR01–DR02 (§5) | Launch (L) |
| Audit event log | A01 (§3) | Launch (L) |
| Deletion/erasure capability | DR04–DR05 | Fast-follow (FF) |
| Security policy document | Q01 vendor summary | Foundation (F) |
| Access control documentation | R01–R06 (§1) | Foundation (F) |
| Incident response plan | S06 ops runbooks | Foundation (F) — adapt from S06 |

---

## 9. Observability Events Named as Required from Day One

The following events must be instrumented before the first paid customer goes live. They form the audit surface for any future compliance inquiry, security review, or support escalation.

**Group A: Account and Auth Events**
- `account.created`, `account.email_verified`, `account.password_changed`
- `account.mfa_enrolled`, `account.mfa_removed`
- `account.login_succeeded`, `account.login_failed` (with failure_reason: bad_password, mfa_failed, account_locked)
- `account.session_terminated`

**Group B: Org and Member Events**
- `org.created`, `org.member_invited`, `org.member_role_changed`, `org.member_removed`
- `org.owner_transferred`

**Group C: Billing and Entitlement Events**
- `org.subscription_activated`, `org.subscription_cancelled`, `org.subscription_past_due`
- `org.subscription_refunded`, `org.entitlement_gate_denied` (with resource attempted)

**Group D: Token Events**
- `token.issued`, `token.rotated`, `token.revoked`, `token.authorization_failed` (with failure_reason)

**Group E: Upload and Report Events**
- `upload.received`, `upload.rejected`, `upload.processing_started`, `upload.processing_failed`
- `report.generated`, `report.generation_failed`, `report.downloaded`, `report.shared`

**Group F: Policy Events**
- `policy.applied` (with outcome: pass/warning/blocked/unknown, category, decision_reason)

**Group G: Support Access Events (internal, not customer-visible)**
- `support.org_accessed` (operator_id, org_id, purpose_code)
- `support.scan_accessed`
- `support.report_accessed`

**SSO failure events (foundation, to be added when SSO is built):**
- `sso.login_failed` (with failure_reason: saml_assertion_invalid, user_not_provisioned, idp_timeout)
- `sso.provisioning_failed`
- `sso.session_expired`

---

## 10. Prioritized Implementation Handoff

### Phase 1 — Launch (GA Required)

1. Implement A01 audit event log with Groups A–G event types and mandatory event shape.
2. Implement R01 (org owner), R02 (project admin), R05 (contractor/upload-only) roles.
3. Publish DR01–DR02 retention schedule in TOS/Privacy Policy.
4. Implement S01 MFA (TOTP) for all accounts.
5. Enforce upload token scoping (scope = upload-only, bound to project) per S03.

### Phase 2 — Early Foundation (Architecture Now, Not Shipped Yet)

1. Add `auth_provider` + `external_identity_id` columns to account/session schema (unblocks future SSO without rewrite).
2. Add `role` column to membership table with enum(owner, billing_admin, project_admin, viewer, contractor, support_operator).
3. Create A02 internal audit trail for support operator access (table only, not customer-visible yet).
4. Draft Q01 vendor security summary from S02–S06 artifacts.
5. Draft Q02 sub-processor list; publish on docs page.
6. Write DR04 deletion policy into TOS; flag deletion handler in backlog for 30-day post-GA sprint.
7. Draft CF01 GDPR privacy policy with data minimization, deletion, and sub-processor clauses.

### Phase 3 — Fast-Follow (0–90 Days Post-Launch)

1. A03/A04 customer-visible audit log with export.
2. M02 multi-member org invitations.
3. M03 project-scoped membership.
4. DR03 data export (GDPR/CCPA portability).
5. DR05 right-to-erasure handler.
6. S02 OAuth social login (GitHub, Google).
7. S07 passkey authentication.
8. DPA01 standard DPA template + DPA03 EU SCCs.
9. DPA04 US state privacy addendums.
10. Q03 penetration test or bug bounty statement.
11. R04 billing admin role.

### Phase 4 — Deferred (Post Enterprise Pipeline)

| Capability | Trigger to Un-defer |
|-----------|-------------------|
| SAML/OIDC SSO (S03, S04) | 3+ prospects blocked on SSO, or 1 account >20 seats |
| SCIM provisioning (M04) | SSO live + 3+ orgs requesting auto-provisioning |
| RBAC engine (R07) | Fixed roles cannot express a real customer requirement |
| A05 immutable log / retention lock | SOC 2 Type II pursuit |
| A06 SIEM integration | Enterprise prospect requires it for contract |
| DR06 retention lock | Legal/litigation hold requirement from a customer |
| DR07 cross-region data residency | EU enterprise contract where US storage is blocked |
| SOC 2 Type I (Q04) | Enterprise pipeline > $100K ARR in 3+ accounts |
| SOC 2 Type II (Q05) | SOC 2 Type I complete + same pipeline threshold |
| ISO 27001 (CF04) | EU enterprise market pursuit |
| DPA02 custom DPA negotiation | Account ACV > $10K |

---

## 11. Risk Assessment

| Risk | Impact | Likelihood | Mitigation |
|------|--------|-----------|-----------|
| No audit log at launch — enterprise prospect blocks on first security review | High | High | A01 is launch blocker (L). Non-negotiable. |
| Auth provider column missing — SSO migration requires schema migration on live data | High | Medium | Add `auth_provider` enum column as foundation (F) before GA. |
| No DPA at first EU inquiry — deal stalls or breaks | Medium | High | Prepare DPA01 template in Phase 3 (FF), not when first asked. |
| Deletion policy in TOS but no deletion handler — GDPR violation | High | Medium | TOS at launch (L), handler within 30 days (F). |
| SSO built for a single deal before 3+ prospects confirm demand | Low | Medium | Use deferral language in §4. Track demand explicitly. |
| SOC 2 pursued too early — 6–12 months dev time, $15–30K cost | Medium | Low | Defer until >$100K ARR enterprise pipeline. |

---

## Appendix: Dependency Links to M003 Slices

| Capability Group | Depends On | Key Artifact |
|----------------|-----------|-------------|
| Roles (§1) | S03 org/membership model | S03-CONTEXT.md §Membership |
| Org Membership (§2) | S03 membership table | S03-CONTEXT.md §Organization |
| Audit Log (§3) | S03 token/billing events, S05 upload events | S03-CONTEXT.md §Observability; S05-CONTEXT.md |
| SSO (§4) | S03 account schema | S03-CONTEXT.md §Account |
| Data Retention (§5) | S05 data model, S06 ops metrics retention | S05-CONTEXT.md; S06 operations-dashboard-metrics.md |
| Questionnaire Evidence (§6) | S02 policy/report boundaries, S03 custody, S05 model | S02-CONTEXT.md; S03-CONTEXT.md |
| DPA (§7) | S03 sub-processor identification | S03-CONTEXT.md §Billing |
| Compliance Mapping (§8) | S02–S06 all slices | M003 milestone context |
| Observability Events (§9) | S03 event list, S06 ops events | S03-CONTEXT.md; S06 ops-dashboard-metrics.md |
| Implementation Handoff (§10) | All S02–S07 | This document |
