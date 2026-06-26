# M003 Enterprise Handoff

**Version:** 1.0  
**Date:** 2026-06-25  
**Milestone:** M003-lp54mb — Self-Service Commercial Launch  
**Audience:** Any engineer, product manager, or reviewer picking up enterprise work after M003 GA  
**Purpose:** A fresh reader who has not seen M003 planning can use this document to determine what was built, what must be built before SSO/enterprise sales, and what has been deliberately deferred.

---

## How to Read This Document

Four tiers describe every enterprise capability:

| Tier | Label | When |
|------|-------|------|
| **L** | Launch Blocker | Must exist at GA or no customer can safely use the product |
| **F** | Early Foundation | Architected at launch; not customer-visible yet but avoids a rewrite later |
| **FF** | Fast-Follow | Ship within 90 days post-GA when the first enterprise signals arrive |
| **D** | Deferred | Explicitly out of scope until the trigger criteria in §4 are met |

If you are deciding whether to build something for an enterprise prospect, check §4 first. If a trigger threshold has been crossed, un-defer it. If not, use the deferral language in §3 and track demand.

---

## 1. What Launches at GA (L Tier)

The following capabilities are required before the first paid customer goes live. Any gap here blocks the launch.

### Authentication
- Email/password with TOTP MFA for all accounts (`account.mfa_enrolled` audit event)
- Upload token scoped to a single project, stored as a hashed value, with `token.issued` / `token.rotated` / `token.revoked` audit events

### Roles
- `org_owner` — full org access; required or the org is unmanageable on payment failure
- `project_admin` — delegated project management without billing access
- `contractor` — upload-only, no dashboard, no report download; enforced by token scope

### Audit Log (A01)
All of the following event types must be emitted before the first paid account is created. No audit log at launch means no enterprise prospect will pass a security review.

**Account events:** `account.created`, `account.email_verified`, `account.password_changed`, `account.mfa_enrolled`, `account.mfa_removed`, `account.login_succeeded`, `account.login_failed`, `account.session_terminated`

**Org/member events:** `org.created`, `org.member_invited`, `org.member_role_changed`, `org.member_removed`, `org.owner_transferred`

**Billing events:** `subscription.activated`, `subscription.cancelled`, `subscription.past_due`

**Token events:** `token.issued`, `token.rotated`, `token.revoked`, `token.use_attempted_after_revoke`

**Upload/report/policy events:** `upload.received`, `upload.rejected`, `report.generated`, `report.downloaded`, `report.shared`, `policy.applied`

**Mandatory event shape** (every event must conform to this schema):
```json
{
  "event_id":       "<uuid v4>",
  "event_type":     "<namespace>.<action>",
  "occurred_at":    "<ISO 8601 UTC>",
  "actor_type":     "<account | system | support_operator>",
  "actor_id":       "<id | 'system'>",
  "org_id":         "<id or null>",
  "project_id":     "<id or null>",
  "resource_type":  "<account|org|project|token|upload|report|subscription|policy|export>",
  "resource_id":    "<primary key>",
  "outcome":        "<success | failure>",
  "failure_reason": "<enum or null>",
  "ip_address":     "<SHA-256(ip + daily_salt) or null — NEVER plaintext>",
  "metadata":       "<flat JSON — no secrets, no PII beyond IDs>"
}
```

### Data Retention (published in TOS at launch)
| Data Type | Retention | Action at Expiry |
|-----------|-----------|-----------------|
| Raw scan uploads | 90 days | Hard delete |
| Scan findings | 90 days | Hard delete |
| Report PDFs | 12 months | Hard delete |
| Aggregate metrics | 365 days | Hard delete |
| Audit events | 365 days | Hard delete |
| Billing history | 7 years | Anonymize non-billing fields |
| Account PII | Until deletion or 30 days post-cancellation | Hard delete |

### Permission Denial Contract
Any API request rejected for insufficient role must: (1) return HTTP 403 with `{"error": "permission_denied", "required_role": "...", "your_role": "..."}`, and (2) emit an audit event with `outcome: failure, failure_reason: permission_denied`. This ensures attempted privilege escalation is always logged.

---

## 2. What Is Architected at Launch but Not Yet Customer-Visible (F Tier)

These are schema or internal changes that must be made before GA to avoid a rewrite when Fast-Follow or enterprise capabilities ship. They are not customer-facing features.

### Schema Invariants (must exist in DB before GA)
- `auth_provider` enum column on account/session: `('email', 'github_oauth', 'google_oauth', 'saml', 'oidc')` — hard-coding `email` means a future SSO migration rewrites session handling
- `external_identity_id` nullable string on account — required for SAML/OIDC JIT provisioning
- `role` enum column on membership table: `('org_owner', 'billing_admin', 'project_admin', 'viewer', 'contractor', 'support_operator')` — `billing_admin` must be present in the enum even though the role ships as FF

### Internal Support Operator Audit Trail (A02)
- `support.operator_accessed_org` event emitted every time a support operator reads any org or scan record
- Stored in the same audit log table; filtered out of customer-facing UI until A03 (FF) ships
- `reason_code` field must be a non-null enum from the support ticket system — free text is prohibited in structured audit fields

### Deletion Policy (DR04)
- GDPR/CCPA deletion obligation must be documented in TOS at launch
- The actual deletion handler (hard delete of PII, anonymize aggregates within 30 days of cancellation) can follow within 30 days of GA

### GDPR Foundation (CF01)
- Publish privacy policy with data minimization, deletion, and sub-processor clauses
- Draft the sub-processor list (Stripe, AWS S3/RDS) and publish on docs page

### Vendor Security Summary (Q01)
- Draft a 1–2 page vendor security summary from existing S02–S06 artifacts covering architecture, data custody, encryption, audit controls, and vulnerability disclosure
- This is the minimum document required for the first enterprise prospect inquiry

---

## 3. What Ships in the First 90 Days Post-GA (FF Tier)

When the first paid accounts arrive and an enterprise buyer asks a question, these are the capabilities that must be ready. Build them in parallel with early customer onboarding, not after a deal is blocked.

### Multi-Member Organizations (M02, M03)
- Org-level member invitations with role assignment and accept/decline flow
- Project-scoped membership (member in project P but not Q within the same org)

### Customer-Visible Audit Log (A03, A04)
- Self-serve customer access to their own org audit events
- CSV/JSON export with date range filter

### Data Portability and Deletion (DR03, DR05)
- Customer-initiated export: org + project + upload + report metadata as JSON/CSV
- Right-to-erasure handler (GDPR Article 17) for individual accounts

### Auth Improvements (S02, S07)
- OAuth social login (GitHub, Google) — reduces friction for developer-first buyers
- Passkey (WebAuthn) authentication — increasingly expected by security buyers

### Legal/Privacy (DPA01, DPA03, DPA04, CF02)
- Standard DPA template covering GDPR Article 28 obligations
- EU Standard Contractual Clauses (SCCs) addendum
- US state privacy addendums (CCPA, VCDPA)
- CCPA compliance: data subject access rights, deletion, and do-not-sell disclosure

### Security Posture (Q03, R04)
- Penetration test or bug bounty statement — required by most InfoSec teams
- `billing_admin` role enforcement: org owner can delegate billing access to a finance team member

---

## 4. What Is Explicitly Deferred (D Tier)

Do not build these until a trigger threshold is crossed. Building too early wastes months of engineering time on features that may never close a deal.

| Capability | Trigger to Un-defer | Notes |
|-----------|-------------------|-------|
| SAML 2.0 SSO | 3+ prospects blocked on SSO, or 1 account >20 seats, or InfoSec questionnaire flags SSO as mandatory | Use deferral language below. Track demand explicitly in CRM. |
| OIDC SSO | Same trigger as SAML | Same deferral path |
| JIT provisioning (SSO) | SSO live | Requires SSO prerequisite |
| SCIM directory sync (M04) | SSO live + 3+ orgs requesting auto-provisioning | High implementation cost |
| RBAC policy engine (R07) | Fixed roles cannot express a real customer requirement | Attribute-based rules unjustified without role conflicts |
| Immutable audit log / retention lock (A05) | SOC 2 Type II pursuit | Schema must not assume short retention |
| SIEM webhook (A06) | Enterprise contract requires it | No self-service buyer needs this |
| Retention lock / litigation hold (DR06) | Legal/litigation hold request from a paying customer | — |
| Cross-region data residency (DR07) | EU enterprise contract where US storage is a hard block | Requires multi-region infrastructure |
| SOC 2 Type I (Q04) | Enterprise pipeline > $100K ARR in 3+ accounts | $15–30K cost, 6–12 month prep |
| SOC 2 Type II (Q05) | SOC 2 Type I complete + same pipeline threshold | 12–18 months |
| ISO 27001 (CF04) | EU enterprise market pursuit | 18–24 months to certification |
| Custom DPA negotiation (DPA02) | Account ACV > $10K | High-touch legal activity |
| HIPAA BAA | Health data use case | Out of scope unless product pivots |
| FedRAMP | US government market | Multi-year effort; not a current market |
| On-premises deployment | Contractual requirement from a paying account | — |
| Enterprise SLA (99.9%+ uptime) | Enterprise contract requiring it | Requires dedicated on-call |
| PO/invoicing billing | Procurement requires it | — |

### Deferral Response Language

**When a prospect asks about SSO:**
> "ez-appsec currently supports email/password with MFA and is adding OAuth social login. SAML SSO is on our roadmap for accounts with 20+ seats or a compliance requirement. If SSO is a hard gate for procurement, please contact us — we track demand to prioritize it."

**When a prospect asks about SOC 2:**
> "We have structured audit logging, data retention controls, and a vendor security summary available on request. SOC 2 Type I is planned when our enterprise pipeline justifies the timeline and cost. We can share our security summary and sub-processor list now."

**When a prospect asks about a DPA:**
> "We are finalizing our standard Data Processing Agreement. In the interim, our data handling is governed by our Privacy Policy, which covers GDPR obligations. We can share our sub-processor list and security summary on request. Custom DPA negotiation is available for accounts above $10K ACV."

---

## 5. Verification Evidence Future Implementation Must Create

The following table identifies what the implementation team must produce as evidence that each capability works correctly. These are not optional — they are the tests and operational checks required before the S07 artifacts can be considered complete.

### Launch-Required Evidence (before GA)

| Capability | Required Evidence | Source Artifact |
|-----------|-----------------|----------------|
| Audit log event shape | Integration test: emit each event type, assert schema matches §3.1 shape; reject if `ip_address` is plaintext | `roles-permissions-audit-events.md` §3 |
| Audit log secrets gate | Test: `metadata` field scanner rejects events containing token values, passwords, or card data | `roles-permissions-audit-events.md` §10 |
| `contractor` role denial | Test: contractor token attempt to download report returns 403 + `permission_denied` audit event | `roles-permissions-audit-events.md` §10 row 1 |
| Token revocation fail-closed | Test: revoked token on upload attempt returns `token_revoked`; cache miss also blocks | `roles-permissions-audit-events.md` §8 |
| IP hashing invariant | Test: raw IP never stored; salt unavailability falls back to `null`, never plaintext | `roles-permissions-audit-events.md` §3 |
| Retention schedule | TOS/privacy policy page renders the retention table from §DR01–DR02 | `data-retention-export-compliance-evidence.md` §2 |
| Data deletion policy | TOS/privacy policy includes 30-day post-cancellation deletion commitment | `data-retention-export-compliance-evidence.md` §4 |

### Foundation Evidence (before first support access)

| Capability | Required Evidence | Source Artifact |
|-----------|-----------------|----------------|
| `auth_provider` column exists | Schema migration test: column present with correct enum values before GA deploy | `enterprise-readiness-capability-map.md` §4 |
| `billing_admin` role in enum | Schema migration test: role enum includes `billing_admin` even though role is not enforced yet | `enterprise-readiness-capability-map.md` §1 |
| Support operator access audit | Functional test: operator reads an org, `support.operator_accessed_org` event emitted with `reason_code` | `roles-permissions-audit-events.md` §4.9 |
| Support access blocked without reason_code | Test: operator access without valid ticket `reason_code` returns error, no access granted | `roles-permissions-audit-events.md` §8 row 8 |
| Vendor security summary | Document rendered and accessible at `/docs/security` or equivalent | `data-retention-export-compliance-evidence.md` §6 |
| Sub-processor list | Page published listing Stripe, AWS S3/RDS with purpose and data types | `data-retention-export-compliance-evidence.md` §6 |

### Fast-Follow Evidence (before first enterprise deal closes)

| Capability | Required Evidence | Source Artifact |
|-----------|-----------------|----------------|
| Multi-member invite | E2E test: org owner invites member, invitee accepts, `org.member_invited` + `org.member_invite_accepted` events emitted | `enterprise-readiness-capability-map.md` §2 |
| Customer audit log export | Test: export returns all org events; `support.*` events are filtered; export is JSON/CSV | `roles-permissions-audit-events.md` §5 rule 7 |
| Data portability export | Test: export includes org + project + upload + report metadata; does not include raw SBOM bytes | `data-retention-export-compliance-evidence.md` §3 |
| GDPR erasure handler | Test: erasure request deletes PII within 30 days; audit log `actor_id` retains account ID (not email) | `data-retention-export-compliance-evidence.md` §4 |
| DPA template | DPA01 document reviewed by counsel; available for EU customer signature without negotiation | `sso-procurement-deferrals.md` §DPA |
| Penetration test | Third-party pentest report available on NDA; bug bounty statement published | `enterprise-readiness-capability-map.md` §6 |

---

## 6. Compliance Framework Boundaries

What can and cannot be claimed at launch:

| Framework | What We Can Say | What We Cannot Say |
|-----------|----------------|-------------------|
| GDPR | We have audit logs, data minimization, a deletion policy, and a sub-processor list. We are a data processor, not a controller, for scan artifact content. | We are not GDPR-certified. |
| CCPA | We have data subject rights (export + deletion) and a do-not-sell statement. | No additional certification. |
| SOC 2 | We have structured audit logging and retention controls that form the foundation for SOC 2 — pursuit not yet started. | We do not have a SOC 2 report. |
| PCI DSS | We do not store payment card data. Stripe handles all payment processing. PCI scope is zero. | — |
| HIPAA | We do not handle health data. Permanent deferral unless the product pivots. | Do not accept health data without a BAA. |

---

## 7. Document Map (S07 Artifact Index)

| Document | What It Contains | Who Uses It |
|----------|-----------------|-------------|
| `enterprise-readiness-capability-map.md` | Complete capability tier table (L/F/FF/D) for all 50+ enterprise capabilities across 10 domains | Product + engineering planning |
| `roles-permissions-audit-events.md` | Binding permission matrix for 6 roles; 35 audit event types with exact field contracts; negative test table | API/auth implementation, security review |
| `data-retention-export-compliance-evidence.md` | Retention schedules, export formats, deletion/erasure flows, compliance framework mapping, security questionnaire evidence inventory | Legal, privacy, compliance, customer success |
| `sso-procurement-deferrals.md` | Customer-facing deferral language, ARR-based trigger thresholds, and demand tracking for 9 deferred capability categories | Sales, customer success, founders |
| `M003-enterprise-handoff.md` (this document) | Synthesized launch path, migration path, deferrals, and verification evidence obligations | Any new contributor; enterprise readiness review |
