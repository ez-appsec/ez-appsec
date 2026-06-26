# Data Retention, Export, and Compliance Evidence

**Version:** 1.0  
**Date:** 2026-06-25  
**Milestone:** M003-lp54mb — Self-Service Commercial Launch  
**Slice:** S07 — Enterprise Ready Foundations  
**Status:** Planning artifact (not yet implemented)  
**Depends on:** `enterprise-readiness-capability-map.md` §5 (DR01–DR07), §6 (Q01–Q07), §8 (CF01–CF07)

---

## Purpose

This document specifies the operational details behind the retention, export, deletion, and compliance evidence tiers established in the enterprise readiness capability map. It identifies the **source data** for each behavior, the **owner action** (what the customer or their admin can trigger), the **support action** (what an internal operator can do), and the explicit **non-goals** (what is out of scope at launch).

It is the authoritative reference for engineering, legal, and support when translating DR/Q/CF tier decisions into actual system behavior.

---

## 1. Data Retention Defaults

### 1.1 Retention Schedule

| Data Type | Source Primitive | Default Retention | Expiry Action | Tier |
|-----------|-----------------|------------------|---------------|------|
| Raw scan upload artifacts (SBOM, manifest files) | S05 object storage (S3) | 90 days from upload | Hard delete from object storage | **L** |
| Scan findings (normalized, structured) | S05 findings table | 90 days from upload date | Hard delete from DB | **L** |
| Report PDFs | S05 object storage (S3) | 12 months from `report.generated` event | Hard delete from object storage | **L** |
| Aggregate scan metrics (finding counts, pass/fail totals) | S06 metrics store | 365 days | Hard delete | **L** |
| Audit events | Audit event log (A01) | 365 days from `occurred_at` | Hard delete | **L** |
| Billing history (invoice references, subscription events) | S03 billing via Stripe; internal billing_events table | 7 years (legal minimum) | Anonymize: null PII fields, retain amount + date + org_id | **L** |
| Account PII (name, email, hashed password) | S03 accounts table | Until deletion request, or 30 days post-cancellation | Hard delete of PII columns; retain anonymized account ID for referential integrity | **F** |

**Owner action:** None required. Retention is automatic. Owners can trigger early deletion via the account deletion flow (DR04/DR05, Fast-Follow).  
**Support action:** Support operators cannot override retention periods or recover deleted data. Operators can query audit events for their own 365-day window.  
**Non-goals:** Per-project retention overrides, litigation holds (DR06), cross-region residency (DR07). Not available at launch.

### 1.2 Retention Publication Requirement (Launch Blocker)

The retention schedule must be published in the TOS and Privacy Policy before GA. The table in §1.1 above is the source of truth. Legal should reference DR01 (raw uploads), DR02 (reports), A01 (audit events), and the 7-year billing hold as the explicit commitments.

### 1.3 Deletion Jobs

Deletion is executed by a scheduled background job (`retention_cleanup`) that runs nightly and deletes rows/objects where `created_at` or `occurred_at` exceeds the retention window.

| Job | Target | Query Pattern | Failure Behavior |
|-----|--------|--------------|-----------------|
| `retention_cleanup` | uploads, findings, reports, audit_events | `WHERE created_at < NOW() - INTERVAL` | Log job failure as `retention.cleanup_failed` alert; do not retry silently. Next nightly run picks up missed rows. |
| `billing_anonymize` | billing_events older than 7 years | `WHERE event_date < NOW() - INTERVAL '7 years'` | Same failure behavior. PII fields: name, email, card_last4. Amount and date are retained. |

**Observability:** The `retention_cleanup` job must emit a structured log entry on completion:
```json
{
  "event": "retention.cleanup_completed",
  "job_run_id": "<uuid>",
  "ran_at": "<ISO8601>",
  "rows_deleted": { "uploads": 0, "findings": 0, "audit_events": 0 },
  "objects_deleted": { "upload_artifacts": 0, "report_pdfs": 0 },
  "errors": [],
  "duration_ms": 0
}
```
If `errors` is non-empty, page oncall. The absence of this log entry for >25 hours must also alert.

---

## 2. Customer Data Export

### 2.1 Export Scope and Format

Customer export (DR03, Fast-Follow) packages all org data that the customer owns. This is the GDPR/CCPA data portability response surface.

| Data Category | Source Table / API | Export Format | Fields Included | Fields Excluded |
|--------------|-------------------|--------------|----------------|-----------------|
| Account profile | `accounts` | JSON | `id`, `email`, `created_at`, `auth_provider` | hashed password, salt, internal flags |
| Org metadata | `orgs` | JSON | `id`, `name`, `created_at`, `subscription_status` | internal billing refs |
| Org membership | `memberships` | JSON | `account_id`, `role`, `status`, `invited_at`, `invited_by_account_id` | internal admin flags |
| Projects | `projects` | JSON | `id`, `name`, `created_at`, `deleted_at` | internal storage refs |
| Upload metadata | `uploads` | JSON | `id`, `project_id`, `received_at`, `filename`, `status`, `rejection_reason` | raw artifact bytes (must be downloaded separately within retention window) |
| Scan findings | `findings` | JSON + CSV | `id`, `upload_id`, `category`, `severity`, `name`, `path`, `outcome` | internal policy engine fields |
| Reports | `reports` | JSON + PDF links | `id`, `project_id`, `generated_at`, `download_url` (if within retention) | internal rendering metadata |
| Audit events | `audit_events` | JSON | all event fields per canonical shape (§3 of `roles-permissions-audit-events.md`) | none — full export |
| Tokens | `tokens` | JSON | `id`, `project_id`, `name`, `created_at`, `revoked_at`, `last_used_at` | hashed token value |

**Owner action:** Org owner initiates export via dashboard settings > "Export my data" or via support request. Export is generated as a `.zip` containing one JSON file per category and a README explaining each file.  
**Support action:** Support operator can trigger an export on behalf of a verified owner (after identity confirmation). Export link is emailed to the owner's verified address only — support cannot download the export.  
**Non-goals:** Export does not include raw artifact bytes (SBOM files). Owners must download raw artifacts individually while within the 90-day window. Export does not include other customers' data, system-internal logs, or Stripe payment method details.

### 2.2 Export Delivery and SLA

| Step | Behavior | SLA |
|------|----------|-----|
| Request received | Export job queued | Immediate |
| Export generated | Zip assembled and stored in temporary encrypted location | ≤ 24 hours |
| Notification | Email to owner's verified address with one-time download link | On completion |
| Link expiry | Download link expires | 7 days from generation |

**Observability:**
```json
{
  "event": "export.job_completed",
  "export_request_id": "<uuid>",
  "org_id": "<id>",
  "requested_by_account_id": "<id>",
  "initiated_by": "owner | support_operator",
  "categories_exported": ["account", "org", "projects", "uploads", "findings", "reports", "audit_events", "tokens"],
  "zip_size_bytes": 0,
  "duration_ms": 0,
  "download_link_expires_at": "<ISO8601>"
}
```

### 2.3 Audit Event for Export

Every export request and delivery must generate an audit event:

| Event | When | Actor |
|-------|------|-------|
| `export.requested` | Owner or support initiates | `actor_account_id` = requesting account |
| `export.completed` | Zip is ready and email sent | `actor_account_id` = `system` |
| `export.link_downloaded` | Owner clicks download link | `actor_account_id` = downloading account |
| `export.link_expired` | 7-day window elapsed without download | `actor_account_id` = `system` |

---

## 3. Deletion and Cancellation Behavior

### 3.1 Cancellation Flow

When an org owner cancels their subscription, the following sequence applies:

| Step | What Happens | When | Owner Visible | Reversible |
|------|-------------|------|--------------|-----------|
| 1. Cancel initiated | Subscription status → `cancelling`; Stripe cancellation webhook received | Immediately | Yes — dashboard shows "Cancelled, access until <date>" | Until period end |
| 2. Access period ends | Subscription status → `cancelled`; org locked (read-only, no uploads) | End of paid period | Yes | No |
| 3. Grace window | Org remains in read-only state; owner can export data | 30 days post-cancellation | Yes — dashboard shows countdown | Owner can reactivate |
| 4. Deletion job triggered | Hard delete of PII, scan data, reports, findings within grace window | Day 30 post-cancellation | Owner notified by email at Day 25 | No |
| 5. Anonymization | Non-PII aggregate records retained; account ID anonymized | Concurrent with step 4 | No | No |

**Owner action:** Owner receives email at Day 25 warning of upcoming deletion. Owner can export data at any point during the 30-day grace window. Owner can reactivate subscription to pause the deletion countdown.  
**Support action:** Support can extend the grace window by up to 30 additional days (maximum 60 days total) for verified edge cases (payment dispute, billing error). Support cannot stop deletion after it has been initiated.  
**Non-goals:** Indefinite grace periods. Data recovery after deletion (no soft-delete for org data). Partial cancellation (per-project data retention independent of subscription status).

### 3.2 Account Deletion (Individual — GDPR Article 17)

Individual account deletion (DR05, Fast-Follow) is distinct from org cancellation.

| Scenario | What Gets Deleted | What Is Retained | Timeline |
|----------|------------------|-----------------|----------|
| Account deleted while org has other members | Account PII (name, email, hashed password); account record anonymized; membership row set to `revoked` | Audit events referencing `actor_account_id` (anonymized to `deleted_account`); org, project, upload records | Immediate |
| Last owner deletes account | Same as above, plus triggers org cancellation flow (§3.1) | Billing history (7 years per §1.1) | Account PII immediate; org data follows cancellation schedule |
| Support-initiated deletion (verified erasure request) | Same as owner-initiated | Same as owner-initiated | Must be completed within 30 days of verified request (GDPR Art. 17 deadline) |

**Owner action:** Account settings > "Delete my account". For last-owner accounts, the UI warns that org deletion will follow.  
**Support action:** Support can process erasure requests via internal admin panel after identity verification. Must log the erasure as a `support.erasure_completed` event with the `reason_code: gdpr_art17` or `ccpa`.  
**Non-goals:** Selective erasure of specific scan results while retaining the account. Erasure of data held by sub-processors (Stripe retains billing data under their own GDPR obligations). Erasure of data that is part of an active legal hold (DR06, Deferred).

### 3.3 Deletion Observability

```json
{
  "event": "deletion.org_data_purged",
  "org_id": "<anonymized>",
  "triggered_by": "cancellation_schedule | erasure_request | admin_action",
  "purged_at": "<ISO8601>",
  "records_deleted": { "accounts": 0, "memberships": 0, "projects": 0, "uploads": 0, "findings": 0, "reports": 0 },
  "objects_deleted": { "upload_artifacts": 0, "report_pdfs": 0 },
  "errors": [],
  "duration_ms": 0
}
```

---

## 4. Compliance Evidence Packs

A compliance evidence pack is a bundle of artifacts that can be assembled from the current M003 system state to answer a security questionnaire or satisfy a compliance audit request. The following packs are producible at or shortly after GA.

### 4.1 Pack: Security Questionnaire Response (Fast-Follow)

**Purpose:** Answer the standard InfoSec vendor questionnaire sent by an enterprise buyer's security team.  
**Audience:** Prospect's Information Security or Procurement team.

| Section | Evidence Source | Available At |
|---------|----------------|-------------|
| Company overview and product description | Product website + GA marketing copy | Launch |
| Data types processed | S03 data custody model + S05 data model | Foundation (F) |
| Data storage location (region) | AWS region configured in S05 deployment | Launch |
| Encryption in transit | TLS 1.2+ enforced (S02 HTTPS enforcement) | Launch |
| Encryption at rest | AWS S3 SSE-S3 / RDS encryption | Launch |
| Access control model | `roles-permissions-audit-events.md` (T02) | Foundation (F) |
| Audit logging | `enterprise-readiness-capability-map.md` §3 (A01) | Launch |
| Data retention periods | This document §1.1 | Launch |
| Sub-processor list | Q02 (Stripe, AWS, transactional email SaaS) | Foundation (F) |
| Incident response | S06 ops runbooks (adapted as IR plan) | Foundation (F) |
| Vulnerability disclosure | Bug bounty statement (Q03) | Fast-Follow |
| Penetration testing | Scheduled pen test (Q03) | Fast-Follow |
| Compliance certifications | None at launch — honest answer per §4.4 | Deferred |

**Non-goals:** This is not a formal audit report. It is a documented set of answers that can be composed into a questionnaire response. Formal SOC 2 or ISO 27001 certification is deferred.

### 4.2 Pack: GDPR Data Subject Access Request (DSAR) Response (Fast-Follow)

**Purpose:** Satisfy a GDPR Article 15 (right of access) or Article 17 (right of erasure) request from an individual data subject.  
**Audience:** Individual (developer, contractor, buyer) whose data is processed.

| Right | Evidence / Action | Source |
|-------|-----------------|--------|
| Right of access (Art. 15) | Trigger org data export (§2.1); include account profile, audit events, membership records | Export job |
| Right of portability (Art. 20) | Same export package in JSON format | Export job |
| Right of erasure (Art. 17) | Execute account deletion flow (§3.2) within 30 days | Deletion job |
| Right to rectification (Art. 16) | Owner can update name/email in account settings | Self-service |
| Confirmation of processing | This document §1 + S03 data custody model | Planning artifact |

**Non-goals:** DSAR for data held exclusively by Stripe (card data, payment method) — Stripe is an independent controller for that data. DSARs from third parties (e.g., a competitor's employee who was scanned) — not applicable; only account holders are data subjects in this system.

### 4.3 Pack: DPA Exhibit (Fast-Follow)

**Purpose:** Satisfy Article 28 GDPR requirement for a Data Processing Agreement when a customer requests one.  
**Audience:** Customer legal / procurement.

| DPA Section | Evidence Source |
|------------|----------------|
| Description of processing (Annex I) | S03 custody model: what data, what purpose, what categories of data subjects |
| Technical and organizational measures (Annex II) | Encryption (S02), access controls (T02 roles spec), audit log (A01), retention schedule (§1.1 of this document) |
| Sub-processor list (Annex III) | Q02: Stripe (billing), AWS (compute/storage), transactional email SaaS (notifications) |
| Deletion obligations | §3.1–§3.2 of this document |
| Audit rights | Customer may request evidence pack on 30 days notice (no on-site audit at self-service tier) |

**Non-goals:** Counter-party DPA negotiation (DPA02, Deferred until ACV > $10K). Full ISMS evidence binder (requires SOC 2 preparation, Deferred).

### 4.4 Honest Capability Statements

When a prospect asks about a capability that is not yet built, use these responses rather than overpromising:

| Prospect Question | Honest Response |
|------------------|----------------|
| "Do you have SOC 2?" | "We do not have SOC 2 at this time. Our audit log, access controls, retention policy, and incident response process are in place. We are tracking demand for SOC 2 Type I and will initiate the process when our enterprise pipeline reaches the appropriate threshold." |
| "Do you support SSO?" | "We support email/password with MFA and are adding OAuth (GitHub/Google). SAML SSO is planned for accounts with 20+ seats. If SSO is a hard gate, contact us — we track demand to prioritize it." |
| "Do you have a DPA?" | "We are finalizing our standard DPA. In the interim, data handling is governed by our Privacy Policy. We can share our sub-processor list and security summary on request. Custom DPA negotiation is available for accounts above [threshold]." |
| "Can I export my data?" | "Data export (GDPR/CCPA portability) is on our roadmap within 90 days. In the interim, support can provide a manual extract on request." |
| "What are your data retention periods?" | Direct the buyer to the published retention schedule (§1.1 of this document, published in TOS). |

---

## 5. Framework Mapping Boundaries

This section defines what ez-appsec does and does not commit to for each compliance framework. The in-scope column maps to evidence that exists or will exist in M003; the non-goals column protects the team from being held to standards that have not been accepted.

### 5.1 GDPR (Foundation)

| In Scope | Non-Goals |
|---------|-----------|
| Data minimization: collecting only what is needed for scan + report | Being a data controller for customer source code content (we are a processor) |
| Deletion obligations: §3.1–§3.2 of this document | Regulating how customers process the reports they receive |
| DPA (standard template) | Custom DPA negotiation below $10K ACV |
| Sub-processor disclosure: Stripe, AWS, email SaaS | Certifying sub-processor GDPR compliance (we rely on their certifications) |
| Audit log for access control decisions | Cross-border transfer mechanism beyond SCCs |
| Privacy policy published at launch | Appointing an EU Data Protection Officer at launch (required only if large-scale processing — monitor as we grow) |

**Source primitives:** S03 account/org model, S05 data model, A01 audit log, DR01–DR05 retention/deletion, DPA01 template, Q02 sub-processor list.

### 5.2 CCPA / CPRA (Fast-Follow)

| In Scope | Non-Goals |
|---------|-----------|
| Right to know (data categories collected) | Selling personal data (not in business model — disclosure is simple) |
| Right to delete (§3.2 deletion flow) | Tracking opt-out (no behavioral advertising) |
| Right to portability / data export (§2.1) | Sensitive personal information controls (scan artifacts do not contain SSNs, health data, etc.) |
| Privacy policy disclosure for California residents | Appointing a CCPA "Do Not Sell" link (not applicable given no data sales) |

**Source primitives:** DR03 export, DR04/DR05 deletion, privacy policy.

### 5.3 SOC 2 (Deferred — Milestone Post $100K ARR Enterprise Pipeline)

| What Would Be In Scope When Pursued | Why Deferred |
|------------------------------------|--------------|
| CC6–CC9 (logical and physical access, change management) | Requires formal access review, change management process, and independent auditor |
| A1 (availability SLAs) | Requires defined uptime SLA and monitoring evidence |
| C1 (confidentiality — data classification, encryption) | Many controls are already in place but evidence collection is not systematic |
| A05 (immutable audit log / retention lock) | Architecture supports it but the tooling is not hardened |

**Trigger to un-defer:** >$100K ARR enterprise pipeline in 3+ accounts, or single account >$50K requiring SOC 2 for procurement.

**Non-goals at self-service launch:** Formal risk registry, vendor management program, formal employee security training records, SOC 2 audit engagement.

### 5.4 PCI DSS (Permanent Deferral)

ez-appsec does not store, process, or transmit cardholder data. Billing is fully delegated to Stripe (S03 hosted billing custody). PCI DSS scope is zero. Permanent deferral. If the payment model ever brings card data in-scope, re-evaluate.

### 5.5 ISO 27001 (Deferred — Post SOC 2)

Requires an Information Security Management System (ISMS) with formal risk registry, management review, and continuous evidence program. 18–24 months from decision to certification. No current EU enterprise pursuit. Defer until after SOC 2 Type I.

### 5.6 HIPAA (Permanent Deferral)

Scan artifacts in ez-appsec are software dependency manifests and SBOM files, not health records. No PHI is processed. Permanent deferral unless product pivots to health data scanning. If a customer asks: "We do not process Protected Health Information. If your use case involves PHI in the software artifacts you submit, please consult your compliance team — this tool is not HIPAA-covered."

### 5.7 FedRAMP (Deferred — Out of Addressable Market)

US government cloud authorization. Multi-year, multi-million dollar process. Not a current target market. Permanent deferral.

---

## 6. Security Questionnaire Evidence Inventory

This section maps each common vendor security questionnaire topic to the M003 artifact that answers it, so that the team can quickly assemble a questionnaire response without researching from scratch.

### 6.1 Evidence Map

| Questionnaire Topic | M003 Artifact / Source | Confidence |
|--------------------|----------------------|-----------|
| Company and product overview | Product website + GA marketing | High |
| Products and services processed | S03 data custody model | High |
| Data types collected (by category) | S03 account model, S05 data model | High |
| Data flow diagram | S03 custody model (described); diagram to be generated in Q01 pack | Medium — needs diagramming |
| Storage location (region) | S05 deployment config (AWS region) | High |
| Encryption in transit | S02 HTTPS enforcement policy | High |
| Encryption at rest | S05 AWS S3 SSE / RDS encryption | High |
| Key management | AWS KMS (default S3 key management) | Medium — document explicitly |
| Access control to production | Internal ops runbooks (S06), IAM policies | Medium — needs formal doc |
| Role-based access control | `roles-permissions-audit-events.md` (T02 artifact) | High |
| Multi-factor authentication requirement | S01 MFA enforcement (TOTP) — `enterprise-readiness-capability-map.md` §4 | High |
| Audit logging | A01 audit event log — `enterprise-readiness-capability-map.md` §3 | High |
| Log retention | 365 days (§1.1 of this document) | High |
| Monitoring and alerting | S06 `operations-dashboard-metrics.md` | High |
| Incident response process | S06 ops runbooks (adapted as IR plan) | Medium — needs formal IR doc |
| Vulnerability management | Dependency scanning process (internal); Q03 bug bounty (FF) | Low at launch → FF |
| Penetration testing | Not yet performed — scheduled in FF (Q03) | Low at launch → FF |
| Sub-processor list | Q02: Stripe, AWS, transactional email SaaS | High — needs published page |
| Data retention schedule | §1.1 of this document, TOS at launch | High |
| Data deletion on cancellation | §3.1 of this document, TOS | High at policy level; Medium for implementation |
| GDPR compliance | §5.1 of this document, Privacy Policy | Medium — no certification |
| SOC 2 report | Not available — see §4.4 honest statement | N/A at launch |
| Business continuity / DR | S06 ops model; RTO/RPO to be defined | Low — needs formal BCP |
| Employee background checks | HR process — not currently formalized | Low — needs HR documentation |
| Security awareness training | Not currently formalized | Low — needs training records |

### 6.2 Questionnaire Readiness Tiers

| Readiness | Count | Topics |
|-----------|-------|--------|
| **High** — answerable now from existing M003 artifacts | 14 | Encryption, storage, roles, MFA, audit log, retention, sub-processors, monitoring |
| **Medium** — answerable with minor documentation work (data flow diagram, formal IR doc) | 6 | Data flow, key management, access to production, incident response, GDPR statement, deletion implementation |
| **Low** — honest gap requiring Fast-Follow work or honest "not yet" answer | 6 | Pen test, vulnerability management, SOC 2, BCP, employee checks, security training |

---

## 7. Observability Surfaces for Retention, Export, and Deletion

| Surface | Event / Log | Owner | Alerting |
|---------|-------------|-------|---------|
| Retention cleanup job completion | `retention.cleanup_completed` (§1.3) | Platform | Alert if absent >25 hours |
| Retention cleanup errors | `retention.cleanup_failed` in errors array | Platform | Page oncall immediately |
| Export job completion | `export.job_completed` (§2.2) | Platform | Alert if job pending >24 hours |
| Export link downloaded | `export.link_downloaded` audit event | Audit log | No alert; visible in customer audit log |
| Org data purged | `deletion.org_data_purged` (§3.3) | Platform | Alert on any `errors` in payload |
| Account erasure completed | `support.erasure_completed` audit event | Support ops | No alert; audit trail for compliance |
| GDPR Art. 17 deadline missed | `deletion.erasure_deadline_exceeded` | Platform | Alert oncall + legal |

---

## 8. Non-Goals Summary

The following are explicitly out of scope for the self-service launch and the first 90 days:

| Non-Goal | Why | When to Revisit |
|----------|-----|----------------|
| Per-project retention overrides | Adds complexity with no validated demand | Post-enterprise contract requiring it |
| Litigation hold / retention lock (DR06) | Legal feature requiring separate tooling | Post SOC 2 Type I pursuit |
| Cross-region data residency (DR07) | Multi-region infrastructure; no current EU enterprise demand | EU enterprise contract blocking on US storage |
| SOC 2 audit report | 6–12 months, $15–30K; premature at self-service scale | >$100K ARR in enterprise pipeline |
| HIPAA BAA | Out of product scope | Product pivot to PHI only |
| Custom DPA negotiation | High-touch legal; not justified below $10K ACV | Per-account above threshold |
| Data recovery after deletion | No soft-delete for org data by design | Do not add — firm commitment |
| Export of raw artifact bytes (SBOM files) | Covered by direct download within 90-day retention window | Reconsider if portability audit requires it |

---

## Appendix: Cross-References

| Document | Section | Relationship |
|---------|---------|-------------|
| `enterprise-readiness-capability-map.md` | §5 (DR01–DR07) | Tier classification source for retention/export capabilities |
| `enterprise-readiness-capability-map.md` | §6 (Q01–Q07) | Questionnaire evidence tier classification |
| `enterprise-readiness-capability-map.md` | §8 (CF01–CF07) | Compliance framework tier classification |
| `roles-permissions-audit-events.md` | §3 (export audit events), §4 (failure modes) | Canonical audit event shape; export/deletion event specifications |
| S03-CONTEXT.md | Account lifecycle, billing custody | Account deletion and billing retention source |
| S05-CONTEXT.md | Data model, storage | Upload/findings/report storage source |
| S06 `operations-dashboard-metrics.md` | Ops metrics, retention metrics | Aggregate metrics retention source |
| TOS / Privacy Policy | Retention commitments | Must publish §1.1 table at launch |
