# Roles, Permissions, and Audit Events

**Version:** 1.0  
**Date:** 2026-06-25  
**Milestone:** M003-lp54mb — Self-Service Commercial Launch  
**Slice:** S07 — Enterprise Ready Foundations  
**Status:** Design specification (implementation contract)

---

## Purpose

This document is the authoritative reference for role boundaries and audit event contracts in ez-appsec. Every API gate, middleware check, and log emitter must be consistent with the tables below. It is a living document: columns do not change shape, but new rows are added as capabilities are promoted from FF/D tiers.

---

## 1. Role Definitions

Six roles exist at launch. The RBAC policy engine (attribute-based rules) is Deferred (D); all authorization is expressed as a fixed role set checked at the API gateway and service layer.

| Role | Label | Internal name | Scope | Who holds it |
|------|-------|---------------|-------|-------------|
| Organization Owner | `org_owner` | `org_owner` | Org-wide | Account that created the org; can be transferred |
| Project Admin | `project_admin` | `project_admin` | Single project | Delegated by org owner |
| Viewer | `viewer` | `viewer` | Single project | Read-only stakeholder |
| Contractor | `contractor` | `contractor` | Single project | Upload-only third party |
| Billing Admin | `billing_admin` | `billing_admin` | Org-wide billing only | Finance team delegate (FF) |
| Support Operator | `support_operator` | `support_operator` | Internal, read-only | ez-appsec staff only |

> **Billing Admin is a Fast-Follow (FF) role.** At launch the org owner holds all billing access. The `billing_admin` role row must be present in the membership role enum from day one so it can be granted without a schema migration.

---

## 2. Permission Matrix

Legend: **Y** = allowed, **N** = explicitly denied, **—** = not applicable.

### 2.1 Org-Level Actions

| Action | org_owner | billing_admin | project_admin | viewer | contractor | support_operator |
|--------|-----------|---------------|---------------|--------|------------|------------------|
| View org settings | Y | Y | N | N | N | Y (read-only) |
| Edit org name / slug | Y | N | N | N | N | N |
| Transfer org ownership | Y | N | N | N | N | N |
| Invite members to org | Y | N | N | N | N | N |
| Change member role | Y | N | N | N | N | N |
| Remove member from org | Y | N | N | N | N | N |
| View billing history / invoices | Y | Y | N | N | N | N |
| Update payment method | Y | Y | N | N | N | N |
| Cancel subscription | Y | Y | N | N | N | N |
| View subscription status | Y | Y | N | N | N | N |
| Delete org (and all data) | Y | N | N | N | N | N |

### 2.2 Project-Level Actions

| Action | org_owner | billing_admin | project_admin | viewer | contractor | support_operator |
|--------|-----------|---------------|---------------|--------|------------|------------------|
| Create project | Y | N | N | N | N | N |
| Delete project | Y | N | N | N | N | N |
| Edit project settings | Y | N | Y | N | N | N |
| Issue upload token | Y | N | Y | N | N | N |
| Rotate / revoke upload token | Y | N | Y | N | N | N |
| View token list (hashed values only) | Y | N | Y | N | N | N |
| Submit scan upload | Y | N | Y | N | Y | N |
| View scan uploads | Y | N | Y | Y | N | Y |
| View findings | Y | N | Y | Y | N | Y |
| Generate report | Y | N | Y | N | N | N |
| Download report | Y | N | Y | Y | N | N |
| Share report link | Y | N | Y | N | N | N |
| Apply / edit scan policy | Y | N | Y | N | N | N |
| View scan policy | Y | N | Y | Y | N | Y |
| View project audit events | Y | N | Y | N | N | N |
| Export project data | Y | N | N | N | N | N |

### 2.3 Support Operator Boundaries

The `support_operator` role is **internal only** — it cannot be granted to a customer account. Its access is read-only and scoped to diagnostic state; it never accesses PII beyond account IDs and org slugs.

| What the operator CAN see | What the operator CANNOT see |
|--------------------------|------------------------------|
| Org ID, org slug, subscription status | Payment method details, last 4 digits of card |
| Project list, project ID, created_at | Report content (findings text) |
| Upload receipt count, upload status | Raw upload artifacts |
| Token metadata (ID, scopes, created_at, revoked_at) | Token plaintext or hash |
| Scan run status and error codes | Finding details / SBOM content |
| Account ID, email (masked: `j***@example.com`) | Plaintext email, password, MFA secrets |
| Audit event log entries | No write access to any resource |

Every support operator page load or API read against a customer org MUST emit `support.operator_accessed_org` (see §4).

---

## 3. Audit Event Contract

### 3.1 Canonical Event Shape

Every audit event MUST conform to this shape. No field may be omitted unless marked nullable.

```json
{
  "event_id":         "<uuid v4>",
  "event_type":       "<namespace>.<action>",
  "occurred_at":      "<ISO 8601 UTC, e.g. 2026-06-25T15:00:00.000Z>",
  "actor_type":       "<account | system | support_operator>",
  "actor_id":         "<account_id | 'system' | operator_account_id>",
  "org_id":           "<org_id or null for pre-org events>",
  "project_id":       "<project_id or null>",
  "resource_type":    "<account|org|project|token|upload|report|subscription|policy|export>",
  "resource_id":      "<resource primary key>",
  "outcome":          "<success | failure>",
  "failure_reason":   "<enum value or null>",
  "ip_address":       "<SHA-256(raw_ip + daily_salt) or null — NEVER plaintext>",
  "user_agent_hash":  "<SHA-256(user_agent) or null — NEVER plaintext>",
  "metadata":         "<flat JSON object — no secrets, no PII beyond IDs>"
}
```

**Security invariants:**
- `ip_address` is always hashed with a rotating daily salt before storage. Never log plaintext IPs in audit events.
- `user_agent_hash` is a hash, not the raw string, to avoid fingerprinting PII.
- `metadata` must never contain passwords, token plaintext, payment card data, MFA codes, or unhashed emails.
- `actor_id` for system events is the literal string `"system"` — not null.
- Events emitted before org creation (e.g., `account.created`) set `org_id` to `null`.

### 3.2 Failure Reason Enum

```
bad_credentials        — wrong password or token
mfa_required           — MFA step not completed
mfa_failed             — wrong TOTP code or passkey assertion failed
account_locked         — too many failed attempts
account_unverified     — email not confirmed
rate_limited           — request rate limit exceeded
permission_denied      — insufficient role for the action
resource_not_found     — target does not exist or is hidden
subscription_required  — action requires active subscription
subscription_past_due  — payment failure blocks access
token_expired          — upload token past TTL
token_revoked          — upload token explicitly revoked
token_scope_exceeded   — token attempted action outside its granted scopes
upload_malformed       — artifact failed schema or MIME check
upload_too_large       — artifact exceeds size limit
policy_blocked         — scan policy evaluation returned block
export_quota_exceeded  — too many export requests in window
```

---

## 4. Audit Events by Category

### 4.1 Account Events

| Event Type | Trigger | Actor Type | Key Metadata Fields |
|-----------|---------|------------|-------------------|
| `account.created` | New account registered | `system` | `email_domain` (not full email) |
| `account.email_verified` | Email verification link clicked | `account` | — |
| `account.password_changed` | Password reset or in-session update | `account` | `change_method: reset\|in_session` |
| `account.mfa_enrolled` | TOTP or passkey added | `account` | `mfa_type: totp\|passkey` |
| `account.mfa_removed` | MFA factor removed | `account` | `mfa_type: totp\|passkey` |
| `account.login_succeeded` | Session established | `account` | `auth_method: password\|oauth\|saml` |
| `account.login_failed` | Authentication attempt rejected | `system` | `failure_reason` (from enum) |
| `account.session_terminated` | Logout or session expiry | `account\|system` | `termination_reason: logout\|expiry\|admin_revoke` |
| `account.deleted` | Account self-deletion | `account` | `org_count` (number of orgs owned) |

**Disallowed in metadata:** full email, password hash, MFA secret, session token.

### 4.2 Org and Membership Events

| Event Type | Trigger | Actor Type | Key Metadata Fields |
|-----------|---------|------------|-------------------|
| `org.created` | Org created | `account` | `plan: free\|starter\|pro` |
| `org.settings_updated` | Org name, slug changed | `account` | `fields_changed: [name, slug, ...]` |
| `org.owner_transferred` | Ownership moved to another account | `account` | `previous_owner_id`, `new_owner_id` |
| `org.member_invited` | Invitation email sent | `account` | `invitee_role`, `invitee_email_domain` |
| `org.member_invite_accepted` | Invitee clicks accept link | `account` | `role_granted` |
| `org.member_invite_declined` | Invitee clicks decline or invite expires | `account\|system` | `reason: declined\|expired` |
| `org.member_role_changed` | Role updated for a member | `account` | `previous_role`, `new_role`, `target_account_id` |
| `org.member_removed` | Member removed from org | `account` | `removed_account_id`, `reason: admin_action\|self_removed` |
| `org.deleted` | Org and all data deletion initiated | `account` | `project_count`, `data_deletion_scheduled_at` |

**Disallowed in metadata:** invitee full email, payment data.

### 4.3 Billing and Subscription Events

| Event Type | Trigger | Actor Type | Key Metadata Fields |
|-----------|---------|------------|-------------------|
| `subscription.activated` | Stripe webhook: payment confirmed | `system` | `plan`, `billing_period`, `stripe_subscription_id` (not card data) |
| `subscription.plan_changed` | Plan upgrade or downgrade | `account\|system` | `previous_plan`, `new_plan`, `proration_applied` |
| `subscription.cancelled` | Customer-initiated or admin cancellation | `account\|system` | `cancellation_reason`, `effective_at` |
| `subscription.past_due` | Payment failure after grace period | `system` | `failure_count`, `next_retry_at` |
| `subscription.reactivated` | Past-due subscription recovered | `system` | `previous_status: past_due` |
| `subscription.trial_started` | Free trial period begins | `system` | `trial_ends_at` |
| `subscription.trial_ended` | Trial period expired | `system` | `converted: true\|false` |

**Disallowed in metadata:** card number, CVV, full card holder name, bank account details, Stripe customer secret key.

### 4.4 Token Events

| Event Type | Trigger | Actor Type | Key Metadata Fields |
|-----------|---------|------------|-------------------|
| `token.issued` | New upload token created | `account` | `token_id`, `token_scopes`, `token_expires_at`, `project_id` |
| `token.rotated` | Token replaced with a new one | `account` | `old_token_id`, `new_token_id`, `reason: manual\|expiry` |
| `token.revoked` | Token explicitly revoked | `account` | `token_id`, `reason: manual\|policy\|member_removed` |
| `token.expired` | Token TTL elapsed (logged on first use attempt after expiry) | `system` | `token_id`, `expired_at` |
| `token.use_attempted_after_revoke` | Revoked or expired token presented | `system` | `token_id`, `failure_reason: token_revoked\|token_expired` |

**Disallowed in metadata:** token plaintext, token hash, any credential value.

### 4.5 Upload Events

| Event Type | Trigger | Actor Type | Key Metadata Fields |
|-----------|---------|------------|-------------------|
| `upload.received` | Scan artifact passed validation and stored | `account` | `upload_id`, `project_id`, `artifact_type`, `size_bytes`, `sha256_content_hash` |
| `upload.rejected` | Scan artifact failed validation | `account\|system` | `upload_id`, `project_id`, `failure_reason`, `size_bytes` |
| `upload.deleted` | Upload purged (retention expiry or manual) | `system\|account` | `upload_id`, `project_id`, `deletion_reason: retention\|manual\|org_deleted` |

**Disallowed in metadata:** raw scan artifact content, source code snippets, SBOM content.

### 4.6 Report Events

| Event Type | Trigger | Actor Type | Key Metadata Fields |
|-----------|---------|------------|-------------------|
| `report.generated` | Acceptance report rendered | `account\|system` | `report_id`, `project_id`, `upload_id`, `finding_count`, `policy_outcome` |
| `report.downloaded` | Report PDF accessed | `account` | `report_id`, `project_id`, `access_method: direct\|shared_link` |
| `report.shared` | Shareable report link created | `account` | `report_id`, `project_id`, `link_expires_at` |
| `report.share_link_revoked` | Shareable link disabled | `account` | `report_id`, `link_id` |
| `report.deleted` | Report purged (retention expiry or manual) | `system\|account` | `report_id`, `project_id`, `deletion_reason` |

**Disallowed in metadata:** finding descriptions, SBOM package names, source code paths, vulnerability detail.

### 4.7 Export Events

| Event Type | Trigger | Actor Type | Key Metadata Fields |
|-----------|---------|------------|-------------------|
| `export.requested` | Org data export initiated | `account` | `export_id`, `scope: org\|project`, `format: json\|csv`, `requested_by_account_id` |
| `export.completed` | Export file ready for download | `system` | `export_id`, `size_bytes`, `download_url_expires_at` |
| `export.downloaded` | Export file downloaded | `account` | `export_id` |
| `export.failed` | Export job failed | `system` | `export_id`, `failure_reason` |
| `export.expired` | Export download link expired without download | `system` | `export_id`, `expired_at` |

**Disallowed in metadata:** export file content, pre-signed URL after expiry.

### 4.8 Policy Events

| Event Type | Trigger | Actor Type | Key Metadata Fields |
|-----------|---------|------------|-------------------|
| `policy.created` | New scan policy saved | `account` | `policy_id`, `project_id`, `rule_count` |
| `policy.updated` | Policy rule set changed | `account` | `policy_id`, `project_id`, `previous_version_id`, `rule_diff_count` |
| `policy.deleted` | Policy removed | `account` | `policy_id`, `project_id` |
| `policy.applied` | Policy evaluated against an upload | `system` | `policy_id`, `upload_id`, `outcome: pass\|block\|warn`, `matched_rule_count` |
| `policy.evaluation_failed` | Policy engine error during evaluation | `system` | `policy_id`, `upload_id`, `failure_reason` |

**Disallowed in metadata:** policy rule expressions with embedded credentials or secrets.

### 4.9 Support Access Events

| Event Type | Trigger | Actor Type | Key Metadata Fields |
|-----------|---------|------------|-------------------|
| `support.operator_accessed_org` | Support operator reads org/project state | `support_operator` | `operator_id`, `org_id`, `resources_viewed: [org, project_list, upload_list, ...]`, `reason_code` |
| `support.operator_accessed_scan` | Operator views scan run detail | `support_operator` | `operator_id`, `upload_id`, `project_id` |
| `support.impersonation_started` | (FF) Operator assumes a user session | `support_operator` | `operator_id`, `target_account_id`, `org_id` |
| `support.impersonation_ended` | (FF) Operator session released | `support_operator` | `operator_id`, `target_account_id`, `duration_seconds` |

**Required invariant:** `reason_code` must be a non-null enum value from the support ticketing system (e.g., `customer_request`, `billing_dispute`, `incident_investigation`, `internal_qa`). Free-text reason is prohibited in structured audit fields — it goes in the support ticket, not the audit log.

**Disallowed in metadata:** ticket content, PII beyond operator ID and org ID.

---

## 5. Cross-Cutting Audit Log Rules

1. **No secrets.** Token plaintext, passwords, hashed passwords, MFA secrets, payment credentials, and pre-signed URLs (after they are used) must never appear in `metadata`.

2. **Consistent actor.** System-generated events set `actor_type: system` and `actor_id: "system"`. Events triggered by a support operator set `actor_type: support_operator` and `actor_id` to the operator's internal account ID.

3. **Outcome is mandatory.** Every event must record `success` or `failure`. Do not omit outcome for background jobs — use `system` as actor and emit the event on job completion.

4. **Idempotency key.** The `event_id` UUID is generated at emission time. Upstream callers must not re-emit an event with the same `event_id`. If a write fails, the caller generates a new `event_id` on retry.

5. **No PII mutation after write.** Audit log rows are append-only. If an email address must be anonymized (e.g., GDPR erasure), the `actor_id` field retains the account ID (anonymized at the account row) and the email is never stored in audit log metadata.

6. **Retention.** Audit events are retained for 365 days by default (DR01 tier L). Deletion after retention is hard delete, not soft. Future SOC 2 controls may extend this to 7 years — the schema must not depend on short retention assumptions.

7. **Operator events are not customer-visible at launch.** `support.*` events are stored in the same audit log table but filtered out of the customer-facing audit log UI (A03, FF). They are visible only to internal tooling.

---

## 6. Role Boundary Violations and Error Shapes

When a request is denied due to insufficient role, the API must return:

```json
{
  "error": "permission_denied",
  "message": "Your role does not permit this action.",
  "required_role": "<min role that would allow this>",
  "your_role": "<caller's current role>"
}
```

HTTP status: **403 Forbidden**.

A `permission_denied` violation MUST emit an audit event with `outcome: failure` and `failure_reason: permission_denied` before returning the 403. This ensures attempted privilege escalation appears in the audit log even when it fails.

---

## 7. Verification Checklist

The following conditions constitute a passing verification for this artifact:

- [ ] Each of the six roles has at least one explicit **Y** and at least one explicit **N** in the permission matrix.
- [ ] No role has access to another role's exclusive domain (e.g., `billing_admin` cannot create projects; `contractor` cannot view findings).
- [ ] Every audit event in §4.1–4.9 specifies `actor_type`, `resource_type`, and at least one key metadata field.
- [ ] No audit event in §4.1–4.9 includes a metadata field that contains a secret (token plaintext, password, card data, MFA code).
- [ ] The `support.operator_accessed_org` event is present and marked as required from day one (§4.9).
- [ ] The permission denial flow (§6) emits a `permission_denied` audit event.
- [ ] The failure reason enum in §3.2 covers every `failure_reason` value referenced in §4.1–4.9.

---

## 8. Failure Modes

This artifact is a design document — it has no runtime external dependencies. The failure modes below apply to the *implementation* of this contract, not to the artifact itself.

| Dependency | Failure Path | Required Handling |
|-----------|-------------|------------------|
| Audit log write path (DB insert) | Write timeout or DB connection loss | Must not block the primary operation; emit event asynchronously; surface write failure as `audit_log.write_failed` internal alert |
| IP hashing (daily salt fetch) | Salt service unavailable | Fall back to `null` for `ip_address`; never fall back to plaintext |
| Support operator `reason_code` lookup | Ticket system unavailable | Reject the support access request; log the rejection; do not allow access without a valid reason code |
| Token revocation check (on upload) | Cache miss or lookup failure | Fail closed — reject the upload with `token_revoked` failure reason until the revocation check can be confirmed |

---

## 9. Load Profile

This artifact has no runtime load dimension. The audit log write path (implemented separately) should be designed to handle 10x peak event volume by:

- Writing to a durable queue (e.g., SQS or Postgres LISTEN/NOTIFY buffer) with async flush to the audit log table.
- Rate-limiting export requests to 1 active export per org per 5 minutes (quota guard at `export.requested`).
- The audit log table should have a partial index on `(org_id, occurred_at DESC)` to keep customer-facing queries fast at 10x row density.

---

## 10. Negative Test Coverage

Audit event contracts are validated at the implementation level by negative tests. Required test cases:

| # | Scenario | Expected Outcome |
|---|----------|-----------------|
| 1 | `contractor` role attempts to download a report | 403, `permission_denied` event emitted |
| 2 | `billing_admin` (FF) attempts to create a project | 403, `permission_denied` event emitted |
| 3 | `viewer` attempts to apply a policy | 403, `permission_denied` event emitted |
| 4 | Upload token with expired TTL is submitted | 403, `token.use_attempted_after_revoke` event emitted |
| 5 | Revoked token is submitted | 403, `token.use_attempted_after_revoke` event emitted |
| 6 | Audit event emitted with plaintext IP | Test fails — IP field must be hashed |
| 7 | Audit event metadata contains a token value | Test fails — metadata scanner must reject secrets |
| 8 | Support operator access without `reason_code` | Request blocked, no `support.operator_accessed_org` emitted |
| 9 | `permission_denied` audit event missing on 403 | Integration test fails — audit log must contain the denial record |
| 10 | `org_owner` attempts to delete org with active subscription | Should be allowed; `org.deleted` event emitted with `subscription_cancelled` cascade |

---

*This document is generated as a planning artifact for M003-lp54mb / S07 / T02. Implementation must treat §3 (event shape) and §2 (permission matrix) as binding contracts.*
