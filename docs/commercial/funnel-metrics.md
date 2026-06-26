# Commercial Funnel Metrics

This document translates the S01 onboarding and offer positioning into measurable funnel stages for ez-appsec commercial operations. Each stage includes the event that proves it happened and the owner-visible metric it feeds.

## Funnel Overview

The commercial funnel operates on two parallel tracks:

1. **One-time contractor assurance**: Landing → Offer → Account → Payment → Project → Token → Scan → Report
2. **Monthly project monitoring**: Landing → Offer → Account → Subscription → Project → Token → Scan → Dashboard → Retention

Both tracks share early stages but diverge at the purchase/subscription decision point.

## Funnel Stages

### Stage 1: Landing Visitor

**Proof Event:** `landing_viewed`

**Owner-Visible Metric:** `unique_landing_visitors`

**Definition:** A unique visitor arrives at a marketplace listing, pricing page, or landing page from any channel (marketplace, search, referral, direct link).

**Implementation Notes:**
- Count unique visitors by session or device ID to avoid double-counting page reloads.
- Distinguish acquisition source where available: marketplace (Upwork/Fiverr), organic search, direct link, referral.
- This is the top of the acquisition funnel.

**Feeds:** `landing_to_offer_click` conversion metric

---

### Stage 2: Account Created

**Proof Event:** `account_created`

**Owner-Visible Metric:** `accounts_created`

**Definition:** A visitor completes account creation using external auth (email/password, magic link, or social login) and receives a default organization/workspace.

**Implementation Notes:**
- Fire event after auth provider confirms identity and ez-appsec creates the account record.
- Preserve the selected offer through signup to calculate offer-specific funnels.
- Track whether this is the user's first account or a return visitor account.

**Feeds:**
- `offer_click_to_account_created` conversion metric
- `account_created_to_payment_complete` conversion metric (for one-time offers)
- `account_created_to_subscription_started` conversion metric (for monitoring offers)

---

### Stage 3: Project Created

**Proof Event:** `project_created`

**Owner-Visible Metric:** `projects_created`

**Definition:** After payment or subscription, the customer creates their first project with required fields (project name, source type, offer context).

**Implementation Notes:**
- Fire event after project record is persisted and attached to the customer organization.
- Track offer context: contractor review, acceptance report, or monthly monitoring.
- Track source type: GitHub, GitLab, local/manual upload, or source archive.

**Feeds:**
- `payment_complete_to_project_created` conversion metric
- `subscription_started_to_project_created` conversion metric

---

### Stage 4: Token Generated

**Proof Event:** `token_generated`

**Owner-Visible Metric:** `tokens_generated`

**Definition:** System automatically generates a project-scoped upload token after project creation.

**Implementation Notes:**
- Fire event after token is hashed and stored with project ID, account/org binding, and creation timestamp.
- Label token by intended use: GitHub Actions, GitLab CI, local CLI, or manual upload.
- Track token revocation and regeneration events separately.

**Feeds:**
- `project_created_to_token_generated` conversion metric (should be 95%+ automatic)
- This is the canonical event name used across operations-dashboard-metrics.md and implementation

---

### Stage 5: First Scan Uploaded

**Proof Event:** `scan_ingestion_succeeded`

**Owner-Visible Metric:** `first_scans_uploaded`

**Definition:** Customer successfully uploads or ingests their first scan result using the upload token.

**Implementation Notes:**
- Fire event after token validation, schema validation, and successful scan summary/findings/SBOM storage.
- Track setup path used: GitHub Actions, GitLab CI, local CLI, or manual artifact upload.
- Track time from token generation to successful ingestion.

**Feeds:**
- `token_generated_to_first_upload_attempt` conversion metric
- `first_upload_attempt_to_successful_ingestion` conversion metric
- `time_to_first_scan_result` latency metric

---

### Stage 6: Report Viewed (One-time Offers)

**Proof Event:** `report_generated` or `report_downloaded`

**Owner-Visible Metric:** `reports_viewed`

**Definition:** Customer views or downloads the acceptance report for a one-time contractor assurance purchase ($20 Security Check or $50 Acceptance Report).

**Implementation Notes:**
- For the $20 Security Check: fire `report_generated` when the simple pass/warn/block result is available.
- For the $50 Acceptance Report: fire `report_generated` when the policy-based acceptance report is available, plus `report_downloaded` when the customer exports it.
- Track whether the report is shared (e.g., sent back to contractor).

**Feeds:**
- `successful_ingestion_to_dashboard_viewed` conversion metric
- One-time offer completion rate

---

### Stage 7: Dashboard Viewed (Monthly Offers)

**Proof Event:** `dashboard_viewed`

**Owner-Visible Metric:** `dashboards_viewed`

**Definition:** Monthly monitoring customer views their portfolio dashboard after first scan ingestion.

**Implementation Notes:**
- Fire event when the customer navigates to the project list or portfolio dashboard.
- Track whether the project status is Passing, Warning, Failing, or Unknown.
- Track time from first successful ingestion to dashboard view.

**Feeds:**
- `successful_ingestion_to_dashboard_viewed` conversion metric
- Activation milestone: customer reached the value moment

---

### Stage 8: Trial Converted

**Proof Event:** `subscription_created` after `payment_completed` for a one-time offer

**Owner-Visible Metric:** `one_time_to_monthly_conversions`

**Definition:** Customer who purchased a one-time Security Check or Acceptance Report later starts a monthly Small Project Security Monitoring subscription.

**Implementation Notes:**
- Fire event when the customer with a prior one-time purchase creates a subscription.
- Track time between one-time purchase and subscription start (0-30 days, 31-90 days, 90+ days).
- Track whether the conversion happened after viewing a report or dashboard.

**Feeds:**
- `one_time_to_monthly_conversion_rate` metric
- Repeat demand signal
- Note: This uses `subscription_created` event, canonical name used across operations-dashboard-metrics.md

---

### Stage 9: Subscription Retained

**Proof Event:** `payment_completed` for an existing subscription

**Owner-Visible Metric:** `subscriptions_retained`

**Definition:** Monthly monitoring customer successfully renews their subscription or completes a recurring payment.

**Implementation Notes:**
- Fire `subscription_renewed` when billing provider confirms renewal.
- Fire `payment_completed` for each successful recurring payment.
- Track payment failures separately via `payment_failed` event.

**Feeds:**
- Monthly recurring revenue (MRR)
- Churn rate (1 - renewal rate)
- Customer lifetime value (CLV) inputs

---

### Stage 10: Expansion Opportunity

**Proof Event:** `project_limit_exceeded` or `additional_project_created`

**Owner-Visible Metric:** `expansion_signals`

**Definition:** Monthly monitoring customer reaches or exceeds their project limit (10 projects under launch price hypothesis) and needs to upgrade.

**Implementation Notes:**
- Fire `project_limit_exceeded` when customer attempts to add a project beyond their plan limit.
- Fire `additional_project_created` when customer adds another project under the same subscription (where allowed).
- Track which customers signal expansion demand.

**Feeds:**
- Upsell/cross-sell pipeline
- Tier pricing validation
- Seat/project quota optimization

---

## Conversion Metrics

These metrics are calculated from the stage events above:

| Metric | Calculation | Launch Target | Why It Matters |
|--------|-------------|---------------|----------------|
| `landing_to_offer_click` | `offer_clicked` / `landing_viewed` | 5-15% (cold); higher from marketplace intent traffic | Shows whether the page/listing makes the offer understandable |
| `offer_click_to_account_created` | `accounts_created` / `offer_clicked` | 40-70% | Shows whether signup friction is too high |
| `account_created_to_payment_complete` | `payment_completed` / `accounts_created` | 25-50% early; investigate below 20% | Shows whether price, trust, or checkout is blocking buyers |
| `payment_complete_to_project_created` | `projects_created` / `payment_completed` | 80%+ within same session | Shows whether post-payment onboarding is clear |
| `project_created_to_token_generated` | `tokens_generated` / `projects_created` | 95%+ | Shows whether project setup automatically reaches integration step |
| `token_generated_to_first_upload_attempt` | `first_upload_attempted` / `tokens_generated` | 50%+ early; 70%+ after docs improve | Shows whether customers can follow setup instructions |
| `first_upload_attempt_to_successful_ingestion` | `scan_ingestion_succeeded` / `first_upload_attempted` | 70%+ early; 85%+ after fixes | Shows whether token/schema/upload path works |
| `successful_ingestion_to_dashboard_viewed` | `dashboard_viewed` / `scan_ingestion_succeeded` | 80%+ | Shows whether the customer reaches the value moment |
| `one_time_to_monthly_conversion` | `subscription_started_after_one_time_purchase` / `one_time_purchases` | 5-15% early; strong signal above 20% | Shows whether one-time scans can feed recurring SaaS |
| `repeat_purchase_rate` | `second_one_time_purchase_within_90d` / `one_time_customers` | 10%+ early is useful signal | Shows whether contractor assurance has repeat demand |

## Operational Metrics

These metrics support business operations decisions:

| Metric | Source | Calculation | Action Threshold |
|--------|--------|-------------|-------------------|
| `time_to_first_project` | `project_created` timestamp - `payment_completed` timestamp | Median | Under 5 minutes |
| `time_to_first_scan_result` | `scan_ingestion_succeeded` timestamp - `payment_completed` timestamp | Median | Under 15 minutes for straightforward repo access |
| `support_minutes_per_customer` | Support time logged | Human support minutes per paying customer per month | Under 10 minutes/customer/month; target under 5 |
| `refund_rate` | `refund_requested` events | Refunds / paid purchases in period | Under 5%; investigate above 10% |
| `setup_failure_reason` | Support notes + `scan_ingestion_failed` | Categorize failed activation by reason | Top 3 reasons reviewed weekly |
| `bad_fit_purchase_rate` | Refunds, cancellations, or unsupported workflow tickets | / paid purchases | Under 10%; tighten listing if higher |

## Event Schema

All funnel events should include these standard fields:

- `event_id`: Unique event identifier
- `event_type`: One of the named events above (e.g., `landing_viewed`, `account_created`)
- `timestamp`: ISO 8601 timestamp
- `user_id` or `account_id`: Customer identifier
- `organization_id`: Organization/workspace identifier (if applicable)
- `session_id`: Session or visit identifier (for anonymous stages)
- `acquisition_source`: marketplace, organic_search, direct_link, referral (where available)
- `offer_type`: security_check, acceptance_report, monthly_monitoring (if applicable)
- `metadata`: Event-specific fields (e.g., `project_id`, `setup_path`, `failure_reason`)

## Privacy Notes

- Use user/account IDs only after account creation; anonymous landing visitors are tracked by session/device ID only.
- Do not store Personally Identifiable Information (PII) in funnel events unless required for billing or support.
- Aggregate metrics for business analysis; individual event data should be accessible only for debugging and support.

## Integration with Downstream Slices

- **S02 (Contractor Assurance):** Uses `report_generated`, `report_downloaded`, and project-status metrics to validate acceptance-report adoption.
- **S03 (Account/Billing/Token):** Implements `account_created`, `payment_completed`, `subscription_started`, `project_created`, `upload_token_generated`, and related state transitions.
- **S04 (Dashboard):** Displays `dashboard_viewed` and project-status metrics for activation monitoring.
- **S06 (Growth Economics):** Consumes all conversion and operational metrics for unit economics modeling and operations dashboard design.

## Verification Checklist

- [x] Funnel definition names each stage
- [x] Each stage has a proof event
- [x] Each stage has an owner-visible metric
- [x] Conversion metrics are calculated from stage events
- [x] Operational metrics support business decisions
- [x] Event schema includes standard fields
- [x] Privacy notes address data minimization
- [x] Integration points with downstream slices are documented