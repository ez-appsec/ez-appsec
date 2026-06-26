# Support and Operations Boundaries

This document defines support tiers, SLA/non-SLA language, customer-facing support channels, escalation rules, refund/cancellation handling, failed payment management, abuse review, and operational runbooks for ez-appsec. It connects the commercial funnel metrics (T01) and unit economics (T02) with operational reality.

## Support Tiers

### Tier 1: Self-Service (Default for all customers)

**Coverage:** All customers (one-time purchasers and monthly subscribers)

**What's Included:**
- Documentation and how-to guides for setup, token generation, scan ingestion
- Public FAQ covering common questions
- Email support at support@ez-appsec.com with standard response time
- Access to community forums (when launched)
- Self-service account cancellation and subscription downgrade
- Downloadable reports and data exports

**Response Times:**
- Email: 24-48 hours (target: 24 hours)
- Documentation: Instant (self-paced)

**What's NOT Included:**
- Phone or live chat support
- Custom integration assistance beyond documented paths
- Priority queueing for resolution
- SLA guarantees
- Dedicated account management

**Data Access:** Support staff may view customer account details, project metadata, and recent support history to diagnose issues. No access to source code or scan findings unless explicitly shared by customer.

---

### Tier 2: Assisted Support (Optional add-on, not launched initially)

**Coverage:** Enterprise customers or high-value contracts (not part of initial launch)

**What's Included:**
- All Tier 1 benefits
- Dedicated email channel with 8-hour response time
- One integration assistance session per month (30 minutes)
- Priority queue for critical issues
- Monthly health check-in call (optional)

**Response Times:**
- Priority email: 8 hours during business hours
- Integration assistance: Scheduled within 5 business days

**What's NOT Included:**
- 24/7 phone support
- Custom report generation beyond standard exports
- On-premise deployment support

**Data Access:** Same as Tier 1, plus access to aggregate usage metrics for health discussions. No access to individual scan findings without customer consent.

---

### Tier 3: SLA Support (Future offering for enterprise contracts)

**Coverage:** Enterprise customers with SLA contracts (post-launch)

**What's Included:**
- All Tier 2 benefits
- 4-hour response time for critical issues
- 99.5% uptime guarantee
- Monthly SLA reporting
- Escalation path to engineering team
- Custom risk policy configuration

**Response Times:**
- Critical issues: 4 hours
- Non-critical: 8 hours
- SLA breach credits: 10% of monthly fee for each 1% uptime shortfall

**What's NOT Included:**
- 24/7 support (only business hours)
- On-site consulting
- Custom development beyond product roadmap

**Data Access:** Same as Tier 2, plus engineering team may access anonymized logs for uptime investigation.

---

## SLA vs Non-SLA Language

### Non-SLA Language (Current - Tier 1)

**Commitments (not guarantees):**
- "We typically respond to email support within 24-48 hours."
- "We strive to maintain 99%+ system availability."
- "Documentation is updated within 5 business days of product changes."

**Limitations:**
- Response times are targets, not binding commitments
- No credits or refunds for delays
- No escalation guarantees
- Best-effort approach

**Use Cases:** Early launch, self-service customers, MVP validation phase

---

### SLA Language (Future - Tier 3)

**Guaranteed commitments:**
- "We guarantee a 4-hour response time for critical issues."
- "We maintain 99.5% uptime. If uptime falls below 99%, you receive a 10% monthly fee credit per 1% shortfall."
- "Monthly SLA reports are delivered by the 5th business day of each month."

**Escalation Rights:**
- Critical issue definition: System downtime affecting all customers, data breach, or complete loss of access
- SLA breach definition: Response time exceeded or uptime below guarantee
- Credit calculation formula is contractually specified
- Dispute resolution path via written notice

**Use Cases:** Enterprise contracts, regulated industries, high-value customers

**Transition Point:** Offer Tier 3 when MRR exceeds $5,000/month or when enterprise customers request SLA contracts.

---

## Customer-Facing Support Channels

### Primary Channel: Email Support

**Address:** support@ez-appsec.com

**Purpose:** All non-critical support inquiries, bug reports, feature requests, billing questions

**Process:**
1. Customer sends email with subject line format: `[Category] Brief Description`
2. Automated reply acknowledges receipt and provides expected response time
3. Support staff triages and responds within target window
4. If escalation needed, notifies customer of expected timeline

**Categories:**
- `[Setup]` Token generation, CI integration, scan upload issues
- `[Billing]` Payment failures, refunds, subscriptions, invoices
- `[Technical]` Scan results interpretation, false positives, rule questions
- `[Feature]` Enhancement requests, new functionality
- `[Bug]` System errors, unexpected behavior
- `[Abuse]` Policy violations, suspicious activity reports

**Observability:** Email tickets are logged with timestamp, category, customer ID, and resolution time for operations dashboard (T04).

---

### Secondary Channel: Documentation

**URL:** docs.ez-appsec.com

**Purpose:** Self-service troubleshooting, setup guides, best practices

**Sections:**
- Getting Started: Quick start, token setup, first scan
- Integration Guides: GitHub Actions, GitLab CI, CLI usage
- Troubleshooting: Common issues, error messages, debugging
- FAQ: Billing, security, privacy, technical questions
- API Reference (future): For power users and integrations

**Feedback Loop:** Each doc page includes "Was this helpful?" feedback. Negative feedback triggers doc review and improvement.

**Observability:** Page views, search terms, and feedback scores are tracked to identify documentation gaps.

---

### Tertiary Channel: Community Forums (Future)

**URL:** community.ez-appsec.com (post-launch)

**Purpose:** Peer-to-peer support, feature discussions, community knowledge sharing

**Moderation:** Light moderation by support staff. Rules: No spam, be respectful, no sharing of confidential information.

**Integration:** Notable community threads are surfaced to product team for roadmap input.

---

## Escalation Rules

### Level 1: First-Tier Resolution

**Resolves By:** Support staff (single person or small team)

**Scope:**
- Documentation-referenced issues
- Common setup problems
- Billing inquiries (payment status, invoices)
- Feature requests logged in backlog
- Non-critical bugs triaged to engineering

**Escalation Triggers:**
- Issue unresolved after 2 email exchanges
- Customer requests engineering involvement
- Security vulnerability reported
- Data breach or privacy concern
- Legal compliance question

**Escalation Path:** Support staff → Product owner → Engineering (if needed)

**Observability:** Escalation events logged with trigger reason and resolution time.

---

### Level 2: Engineering Escalation

**Resolves By:** Engineering team

**Scope:**
- Bug fixes for non-critical issues
- Feature requests prioritized in roadmap
- Technical integrations beyond documentation
- Performance investigations

**Escalation Triggers:**
- Bug reproduction confirmed
- Feature request approved for development
- Integration issue requires code change
- Customer requests custom configuration

**Escalation Path:** Support → Engineering team → Product owner (for timeline commitment)

**Observability:** Engineering tickets linked to support case. Resolution time tracked for SLA compliance (Tier 3).

---

### Level 3: Critical Incident

**Resolves By:** Engineering team with product owner oversight

**Scope:**
- System downtime affecting all customers
- Data breach or security incident
- Critical bug blocking all scans
- Regulatory compliance failure

**Escalation Triggers:**
- Uptime below 99% for 1+ hours
- Customer reports data exposure
- Payment processing failure affecting >10% of customers
- Data loss incident

**Escalation Path:** Support → Engineering lead → Product owner → Founder (if needed)

**Response Time:** Immediate (within 1 hour for Tier 3 customers, best-effort for Tier 1)

**Observability:** Incident posted to status.ez-appsec.com. Post-incident review within 5 business days.

---

## Refund and Cancellation Paths

### One-Time Purchases ($20 Security Check, $50 Acceptance Report)

**Refund Window:** 14 days from purchase

**Refund Conditions:**
- Technical failure: Scan ingestion failed due to ez-appsec error, customer unable to retry
- Product misrepresentation: Listing/landing page promised feature not delivered
- Fraud/unauthorized charge

**Non-Refundable:**
- Customer completed scan and viewed report (value received)
- Customer failed to follow setup instructions (user error)
- Change of mind after value received

**Refund Process:**
1. Customer emails support@ez-appsec.com with `[Billing] Refund Request - [Order ID]`
2. Support staff validates refund conditions (check scan ingestion status, report viewed flag)
3. If approved, initiate refund via Stripe within 2 business days
4. Customer receives confirmation email
5. Refund recorded in operations dashboard with reason code

**Abuse Prevention:** Customers with >2 refunds within 90 days are flagged for review and may be restricted from future purchases.

**Observability:** Refund events (`refund_requested`, `refund_approved`, `refund_denied`) feed into `refund_rate` metric from funnel metrics (T01).

---

### Monthly Subscriptions ($15/month)

**Cancellation Window:** Any time (no commitment period)

**Cancellation Process (Self-Service):**
1. Customer logs in and navigates to Account → Subscription → Cancel
2. System confirms cancellation date (effective end of current billing period)
3. Access continues until paid period ends
4. No refunds for partial months

**Cancellation Process (Email Request):**
1. Customer emails support@ez-appsec.com with `[Billing] Cancel Subscription - [Account ID]`
2. Support staff processes cancellation within 24 hours
3. Confirmation email sent with cancellation date and data retention policy

**Refund Conditions (Subscriptions):**
- Refunds only for billing errors (double charge, unauthorized transaction)
- No prorated refunds for early cancellation
- Last month's payment is non-refundable once accessed

**Reactivation:**
- Cancelled subscriptions can be reactivated within 30 days (retain project data)
- After 30 days, account remains but project data is deleted per retention policy

**Observability:** Cancellation events (`subscription_cancelled`) feed into churn rate calculation from unit economics (T02).

---

## Failed Payment Handling

### Payment Failure Detection

**Trigger:** Stripe webhook `payment_failed` event

**Failure Types:**
- Insufficient funds
- Card declined
- Expired card
- Bank processing error
- Network timeout (retryable)

**Immediate Action:**
- Email customer: "Payment failed for your ez-appsec subscription. Update your payment method to continue service."
- Add failed payment flag to account status
- Log `payment_failed` event in operations dashboard

**Retry Schedule:**
- Immediate retry (automatic Stripe retry logic)
- Retry after 24 hours
- Retry after 3 days
- Retry after 5 days
- After 3 failures, mark subscription as `past_due` and suspend service

---

### Grace Period

**Duration:** 7 days from first failed payment

**During Grace Period:**
- Service continues uninterrupted
- Daily reminder emails sent (days 1, 3, 5, 7)
- Customer can update payment method and resume service
- No data loss or access restrictions

**After Grace Period:**
- Service suspended (cannot view dashboard or upload new scans)
- Historical data retained for 30 days
- Reactivation requires updating payment method
- If not reactivated within 30 days, account archived and data deleted

---

### Payment Recovery Workflow

**Step 1: Customer Updates Payment Method**
- Customer navigates to Account → Billing → Update Payment Method
- Stripe validates new payment method
- Retry failed charge immediately
- If successful, remove `past_due` flag, send confirmation email

**Step 2: Support Intervention**
- If customer contacts support with payment issue
- Support staff can manually trigger retry
- Support staff can extend grace period by 7 days (one-time exception)
- Support staff can offer one-time discount if payment failed due to temporary hardship

**Step 3: Dunning Automation**
- Automated email sequence (days 1, 3, 5, 7, 14, 21, 28)
- After 3 failed charges, subscription status = `past_due`
- After 30 days, subscription status = `cancelled`
- Customer receives final email: "Your subscription has been cancelled. Data will be deleted in 30 days."

**Observability:** Failed payment events feed into `payment_failure_rate` assumption from unit economics (T02): 2% of recurring payments fail monthly, with revenue impact of $90-150 at 500 customers.

---

## Abuse Review

### Abuse Flag Triggers

**Automatic Triggers:**
- Customer uploads >100 scans per day (exceeds reasonable usage)
- Multiple accounts using same IP address or payment method
- Credit card chargebacks or fraudulent disputes
- Pattern of refund requests (>2 in 90 days)
- API abuse (excessive rate limit violations when API launches)

**Manual Triggers:**
- Customer reports suspicious activity in another account
- Payment provider flags high-risk transaction
- Support staff observes suspicious pattern during case handling

---

### Abuse Review Process

**Step 1: Flag Assignment**
- Automated system creates abuse case in support queue
- Case tagged `[Abuse]` with trigger reason and evidence
- High-severity flags (data breach, confirmed fraud) auto-escalate to Level 3

**Step 2: Investigation**
- Support staff reviews account activity: scans uploaded, IP addresses, payment history
- If needed, engineering team anonymizes logs for investigation
- If criminal activity confirmed, notify legal team

**Step 3: Resolution**
- **False positive:** Remove flag, add note to account, close case
- **Policy violation:** Send warning email, restrict usage (rate limits), monitor for 30 days
- **Fraud/Criminal:** Suspend account immediately, retain data for legal review, notify payment provider, ban payment method

**Step 4: Documentation**
- Resolution logged with reason code (false_positive, policy_warning, fraud_ban)
- If account suspended, customer notified with explanation and appeal process
- Appeals reviewed within 5 business days by product owner

**Observability:** Abuse flags (`abuse_flag_raised`, `abuse_review_completed`) feed into operations dashboard metrics (T04).

---

## Operational Runbooks for Common Failure Cases

### Runbook: Scan Ingestion Failure

**Symptoms:**
- Customer reports "scan ingestion failed" error
- `scan_ingestion_failed` event in funnel metrics
- Dashboard shows project status = Unknown

**Diagnosis Steps:**
1. Check error message: Invalid schema, token expired, storage full, network timeout?
2. Verify token validity in database (not expired, not revoked, matches project ID)
3. Check infrastructure status (AWS S3 storage availability, Lambda function health)
4. Review logs for ingestion errors (S3 put object failure, schema validation error)

**Resolution Paths:**
- **Invalid schema:** Email customer with "Invalid scan format. Ensure you're using the correct scanner version." Provide link to documentation.
- **Expired token:** Generate new token via customer portal or support intervention. Email customer: "Your upload token has expired. Here's a new token: [redacted]. For security, regenerate your token after each CI run."
- **Storage full:** Check AWS S3 bucket size. If near limit, trigger auto-scaling or manual capacity increase. Email affected customers: "System maintenance in progress. Your scan will be processed within 2 hours."
- **Network timeout:** Retry ingestion automatically. If persistent, check infrastructure health. Escalate to engineering if S3 Lambda is failing.

**Preventive Actions:**
- Monitor `first_upload_attempt_to_successful_ingestion` conversion metric (target: 70%+ early, 85%+ after fixes)
- Top 3 failure reasons reviewed weekly
- Doc improvements for common error messages

**Escalation Criteria:**
- >10% ingestion failure rate for 1+ hours
- Multiple customers reporting same error
- Infrastructure health check fails

---

### Runbook: Payment Processing Failure

**Symptoms:**
- Stripe webhook `payment_failed` events spike
- Customer emails about payment issues
- Dashboard shows subscription status = `past_due`

**Diagnosis Steps:**
1. Check Stripe status page (outages, API issues)
2. Verify webhooks are firing (check webhook logs in Stripe dashboard)
3. Review failed payment error codes (insufficient_funds, card_declined, expired_card)
4. Check database for payment transaction records

**Resolution Paths:**
- **Stripe outage:** Post status update to status.ez-appsec.com. Extend grace periods for affected customers. Notify support team of increased support volume.
- **Webhook failure:** Check webhook endpoint health. Restart webhook listener if needed. Manually reconcile recent payments.
- **High failure rate (systematic):** Check billing system configuration. Escalate to engineering if payment provider integration is broken.
- **Individual customer failures:** Process per failed payment handling workflow above.

**Preventive Actions:**
- Monitor `payment_failure_rate` metric (assumption: 2% of recurring payments fail monthly)
- Daily reconciliation of Stripe dashboard vs internal payment records
- Webhook health check automated

**Escalation Criteria:**
- Payment processing down for >30 minutes
- Failure rate exceeds 5% for 1+ hours
- Duplicate charges or billing errors affecting >10 customers

---

### Runbook: System Downtime

**Symptoms:**
- Status.ez-appsec.com shows incident
- Customer reports "service unavailable" or slow response times
- Infrastructure monitoring alerts (CPU >80%, memory >90%, database connection pool exhausted)

**Diagnosis Steps:**
1. Check infrastructure monitoring dashboards (AWS CloudWatch, application logs)
2. Identify bottleneck: web servers, database, storage, external dependencies
3. Check recent deployments (did a change cause the issue?)
4. Review error rates and latency metrics

**Resolution Paths:**
- **Web server overload:** Scale up web servers (auto-scaling or manual). If auto-scaling failing, check autoscaling configuration.
- **Database overload:** Check slow queries. Add indexes if needed. Scale database instance. Connection pool tuning.
- **Storage full:** Check S3 bucket size. Add lifecycle rules to archive old data. Scale storage.
- **External dependency failure:** Check if GitHub API, Stripe API, or other dependency is down. Implement circuit breaker if needed.

**Preventive Actions:**
- Infrastructure monitoring with alerting (CPU >80%, memory >90%, database connection pool >80%)
- Capacity planning based on growth scenarios (T02)
- Load testing before major launches

**Escalation Criteria:**
- Uptime below 99% for 1+ hours (critical incident)
- Any data loss or data breach
- Downtime affecting >50% of customers

---

### Runbook: Data Privacy Incident

**Symptoms:**
- Customer reports data exposure (saw another customer's scan results)
- Logs show unauthorized access attempts
- Support staff observe data inappropriately visible in ticket

**Diagnosis Steps:**
1. Confirm scope: Which customers affected? What data exposed?
2. Identify root cause: Access control bug, authentication failure, support tool misconfiguration?
3. Check logs for access patterns
4. Preserve evidence for legal review

**Resolution Paths:**
- **Access control bug:** Engineering team fixes immediately. Deploy hotfix. Notify affected customers within 72 hours per GDPR requirements.
- **Support tool misconfiguration:** Revoke support staff access. Train team on data access policies. Implement data masking for sensitive fields.
- **Authentication failure:** Check auth provider (e.g., Supabase). Rotate secrets if needed. Reset sessions for affected users.

**Preventive Actions:**
- Regular security audits
- Data access logging for all support tools
- Support staff training on data privacy
- Least-privilege access controls

**Escalation Criteria:**
- Any confirmed data exposure
- Unauthorized access to customer data
- Compliance requirement triggered (GDPR, CCPA)

---

### Runbook: High Support Volume

**Symptoms:**
- Support ticket volume exceeds baseline (>20 tickets/day for 25 customers)
- Email response times exceed 48 hours
- Multiple customers reporting same issue (pattern detection)

**Diagnosis Steps:**
1. Categorize tickets by type: setup, billing, technical, bug, abuse
2. Identify top issue categories
3. Check if issue correlates with recent deployment or system change
4. Review funnel metrics for anomaly (e.g., drop in conversion, increase in support tickets)

**Resolution Paths:**
- **Single root cause (e.g., bug):** Escalate to engineering. Bug fix prioritized. Communicate timeline to affected customers.
- **Documentation gap:** Improve docs for top issues. Email customers with links to updated documentation.
- **Onboarding friction:** Simplify signup or setup process. Add in-product guidance.
- **Support understaffed:** Temporary resource allocation (founder or engineering team helps). Review hiring plan for support role.

**Preventive Actions:**
- Monitor `support_minutes_per_customer` metric (target: <10 minutes/customer/month)
- Weekly review of top 10 support issues
- Proactive doc improvements based on support patterns

**Escalation Criteria:**
- Support backlog >50 tickets
- Response time >72 hours
- Pattern of identical issues from >10 customers

---

## Observability and Data Access

### Support Case Status

**Status Types:**
- `new`: Ticket created, not yet triaged
- `in_progress`: Support staff actively working
- `waiting_customer`: Waiting for customer response
- `escalated`: Escalated to engineering or product owner
- `resolved`: Issue resolved, ticket closed
- `closed`: Ticket closed without resolution (e.g., no response)

**Data Logged per Case:**
- Case ID, timestamp, category, customer ID
- Support staff assigned, time spent
- Resolution status, reason code
- Link to engineering ticket (if escalated)

**Observability:** `support_case_created`, `support_case_resolved` events feed into operations dashboard (T04).

---

### Failed Payment Status

**Status Types:**
- `payment_failed`: Initial failure detected
- `retry_pending`: Automatic retry scheduled
- `grace_period_active`: Customer has 7 days to update payment
- `past_due`: 3 failed charges, service suspended
- `cancelled`: 30 days past due, subscription cancelled

**Data Logged per Failed Payment:**
- Customer ID, subscription ID, timestamp
- Failure reason code (insufficient_funds, card_declined, expired_card, etc.)
- Retry count, grace period end date
- Recovery action (updated_payment_method, extended_grace, cancelled)

**Observability:** `payment_failed` events feed into `payment_failure_rate` metric from unit economics (T02).

---

### Abuse Flags

**Flag Types:**
- `excessive_usage`: >100 scans per day
- `duplicate_accounts`: Multiple accounts from same IP/payment
- `fraudulent_chargeback`: Payment provider confirmed fraud
- `refund_abuse`: >2 refunds in 90 days
- `api_abuse`: Excessive rate limit violations (when API launches)

**Data Logged per Flag:**
- Flag ID, timestamp, trigger reason
- Customer ID, evidence (IP address, payment method, scan count)
- Review outcome (false_positive, policy_warning, fraud_ban)
- Reviewer, review timestamp

**Observability:** `abuse_flag_raised`, `abuse_review_completed` events feed into operations dashboard (T04).

---

### Customer-Safe Audit Notes

**Purpose:** Support staff can add notes to customer accounts for future reference without exposing sensitive data to customer.

**Note Categories:**
- `interaction_summary`: Summary of support conversation
- `escalation_reason`: Why case was escalated
- `refund_reason`: Reason for refund approval/denial
- `abuse_review_notes`: Investigation notes (restricted access)
- `special_handling`: Customer requires specific care (e.g., enterprise contract)

**Access Control:**
- All support staff can view `interaction_summary`, `escalation_reason`, `refund_reason`
- Only support lead and product owner can view `abuse_review_notes`
- Customers never see audit notes (internal only)

**Data Minimization:**
- Notes do not include PII unless required for resolution
- No source code or scan findings in notes
- Notes reference customer ID, not customer details

**Observability:** Audit note creation events logged for compliance review.

---

## Legal and Accounting Review Items

### Legal Review Required For:

1. **SLA contracts:** Tier 3 service level agreements require legal review before offering to enterprise customers
2. **Data processing agreements (DPA):** If customer requests DPA under GDPR, legal team reviews and countersigns
3. **Abuse handling:** Legal review of abuse policy and customer notification language
4. **Refund policy:** Legal review of refund terms and conditions

### Accounting Review Required For:

1. **Revenue recognition:** Monthly recurring revenue (MRR) and one-time revenue classification under GAAP
2. **Churn calculation:** Standard churn definition for investor reporting
3. **Deferred revenue:** Handling of prepaid annual subscriptions (if offered)
4. **Tax compliance:** Sales tax collection and remittance across jurisdictions

**Non-Blocking:** These review items do not block product planning or early launch. They are documented for future professional review when revenue scales or enterprise contracts emerge.

---

## Integration with Downstream Slices

- **S03 (Account/Billing/Token):** Implements payment failure detection, subscription status transitions, refund processing, and data retention policies defined here.
- **S04 (Dashboard):** Displays account status (active, past_due, cancelled), payment method update interface, and cancellation self-service flow.
- **T04 (Operations Dashboard):** Consumes support case status, failed payment status, abuse flags, and operational metrics for internal operations visibility.
- **S07 (Enterprise Readiness):** Uses Tier 2 and Tier 3 support definitions for enterprise tradeoff analysis and SLA contract templates.

---

## Verification Checklist

- [x] Support tiers define included/excluded work
- [x] SLA/non-SLA language clearly distinguished
- [x] Customer-facing support channels documented
- [x] Escalation rules specify triggers and paths
- [x] Refund and cancellation paths defined
- [x] Failed payment handling workflow specified
- [x] Abuse review process defined
- [x] Operational runbooks cover common failure cases
- [x] Support case status types enumerated
- [x] Failed payment status types enumerated
- [x] Abuse flag types enumerated
- [x] Customer-safe audit notes specified
- [x] Data access boundaries for support staff defined
- [x] Legal and accounting review items identified
- [x] Integration with downstream slices documented