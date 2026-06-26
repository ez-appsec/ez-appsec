# Operations Dashboard Metrics

This document defines the internal metrics and lightweight dashboard surfaces needed to operate the ez-appsec business. Each metric includes a source event, aggregation period, action threshold, and owner response to enable operational visibility and proactive response.

## Overview

The operations dashboard is for internal use only — not exposed to customers. It provides real-time visibility into business health, system performance, customer behavior, and operational capacity. Metrics are organized into seven categories:

1. **Activation Metrics** — Customer onboarding and first-time usage
2. **Scan Performance Metrics** — Scan processing quality and speed
3. **Payment State Metrics** — Billing health and revenue protection
4. **Churn Risk Metrics** — Customer retention signals
5. **Support Operations Metrics** — Support workload and response quality
6. **Abuse and Security Metrics** — Policy violations and security events
7. **Infrastructure Metrics** — System health and capacity planning

Each metric below specifies:
- **Source Event**: The event or data point that feeds this metric
- **Aggregation Period**: How often the metric is calculated (e.g., hourly, daily, weekly)
- **Action Threshold**: The value that triggers attention or intervention
- **Owner Response**: What the responsible owner does when threshold is breached

---

## 1. Activation Metrics

### M1: Time to First Scan

Measures how quickly new customers upload their first scan after signup.

- **Source Event**: `token_generated` timestamp → `first_scan_uploaded` timestamp
- **Aggregation Period**: Daily
- **Action Threshold**: >50% of customers haven't uploaded first scan within 24 hours
- **Owner Response**: Support lead reviews onboarding friction points. Product owner considers adding in-app guidance or email nudge sequence. Target: 70%+ upload within 24 hours.

**Calculation**: For customers who uploaded a scan, compute the time delta between token generation and first scan upload. Report the 50th, 75th, and 90th percentile.

**Dashboard Surface**: Line chart showing 50th/75th/90th percentile over time, with target line at 24 hours.

---

### M2: Activation Rate

Measures the percentage of new accounts that become active (upload first scan).

- **Source Event**: `account_created` events vs `first_scan_uploaded` events
- **Aggregation Period**: Daily
- **Action Threshold**: <40% activation rate for 3+ consecutive days
- **Owner Response**: Product owner investigates conversion barriers. Check onboarding flow, token generation issues, or scan ingestion failures. Target: 60%+ activation.

**Calculation**: `first_scan_uploaded` count ÷ `account_created` count for the same time period.

**Dashboard Surface**: Daily bar chart with activation percentage and target line.

---

### M3: Onboarding Drop-off Points

Identifies where customers abandon during onboarding.

- **Source Event**: Funnel stage progression: `account_created` → `token_generated` → `first_upload_attempt` → `first_scan_uploaded`
- **Aggregation Period**: Weekly
- **Action Threshold**: Any stage conversion drops below 50% of baseline
- **Owner Response**: Product owner analyzes drop-off stage. Engineer reviews error logs for that stage. Consider adding hints, simplifying steps, or fixing bugs.

**Calculation**: For each transition, compute: `events_at_next_stage` ÷ `events_at_current_stage`.

**Dashboard Surface**: Funnel chart showing conversion percentages at each stage, with week-over-week change indicators.

---

## 2. Scan Performance Metrics

### M4: First Scan Latency (P50, P90)

Measures time from scan upload to result availability.

- **Source Event**: `scan_ingestion_succeeded` timestamp vs `scan_processing_completed` timestamp
- **Aggregation Period**: Hourly
- **Action Threshold**: P90 latency >15 minutes for 2+ hours
- **Owner Response**: Engineer checks infrastructure health. Identify bottleneck: ingestion queue, scan processing, result generation, database writes. Target: P50 <5 minutes, P90 <15 minutes.

**Calculation**: For all completed scans in the aggregation window, compute time deltas. Report 50th and 90th percentiles.

**Dashboard Surface**: Time-series line chart with P50 and P90 lines, threshold line at 15 minutes.

---

### M5: Scan Failure Rate

Measures percentage of scan uploads that fail to process.

- **Source Event**: `scan_ingestion_failed` events vs total scan upload attempts
- **Aggregation Period**: Hourly
- **Action Threshold**: Failure rate >10% for 1+ hour
- **Owner Response**: Engineer checks error logs by failure reason. If systematic issue, escalate to engineering lead. If isolated errors, provide support with customer guidance.

**Calculation**: `scan_ingestion_failed` count ÷ (`scan_ingestion_succeeded` + `scan_ingestion_failed`) count.

**Dashboard Surface**: Percentage line chart with threshold line at 10%. Breakdown by failure reason (invalid_schema, token_expired, storage_full, network_timeout).

---

### M6: Top Scan Failure Reasons

Identifies the most common scan ingestion failures.

- **Source Event**: `scan_ingestion_failed` events with failure_reason field
- **Aggregation Period**: Daily
- **Action Threshold**: Any single reason accounts for >30% of failures
- **Owner Response**: Engineer addresses root cause. If invalid_schema, update scanner documentation. If token_expired, improve token lifecycle messaging. If storage_full, trigger capacity scaling.

**Calculation**: Group `scan_ingestion_failed` events by `failure_reason`. Count and percentage breakdown.

**Dashboard Surface**: Stacked bar chart showing failure reasons over time, with top 3 reasons highlighted.

---

### M7: Report Delivery Success Rate

Measures percentage of scan results successfully delivered to customers.

- **Source Event**: `report_delivery_attempted` vs `report_delivery_succeeded` events
- **Aggregation Period**: Hourly
- **Action Threshold**: Success rate <95% for 2+ hours
- **Owner Response**: Engineer checks delivery mechanism (email notification, dashboard update, webhook). If email provider issue, switch to backup. If dashboard issue, check frontend infrastructure.

**Calculation**: `report_delivery_succeeded` count ÷ `report_delivery_attempted` count.

**Dashboard Surface**: Percentage line chart with threshold line at 95%. Breakdown by delivery method (email, dashboard, webhook).

---

## 3. Payment State Metrics

### M8: Payment Failure Rate

Measures percentage of recurring payment charges that fail.

- **Source Event**: Stripe webhook `payment_failed` events vs total recurring charges
- **Aggregation Period**: Daily
- **Action Threshold**: Failure rate >5% for 2+ consecutive days
- **Owner Response**: Support lead checks failure reason breakdown. If systematic (payment provider issue), escalate to engineering. If isolated (card declined), provide customer outreach templates. Target: ≤2% per unit economics (T02).

**Calculation**: `payment_failed` count ÷ (`payment_succeeded` + `payment_failed`) count for recurring charges only.

**Dashboard Surface**: Percentage line chart with threshold line at 5%. Breakdown by failure reason (insufficient_funds, card_declined, expired_card, bank_error).

---

### M9: Active Subscriptions vs Past Due

Measures subscription health and dunning progress.

- **Source Event**: Customer subscription status transitions (active, grace_period_active, past_due, cancelled)
- **Aggregation Period**: Daily
- **Action Threshold**: Past_due count >10% of active subscriptions
- **Owner Response**: Support lead reviews dunning automation. Check if grace period emails are sending. Consider manual outreach for high-value customers.

**Calculation**: Count customers by subscription status. Report: active, grace_period_active, past_due, cancelled.

**Dashboard Surface**: Stacked area chart showing subscription status distribution over time. Table with absolute counts and percentages.

---

### M10: Revenue Recovery Rate

Measures percentage of failed payments that are recovered during grace period.

- **Source Event**: `payment_failed` events → subscription status transitions back to `active`
- **Aggregation Period**: Weekly
- **Action Threshold**: Recovery rate <50%
- **Owner Response**: Support lead reviews dunning email content and timing. Product owner considers improving payment method update UI. Target: 70%+ recovery.

**Calculation**: `payment_failed` events that later transitioned to `active` ÷ total `payment_failed` events in the grace period.

**Dashboard Surface**: Percentage line chart with target line at 70%. Cohort analysis by failure reason.

---

### M11: Failed Payment Time to Recovery

Measures how quickly customers recover failed payments.

- **Source Event**: `payment_failed` timestamp → subscription status transitions to `active`
- **Aggregation Period**: Weekly
- **Action Threshold**: Median time to recovery >7 days
- **Owner Response**: Support lead reviews dunning email sequence. Product owner considers adding urgency messaging or payment method update reminders.

**Calculation**: For recovered payments, compute time delta from `payment_failed` to `active` status. Report median and 75th percentile.

**Dashboard Surface**: Box plot showing recovery time distribution over weeks. Target line at 7 days.

---

## 4. Churn Risk Metrics

### M12: Weekly Churn Rate

Measures percentage of active subscriptions that cancel each week.

- **Source Event**: `subscription_cancelled` events vs active subscriptions
- **Aggregation Period**: Weekly
- **Action Threshold**: Churn rate >10% weekly (equivalent to >40% annual)
- **Owner Response**: Product owner investigates churn reasons. Review exit survey responses (if collected). Analyze churned customer segments. Target: <5% monthly (≈1.2% weekly) per unit economics (T02).

**Calculation**: `subscription_cancelled` count in week ÷ average active subscriptions during week.

**Dashboard Surface**: Weekly bar chart with churn percentage and target line. 4-week moving average for trend visibility.

---

### M13: Churn by Customer Segment

Measures churn rate by customer characteristics.

- **Source Event**: `subscription_cancelled` events with customer metadata (signup cohort, acquisition channel, subscription age, scan usage)
- **Aggregation Period**: Monthly
- **Action Threshold**: Any segment churn >2x overall churn rate
- **Owner Response**: Product owner investigates high-churn segment. Engineer checks for systematic issues affecting that segment. Consider targeted outreach or product improvements.

**Calculation**: For each segment (cohort, channel, age, usage tier), compute churn rate: `subscription_cancelled` count ÷ segment size.

**Dashboard Surface**: Heat map with segments on rows, months on columns, churn rate in cells. Highlight cells >2x overall rate.

---

### M14: Low Usage Indicator

Identifies customers at risk of churn due to low engagement.

- **Source Event**: Scan upload frequency per customer over last 30 days
- **Aggregation Period**: Weekly
- **Action Threshold**: >30% of customers uploaded <1 scan in last 30 days
- **Owner Response**: Product owner considers engagement features (weekly scan reminders, usage insights). Support lead identifies high-value customers in low-use segment for outreach.

**Calculation**: Count active customers with scan count in last 30 days = 0, 1, 2-4, 5+. Report percentage distribution.

**Dashboard Surface**: Stacked bar chart showing usage distribution over time. Table with counts and percentages.

---

### M15: Failed Payment to Churn Conversion

Measures how many failed payments result in churn.

- **Source Event**: `payment_failed` events → `subscription_cancelled` events within 30 days
- **Aggregation Period**: Monthly
- **Action Threshold**: Conversion rate >50%
- **Owner Response**: Support lead reviews dunning process. Product owner considers extending grace period or improving payment recovery UX.

**Calculation**: `subscription_cancelled` within 30 days of `payment_failed` ÷ total `payment_failed` events.

**Dashboard Surface**: Percentage line chart with target line at 50%. Cohort analysis by failure reason.

---

## 5. Support Operations Metrics

### M16: Daily Support Ticket Volume

Measures support workload.

- **Source Event**: `support_case_created` events
- **Aggregation Period**: Daily
- **Action Threshold**: Ticket volume >2x baseline (baseline = tickets per customer × active customers)
- **Owner Response**: Support lead categorizes tickets. If single root cause, escalate to product owner or engineering. If broad issue, consider temporary resource allocation.

**Calculation**: Count `support_case_created` events per day. Baseline: 0.8 tickets/customer/month ÷ 30 days × active customers.

**Dashboard Surface**: Daily line chart with ticket count and baseline line. Breakdown by category (Setup, Billing, Technical, Bug, Feature, Abuse).

---

### M17: Support Response Time (P50, P90)

Measures how quickly support staff respond to tickets.

- **Source Event**: `support_case_created` timestamp → first response timestamp
- **Aggregation Period**: Weekly
- **Action Threshold**: P90 response time >48 hours
- **Owner Response**: Support lead reviews workload and staffing. Consider hiring support role or allocating engineering/founder time. Target: P50 <24 hours, P90 <48 hours.

**Calculation**: For resolved tickets, compute time delta from creation to first response. Report 50th and 90th percentiles.

**Dashboard Surface**: Time-series line chart with P50 and P90 lines, threshold lines at 24h/48h.

---

### M18: Support Resolution Time

Measures how quickly tickets are closed.

- **Source Event**: `support_case_created` timestamp → `support_case_resolved` timestamp
- **Aggregation Period**: Weekly
- **Action Threshold**: Median resolution time >72 hours
- **Owner Response**: Support lead reviews complex tickets. Product owner considers product improvements to reduce support burden.

**Calculation**: For resolved tickets, compute time delta from creation to resolution. Report median and 75th percentile.

**Dashboard Surface**: Time-series line chart with median and 75th percentile lines, threshold line at 72 hours. Breakdown by ticket category.

---

### M19: Escalation Rate

Measures percentage of tickets escalated to engineering or product owner.

- **Source Event**: `support_case_escalated` events vs total `support_case_created` events
- **Aggregation Period**: Weekly
- **Action Threshold**: Escalation rate >20%
- **Owner Response**: Product owner reviews escalation reasons. Engineer investigates systematic issues. Consider improving documentation or product to reduce escalations.

**Calculation**: `support_case_escalated` count ÷ `support_case_created` count.

**Dashboard Surface**: Percentage line chart with threshold line at 20%. Breakdown by escalation level and reason.

---

### M20: Support Backlog Age

Measures how long tickets sit unresolved.

- **Source Event**: Open support tickets (status != resolved/closed) and their creation timestamps
- **Aggregation Period**: Daily
- **Action Threshold**: >10 tickets open >7 days
- **Owner Response**: Support lead prioritizes oldest tickets. Escalate to engineering or product owner if blocked. Consider increasing support capacity.

**Calculation**: Count open tickets by age bucket: <24 hours, 1-2 days, 3-7 days, >7 days.

**Dashboard Surface**: Stacked bar chart showing backlog age distribution. Table with open ticket count and percentage >7 days.

---

### M21: Support Minutes per Customer

Measures support time expenditure relative to customer base.

- **Source Event**: Total time spent on tickets (summed from case logs) ÷ active customers
- **Aggregation Period**: Monthly
- **Action Threshold**: >10 minutes/customer/month
- **Owner Response**: Support lead reviews efficiency. Product owner considers self-service improvements. Engineer investigates product issues causing high support load. Target: <8 minutes/customer/month per unit economics (T02).

**Calculation**: Sum of all ticket resolution minutes in month ÷ average active customers in month.

**Dashboard Surface**: Monthly bar chart with minutes/customer and target line. Trend line over months.

---

## 6. Abuse and Security Metrics

### M22: Abuse Flag Rate

Measures abuse flag frequency relative to customer base.

- **Source Event**: `abuse_flag_raised` events vs active customers
- **Aggregation Period**: Weekly
- **Action Threshold**: Flag rate >5% of active customers
- **Owner Response**: Support lead reviews flagged accounts. Product owner considers improving detection rules or policy clarity. Engineer checks for systematic abuse patterns.

**Calculation**: `abuse_flag_raised` count ÷ active customers count.

**Dashboard Surface**: Percentage line chart with threshold line at 5%. Breakdown by flag type (excessive_usage, duplicate_accounts, fraudulent_chargeback, refund_abuse, api_abuse).

---

### M23: Abuse Review Outcome Distribution

Shows the resolution of abuse flags.

- **Source Event**: `abuse_review_completed` events with outcome field (false_positive, policy_warning, fraud_ban)
- **Aggregation Period**: Monthly
- **Action Threshold**: False positive rate >50%
- **Owner Response**: Support lead reviews detection rules. Adjust automatic trigger thresholds to reduce false positives. Target: <30% false positive.

**Calculation**: Count flags by outcome. Report percentage breakdown.

**Dashboard Surface**: Pie chart showing outcome distribution. Monthly trend line for false positive rate.

---

### M24: Time to Abuse Review

Measures how quickly abuse flags are reviewed.

- **Source Event**: `abuse_flag_raised` timestamp → `abuse_review_completed` timestamp
- **Aggregation Period**: Weekly
- **Action Threshold**: Median review time >48 hours for high-severity flags
- **Owner Response**: Support lead prioritizes abuse review backlog. Consider automated response for clear-cut cases.

**Calculation**: For completed reviews, compute time delta. Report median and 75th percentile, broken down by severity level.

**Dashboard Surface**: Box plot showing review time distribution by severity. Target line at 48 hours for high-severity.

---

### M25: Security Incident Count

Counts confirmed security incidents.

- **Source Event**: Manual incident logging (post-incident review)
- **Aggregation Period**: Monthly
- **Action Threshold**: Any incident in the month
- **Owner Response**: Engineering lead conducts root cause analysis. Product owner communicates to affected customers. Post-incident review completed within 5 business days.

**Calculation**: Count incidents by severity (critical, high, medium, low). Report summary for each.

**Dashboard Surface**: Monthly bar chart with incident count by severity. Table with incident summaries.

---

## 7. Infrastructure Metrics

### M26: Uptime

Measures system availability.

- **Source Event**: External uptime monitoring (e.g., Pingdom, UptimeRobot) or synthetic health checks
- **Aggregation Period**: Hourly
- **Action Threshold**: Uptime <99% for 1+ hour
- **Owner Response**: Engineering lead checks infrastructure health. Identify bottleneck and scale or fix. Post status update to status.ez-appsec.com if >30 minutes. Target: 99.5%+ uptime for Tier 3 SLA compliance.

**Calculation**: Successful health checks ÷ total health checks in window. Report as percentage.

**Dashboard Surface**: Time-series line chart with uptime percentage, threshold line at 99%. Status indicator (green/yellow/red).

---

### M27: API Response Time (P50, P95)

Measures API endpoint latency.

- **Source Event**: Request logs for all API endpoints
- **Aggregation Period**: Hourly
- **Action Threshold**: P95 response time >500ms for 2+ hours
- **Owner Response**: Engineer checks slow queries, database locks, or external dependency latency. Optimize or scale. Target: P50 <200ms, P95 <500ms.

**Calculation**: For API requests in window, compute response time percentiles. Report by endpoint.

**Dashboard Surface**: Time-series line chart with P50 and P95 lines per endpoint, threshold line at 500ms. Highlight endpoints exceeding threshold.

---

### M28: Error Rate

Measures API error responses.

- **Source Event**: API request logs with status code ≥400
- **Aggregation Period**: Hourly
- **Action Threshold**: Error rate >5% for 1+ hour
- **Owner Response**: Engineer checks error logs by status code and endpoint. Identify root cause (400 client errors, 500 server errors). Fix bugs or rate limiting issues.

**Calculation**: Requests with status ≥400 ÷ total requests. Breakdown by status code (4xx, 5xx).

**Dashboard Surface**: Percentage line chart with threshold line at 5%. Breakdown by status code. Top error endpoints.

---

### M29: Database Connection Pool Utilization

Measures database connection pool saturation.

- **Source Event**: Database metrics (e.g., AWS RDS CloudWatch)
- **Aggregation Period**: Every 5 minutes
- **Action Threshold**: Pool utilization >80%
- **Owner Response**: Engineer checks connection leaks or slow queries. Scale database instance or tune connection pool size.

**Calculation**: Active connections ÷ max connections.

**Dashboard Surface**: Gauge with percentage. Time-series line chart for trend visibility. Alert when >80%.

---

### M30: Storage Utilization

Measures S3 bucket or storage capacity.

- **Source Event**: AWS S3 bucket size metrics
- **Aggregation Period**: Daily
- **Action Threshold**: Storage utilization >80%
- **Owner Response**: Engineer reviews storage growth trend. Add lifecycle rules to archive old data. Scale storage capacity.

**Calculation**: Used storage ÷ total storage quota.

**Dashboard Surface**: Gauge with percentage. Time-series line chart showing growth trend. Projected utilization based on growth rate.

---

### M31: Scan Processing Queue Depth

Measures backlog of scans waiting to be processed.

- **Source Event**: Queue metrics (e.g., AWS SQS or Lambda concurrency)
- **Aggregation Period**: Every 5 minutes
- **Action Threshold**: Queue depth >100 scans for 10+ minutes
- **Owner Response**: Engineer checks processing Lambda health. Scale concurrency. If systematic issue, investigate processing bottlenecks.

**Calculation**: Number of messages in scan processing queue.

**Dashboard Surface**: Gauge with absolute count. Time-series line chart showing queue depth over time. Alert when >100.

---

### M32: Cost per Customer

Measures infrastructure cost efficiency.

- **Source Event**: AWS billing data + active customer count
- **Aggregation Period**: Monthly
- **Action Threshold**: Cost/customer exceeds assumptions in unit economics (T02)
- **Owner Response**: Engineer reviews cost drivers (compute, storage, data transfer). Optimize architecture. Product owner considers pricing adjustments if sustained.

**Calculation**: Total infrastructure cost ÷ average active customers. Breakdown by service (Lambda, S3, RDS, etc.).

**Dashboard Surface**: Monthly bar chart with cost/customer and target line from unit economics. Breakdown by service category.

---

## Dashboard Surfaces

### Primary Operations Dashboard

**Purpose**: Real-time operational health and alerting for founders, support lead, and engineering team.

**Layout**:
- **Header**: Key metrics summary (Uptime, Active Subscriptions, Daily Signups, Support Backlog)
- **Row 1 - Activation**: Time to First Scan (P50/P90), Activation Rate, Onboarding Funnel
- **Row 2 - Scan Performance**: First Scan Latency, Scan Failure Rate, Top Failure Reasons, Report Delivery Success
- **Row 3 - Payment State**: Payment Failure Rate, Subscriptions by Status, Revenue Recovery Rate, Failed Payment to Churn
- **Row 4 - Churn Risk**: Weekly Churn Rate, Churn by Segment, Low Usage Distribution
- **Row 5 - Support Operations**: Daily Ticket Volume, Response/Resolution Time, Escalation Rate, Backlog Age
- **Row 6 - Abuse/Security**: Abuse Flag Rate, Review Outcomes, Security Incident Count
- **Row 7 - Infrastructure**: Uptime, API Response Time, Error Rate, Database Pool, Storage, Queue Depth, Cost/Customer

**Refresh Frequency**: Real-time for infrastructure metrics, hourly for operational metrics, daily for business metrics.

**Access**: Internal only. Role-based access: founders (all), support lead (operations metrics), engineering (infrastructure metrics).

---

### Alerting Rules

Alerts trigger when action thresholds are breached. Alert notifications go to appropriate owners via Slack or email.

| Alert Metric | Threshold | Notification Owner | Alerting Channel |
|--------------|-----------|-------------------|------------------|
| First Scan Latency P90 | >15 min for 2 hours | Engineer | Slack #alerts |
| Scan Failure Rate | >10% for 1 hour | Engineer | Slack #alerts |
| Report Delivery Success | <95% for 2 hours | Engineer | Slack #alerts |
| Payment Failure Rate | >5% for 2 days | Support Lead | Email + Slack #ops |
| Past Due Subscriptions | >10% of active | Support Lead | Slack #ops |
| Weekly Churn Rate | >10% | Product Owner | Email + Slack #ops |
| Daily Ticket Volume | >2x baseline | Support Lead | Slack #ops |
| Support Response P90 | >48 hours | Support Lead | Slack #ops |
| Abuse Flag Rate | >5% of active | Support Lead | Slack #ops |
| Uptime | <99% for 1 hour | Engineering Lead | Slack #alerts |
| API Response P95 | >500ms for 2 hours | Engineer | Slack #alerts |
| Error Rate | >5% for 1 hour | Engineer | Slack #alerts |
| Database Pool Utilization | >80% | Engineer | Slack #alerts |
| Storage Utilization | >80% | Engineer | Email |
| Queue Depth | >100 scans for 10 min | Engineer | Slack #alerts |

**Alert Escalation**: If alert is not acknowledged within 30 minutes, escalate to on-call backup. If unresolved for 2 hours, escalate to engineering lead or founder.

---

## Metric Source Events

The following event schema feeds the operations dashboard. Events are emitted by the application and consumed by the metrics aggregation layer.

### Customer Events

- `account_created` — New account signup
- `token_generated` — Upload token created for customer project
- `first_upload_attempt` — Customer attempted first scan upload
- `first_scan_uploaded` — First scan successfully ingested
- `subscription_created` — Subscription started
- `subscription_cancelled` — Subscription cancelled
- `payment_failed` — Recurring payment charge failed
- `payment_succeeded` — Recurring payment charge succeeded

### Scan Events

- `scan_ingestion_attempted` — Scan upload received
- `scan_ingestion_succeeded` — Scan validated and stored
- `scan_ingestion_failed` — Scan upload failed (includes failure_reason)
- `scan_processing_started` — Scan analysis started
- `scan_processing_completed` — Scan analysis finished
- `report_delivery_attempted` — Report delivery initiated
- `report_delivery_succeeded` — Report delivered successfully
- `report_delivery_failed` — Report delivery failed (includes delivery_method, error)

### Support Events

- `support_case_created` — New support ticket
- `support_case_assigned` — Ticket assigned to staff
- `support_case_resolved` — Ticket resolved and closed
- `support_case_escalated` — Ticket escalated to engineering/product
- `support_case_escalation_level` — Level 1, 2, or 3

### Abuse Events

- `abuse_flag_raised` — Abuse flag created (includes flag_type, severity, evidence)
- `abuse_review_assigned` — Flag assigned for review
- `abuse_review_completed` — Flag reviewed (includes outcome: false_positive, policy_warning, fraud_ban)

### Infrastructure Events

- `health_check_succeeded` — Synthetic health check passed
- `health_check_failed` — Synthetic health check failed
- `api_request_logged` — API request (includes endpoint, status_code, response_time_ms)

---

## Integration with Downstream Slices

- **S03 (Account/Billing/Token)**: Emits account, payment, and subscription events that feed activation, payment state, and churn risk metrics.
- **S04 (Dashboard)**: Customer-facing dashboard. Operations dashboard is separate internal surface.
- **S06 (Growth Economics)**: Consumes operations metrics to validate economic assumptions (e.g., support_minutes_per_customer, payment_failure_rate, churn_rate).
- **S07 (Enterprise Readiness)**: Uses operations metrics to plan support capacity and infrastructure scaling for enterprise customers.

---

## Metric Data Retention

- **Raw event logs**: Retain for 90 days (for debugging and incident investigation)
- **Aggregated metrics (hourly/daily)**: Retain indefinitely (for trend analysis)
- **Customer-level metrics**: Retain for 365 days (for churn analysis and retention patterns)
- **Infrastructure metrics**: Retain for 365 days (for capacity planning)

**Data Minimization**: Operations dashboard does not store customer PII. Events reference customer IDs, not customer details. Audit notes (from support-operations-boundaries.md) are internal-only and access-controlled.

---

## Verification Checklist

- [x] Each metric specifies source event
- [x] Each metric specifies aggregation period
- [x] Each metric specifies action threshold
- [x] Each metric specifies owner response
- [x] Metric categories cover: activation, scan performance, payment state, churn risk, support operations, abuse/security, infrastructure
- [x] Dashboard surface defined for operations health visibility
- [x] Alerting rules map thresholds to owners and channels
- [x] Event schema documented for metric sources
- [x] Integration with downstream slices documented
- [x] Data retention policy defined
- [x] Data minimization and access controls specified

---

## Future Enhancements (Post-Launch)

- **Predictive Churn Model**: Machine learning model to identify customers at high churn risk based on usage patterns, support interactions, and failed payments
- **Support Capacity Forecasting**: Predict support workload based on customer growth, enabling proactive hiring planning
- **Cost Anomaly Detection**: Alert on unusual infrastructure cost spikes or efficiency drops
- **Real-time Alerting Dashboard**: Live incident management view during outages or high-severity events
- **Mobile Operations Dashboard**: On-the-go visibility for founders and support lead