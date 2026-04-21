# ez-appsec Roadmap

**Goal:** Reach feature parity with commercial AppSec platforms (Snyk, Veracode, Checkmarx) while remaining free, open-source, and AI-native.

Each body of work below is **atomic and independent** — no plan has a hard dependency on another unless listed. Every plan ships its own tests and must pass the full existing test suite before merge.

Work is tracked in the [ez-appsec GitHub Project](https://github.com/orgs/ez-appsec/projects) and mirrored to the [GitLab group](https://gitlab.com/jfelten.work-group/ez_appsec) for reporting.

---

## Current State

| Capability | Status |
|---|---|
| Secret detection (gitleaks) | ✅ Shipped |
| SAST (semgrep) | ✅ Shipped |
| IaC scanning (kics) | ✅ Shipped |
| Dependency CVEs (grype) | ✅ Shipped |
| Unified vulnerability schema | ✅ Shipped |
| GitHub CI integration | ✅ Shipped |
| GitLab CI integration | ✅ Shipped |
| Security dashboard (GitHub/GitLab Pages) | ✅ Shipped |
| Claude Code skills (`/ez-appsec`) | ✅ Shipped |
| AI remediation guidance | ✅ Shipped |
| Docker images (standard / slim / micro) | ✅ Shipped |

---

## Roadmap

Plans are grouped into phases for orientation, but **each plan is independently claimable**.

---

### Phase 1 — Developer Feedback Loop

> Make findings land where developers already work.

---

#### PLAN-01: PR/MR Inline Comments

**Problem:** Scan results live in the dashboard. Developers don't check the dashboard during code review — they check the PR diff.

**Scope:**
- GitHub: post findings as inline review comments on the PR diff using the GitHub Checks API and pull_request_review_comments endpoint
- GitLab: post findings as MR diff notes
- Only comment on lines changed in the diff (not pre-existing findings)
- Group multiple findings per file into a single comment thread
- Re-use existing finding location schema (`file_name`, `start_line`)

**Out of scope:** Resolving/dismissing comments automatically; Bitbucket.

**Technical approach:**
- New `ez_appsec/pr_commenter.py` module
- Add `--pr-comment` flag to `github-scan` and `gitlab_scan` CLI commands
- GitHub: read `GITHUB_TOKEN` + `GITHUB_EVENT_PATH` from Actions environment
- GitLab: read `CI_MERGE_REQUEST_IID` + `GITLAB_ACCESS_TOKEN` from CI environment
- Diff context: fetch PR file list, filter findings to changed lines only

**Done criteria:**
- `tests/test_pr_commenter.py` with mocked GitHub/GitLab API calls
- End-to-end test via `github-pipeline-test.sh --check-pr-comments` on a test PR
- Existing test suite passes
- Docs updated in `docs/github.md` and `docs/gitlab.md`

---

#### PLAN-02: Ignore Rules (`.ez-appsec.yaml`)

**Problem:** Every codebase has known false positives — test credentials, example configs, vendored code. Without ignore rules, the same noise appears in every scan.

**Scope:**
- `.ez-appsec.yaml` config file at repo root (or path passed via `--config`)
- Ignore by: rule ID, file path (glob), finding message substring, CVE ID
- Ignore scopes: `permanent` (suppress forever) or `until: <ISO date>` (expires and resurfaces)
- `ez-appsec check` command validates the config file syntax
- Ignored findings appear in output as `[suppressed]` count, not hidden silently

**Out of scope:** Web UI for managing ignores; team-level ignore sharing.

**Technical approach:**
- Extend `ez_appsec/config.py` with `IgnoreRule` dataclass and loader
- Post-process findings in `ez_appsec/scanner.py` after all scanners complete
- Store suppression reason in the finding's `suppressed_by` field in `vulnerabilities.json`

**Done criteria:**
- `tests/test_config.py` extended with ignore rule parsing and matching tests
- `tests/test_scanner.py` extended with suppression post-processing tests
- Config schema documented in `docs/github.md` reference section
- Existing test suite passes

---

#### PLAN-03: Baseline Mode (New-Findings-Only Alerting)

**Problem:** Running a scan on a legacy codebase produces hundreds of findings, most pre-existing. Teams need to see only *new* findings introduced since a baseline snapshot.

**Scope:**
- `ez-appsec scan --baseline <path-or-url>` flag
- Baseline is a `vulnerabilities.json` from a previous scan (local path or dashboard URL)
- Diff logic: match findings by `(rule_id, file_path, start_line)` fingerprint
- Output: new findings only; summary shows `N new, M existing (suppressed)`
- CI integration: exit non-zero only when *new* findings exceed threshold

**Out of scope:** Automatic baseline promotion; persistent baseline storage.

**Technical approach:**
- New `ez_appsec/baseline.py` module with `diff_findings(current, baseline)` function
- Fingerprint is a stable hash of `rule_id + normalized_file_path + start_line`
- Add `--baseline` and `--baseline-threshold` flags to `scan` and `github-scan` commands

**Done criteria:**
- `tests/test_baseline.py` covering: identical findings (all suppressed), new file (all new), line shift (matched by rule+file), empty baseline (all new)
- Integration test with fixture `vulnerabilities.json` files in `tests/fixtures/`
- Existing test suite passes

---

#### PLAN-04: Automated Fix PRs for CVEs

**Problem:** `/ez-appsec remediate` applies fixes locally. Most CVE fixes are mechanical (version bumps) — they should be auto-opened as PRs without requiring a developer to run anything.

**Scope:**
- GitHub: `ez-appsec fix-pr --repo <owner/repo>` opens a branch + PR with version bumps for all `dependency_scanning` findings with a `solution` field
- Supports: `package.json`, `requirements.txt`, `go.mod`, `Gemfile`, `pom.xml`
- One PR per package ecosystem (not one PR per finding)
- PR description lists each CVE fixed with CVSS score and link
- GitLab: opens an MR instead

**Out of scope:** SAST/IaC fix PRs (too risky to auto-apply); secret rotation.

**Technical approach:**
- New `ez_appsec/fix_pr.py` module
- New `fix-pr` CLI command
- Reuse version-bump logic from `/ez-appsec remediate` skill
- GitHub PR via `gh` CLI or REST API; GitLab MR via `glab` or REST API

**Done criteria:**
- `tests/test_fix_pr.py` with mocked gh API: correct branch name, correct version bump per ecosystem, correct PR body format
- Manual end-to-end test on `ez-appsec/juice-shop-public` documented in PR
- Existing test suite passes

---

### Phase 2 — Visibility & Tracking

> Know what you have, where it's trending, and who owns it.

---

#### PLAN-05: Scan History & Trend Tracking

**Problem:** The dashboard shows the current snapshot only. There is no way to see whether the security posture is improving or degrading over time.

**Scope:**
- Each scan appends a timestamped entry to `data/projects/<slug>/history.json` in the dashboard repo
- Dashboard UI shows a sparkline chart of finding count over time (last 30 scans)
- Trend indicator on project cards: ↑ worse / ↓ better / → stable (vs previous scan)
- History capped at 90 entries per project; older entries rolled off

**Out of scope:** Cross-project trend aggregation; export to external SIEM.

**Technical approach:**
- Modify `scripts/aggregate-index.py` to append to history on each ingest
- Extend `app-github.js` with a `renderSparkline(history)` function using a minimal SVG approach (no Chart.js dependency)
- History schema: `[{date, total, critical, high, medium, low}, ...]`

**Done criteria:**
- `tests/test_history.py` covering history append, rolloff at 90 entries, delta calculation
- Dashboard UI renders sparkline without JavaScript errors (manual verification)
- Existing test suite passes

---

#### PLAN-06: Finding Ownership & SLA Tracking

**Problem:** Findings sit unassigned indefinitely. There is no way to assign ownership or track whether SLA targets (e.g., critical fixed within 7 days) are being met.

**Scope:**
- Dashboard: assign findings to a GitHub/GitLab username via a dropdown
- SLA configuration in `data/config.json`: `{critical: 7, high: 30, medium: 90}` days
- Findings past SLA are flagged with a visual indicator in the dashboard
- Ownership and SLA data stored in `data/projects/<slug>/ownership.json`

**Out of scope:** Email notifications; Jira sync; LDAP/SSO user resolution.

**Technical approach:**
- New `ownership.json` schema: `{finding_fingerprint: {owner, assigned_date, sla_days}}`
- Dashboard JS reads ownership.json and merges with vulnerability list on render
- Save ownership changes via GitHub/GitLab API (direct commit to dashboard repo)

**Done criteria:**
- `tests/test_ownership.py` covering SLA calculation, overdue detection, fingerprint matching
- Dashboard UI ownership panel renders without errors (manual verification)
- Existing test suite passes

---

#### PLAN-07: Slack / Teams Notifications

**Problem:** New critical findings are invisible until someone checks the dashboard. Teams need findings pushed to them.

**Scope:**
- Webhook notification when a scan produces new critical or high findings
- Configurable via `EZ_APPSEC_SLACK_WEBHOOK` / `EZ_APPSEC_TEAMS_WEBHOOK` CI variable
- Message format: project name, finding count by severity, top 3 findings, dashboard link
- Deduplication: only notify on findings that are *new* since the previous scan (requires PLAN-03 or its own simple snapshot)

**Out of scope:** PagerDuty; email; per-user DMs; notification rules engine.

**Technical approach:**
- New `ez_appsec/notifier.py` with `SlackNotifier` and `TeamsNotifier` classes
- Called at end of `scanner.py` scan pipeline if webhook env var is set
- Slack: Block Kit message. Teams: Adaptive Card.

**Done criteria:**
- `tests/test_notifier.py` with mocked HTTP calls: correct payload shape for Slack and Teams, dedup logic, no notification when zero new findings
- Existing test suite passes
- Docs updated in CI variable reference tables

---

#### PLAN-08: Jira Integration

**Problem:** Security findings need to live in the same backlog as engineering work. Teams using Jira need findings to automatically create and update tickets.

**Scope:**
- Create Jira issues for new critical/high findings
- Update existing issues when findings are resolved (close the ticket)
- Configurable via: `EZ_APPSEC_JIRA_URL`, `EZ_APPSEC_JIRA_TOKEN`, `EZ_APPSEC_JIRA_PROJECT`
- Jira issue contains: severity, scanner, file location, AI remediation guidance, dashboard link
- Dedup: track `finding_fingerprint → jira_issue_key` in dashboard to avoid duplicate tickets

**Out of scope:** Linear; Asana; bidirectional sync; Jira Service Management.

**Technical approach:**
- New `ez_appsec/jira_sync.py` module using Jira REST API v3
- Called post-scan if Jira env vars are set
- Fingerprint → issue key map stored in `data/projects/<slug>/jira_map.json`

**Done criteria:**
- `tests/test_jira_sync.py` with mocked Jira API: create issue, update issue, close on resolution, skip duplicate
- Existing test suite passes
- Docs: new `docs/integrations.md` with Jira setup section

---

### Phase 3 — Compliance & Policy

> Enforce standards, generate evidence, satisfy auditors.

---

#### PLAN-09: Policy Engine

**Problem:** "Fail the build if there are any critical findings" is too blunt. Teams need policies like "fail only on critical secrets findings" or "warn on high CVEs older than 30 days."

**Scope:**
- Policy rules defined in `.ez-appsec.yaml` under a `policy:` key
- Rule attributes: `severity`, `category` (secrets/sast/iac/cve), `max_count`, `action` (fail/warn/ignore)
- `ez-appsec scan` exits non-zero when a `fail` policy is violated
- Policy evaluation result included in `vulnerabilities.json` as `policy_violations: []`

**Out of scope:** Org-level policy inheritance; policy-as-code DSL; OPA integration.

**Technical approach:**
- New `ez_appsec/policy.py` with `PolicyEngine` class
- Extend config loader (PLAN-02's `config.py`) or implement standalone
- Policy check runs after all scanners and after ignore-rule suppression

**Done criteria:**
- `tests/test_policy.py` covering: fail on threshold breach, warn below threshold, category filter, combined rules, policy result in JSON output
- Existing test suite passes

---

#### PLAN-10: SBOM Generation

**Problem:** Customers, auditors, and the US Federal government (EO 14028) require a Software Bill of Materials with every release.

**Scope:**
- Generate CycloneDX 1.4 JSON SBOM from `grype` scan output
- Output as `sbom.cdx.json` alongside `vulnerabilities.json`
- Attach SBOM to GitHub Releases as a release asset (in release.yml)
- `ez-appsec scan --sbom` flag enables SBOM generation

**Out of scope:** SPDX format; SBOM signing; license data in SBOM (see PLAN-11).

**Technical approach:**
- New `ez_appsec/sbom.py` with `generate_cyclonedx(grype_output)` function
- Grype already outputs SBOM natively via `--output cyclonedx-json` — thin wrapper
- Add `--sbom` flag to `scan` and `github-scan` commands

**Done criteria:**
- `tests/test_sbom.py` with fixture grype output: validates CycloneDX schema version, component count, required fields
- Integration: SBOM present in release artifacts (verified in release workflow)
- Existing test suite passes

---

#### PLAN-11: License Compliance

**Problem:** Using a GPL dependency in a commercial product is a legal risk. Teams need to know what licenses their dependencies carry and whether any violate policy.

**Scope:**
- Extract license data from grype/syft SBOM output
- Configurable allowed/denied license lists in `.ez-appsec.yaml`
- License violations appear as `category: license_compliance` findings in `vulnerabilities.json`
- Dashboard shows license breakdown by type

**Out of scope:** License text extraction; OSI approval status lookup; FOSS compliance tooling.

**Technical approach:**
- New `ez_appsec/license_checker.py`
- Syft (bundled with grype) outputs license data — parse from its JSON output
- Map SPDX license identifiers to policy rules

**Done criteria:**
- `tests/test_license_checker.py` covering: allowed license passes, denied license fails, unknown license warns, wildcard match (GPL*)
- Existing test suite passes
- Docs updated with license policy config reference

---

#### PLAN-12: Compliance Report Generation

**Problem:** SOC2, PCI-DSS, and HIPAA auditors ask "show me your vulnerability management program." There is no way to export findings mapped to control frameworks.

**Scope:**
- `ez-appsec report --framework <soc2|pci-dss|hipaa>` command
- Maps finding categories to control IDs (e.g., SOC2 CC6.1, PCI DSS 6.3.2)
- Output: PDF-ready HTML report with: executive summary, findings by control, open vs closed counts
- Findings sourced from `vulnerabilities.json` (local or dashboard)

**Out of scope:** Automated evidence collection; GRC platform integration; dynamic control mapping updates.

**Technical approach:**
- New `ez_appsec/compliance_reporter.py`
- Control mapping tables as static JSON in `ez_appsec/data/frameworks/`
- HTML output rendered via Jinja2 template; PDF via `weasyprint` (optional dep)

**Done criteria:**
- `tests/test_compliance_reporter.py` covering: finding → control mapping correctness, HTML output contains required sections, missing framework raises clear error
- Existing test suite passes
- Framework mapping tables reviewed for accuracy (documented in PR)

---

### Phase 4 — Platform Expansion

> Meet developers where they are.

---

#### PLAN-13: VS Code Extension

**Problem:** The Claude Code skill works only inside Claude Code. Most developers use VS Code and want inline security feedback without switching tools.

**Scope:**
- VS Code extension that runs `ez-appsec scan` on save (configurable) or on demand
- Inline diagnostic squiggles on vulnerable lines
- Hover tooltip: severity, rule name, AI remediation hint
- Command palette: `ez-appsec: Scan workspace`, `ez-appsec: Clear findings`
- Requires Docker to be running

**Out of scope:** JetBrains; Neovim; auto-fix from IDE.

**Technical approach:**
- New `vscode-extension/` directory with standard VS Code extension scaffold
- Spawns `docker run ... ez-appsec scan` as a child process
- Parses `vulnerabilities.json` output, maps to VS Code `Diagnostic` objects
- Separate release pipeline: publishes to VS Code Marketplace

**Done criteria:**
- Extension unit tests via `@vscode/test-electron` or `vitest`: diagnostic mapping, command registration, config reading
- Manual smoke test: install from VSIX, scan a fixture project, verify squiggles appear
- Existing Python test suite passes (unaffected)
- `vscode-extension/README.md` with install and usage guide

---

#### PLAN-14: REST API

**Problem:** There is no programmatic way to query findings, trigger scans, or integrate ez-appsec into custom tooling without parsing JSON files directly.

**Scope:**
- FastAPI service exposing: `POST /scan`, `GET /projects`, `GET /projects/{slug}/findings`, `GET /projects/{slug}/history`
- API key authentication via `X-API-Key` header
- Findings sourced from the dashboard repo (reads `vulnerabilities.json` via GitHub API)
- OpenAPI spec auto-generated at `/docs`
- Docker image: `ghcr.io/ez-appsec/ez-appsec-api:latest`

**Out of scope:** Write operations via API; user management; rate limiting; SaaS hosting.

**Technical approach:**
- New `api/` directory with FastAPI app
- New `Dockerfile.api` for the API image
- New GitHub Actions workflow `api.yml` for building and publishing the API image

**Done criteria:**
- `tests/test_api.py` covering: auth rejection on missing key, scan endpoint returns 202, findings endpoint returns correct schema, history endpoint returns array
- OpenAPI spec validates against OpenAPI 3.1 schema
- Existing test suite passes

---

#### PLAN-15: Container Image Scanning

**Problem:** Grype scans SBOMs and file-system dependencies but does not scan running container images for OS-level CVEs (kernel packages, base OS libraries).

**Scope:**
- `ez-appsec scan --image <image:tag>` pulls the image and runs a full grype image scan
- OS package CVEs appear as `category: container_scanning` findings
- Dashboard: container scan results shown separately from code scan results
- Support for scanning images from private registries via `--registry-auth`

**Out of scope:** Runtime container scanning; Kubernetes cluster scanning; distroless image analysis.

**Technical approach:**
- Extend `ez_appsec/external_scanners.py` with `GrypeImageScanner` class
- `grype <image>` already supports image scanning — wire it into the scanner pipeline
- New `category: container_scanning` in the unified schema

**Done criteria:**
- `tests/test_container_scanner.py` with mocked grype output: correct category assignment, correct severity mapping, private registry flag passed through
- Existing test suite passes
- Docs updated in `docs/github.md` with `--image` flag reference

---

#### PLAN-16: Expanded SAST Rule Sets

**Problem:** The default semgrep OSS rules miss many language-specific patterns. Custom rules for common frameworks (Django, Rails, Spring, Express) would catch far more real issues.

**Scope:**
- Custom semgrep rule packs for: Python/Django, Ruby/Rails, Java/Spring, Node/Express, PHP/Laravel
- Rules cover: IDOR, mass assignment, CSRF bypass, header injection, insecure deserialization
- Rules stored in `rules/<language>/` and bundled in the Docker image
- `ez-appsec scan --rules <language>` enables the pack; `--rules all` runs all packs

**Out of scope:** Rule editor UI; rule contribution pipeline; paid rule registry.

**Technical approach:**
- New `rules/` directory with YAML rule files per language
- Rules tested against fixtures in `rules/<language>/tests/`
- Extend `ez_appsec/external_scanners.py` to pass `--config` flag to semgrep

**Done criteria:**
- Each rule pack has at minimum 5 rules, each with a true-positive and true-negative fixture
- `tests/test_custom_rules.py` validates rule YAML schema, fixture pass/fail
- At least one rule per language pack triggers on a real CVE from OWASP test projects
- Existing test suite passes

---

### Phase 5 — Enterprise Features

> Scale to organizations, meet compliance needs, enable autonomy.

---

#### PLAN-17: Secret Rotation Automation

**Problem:** Detecting a hardcoded secret is step one. Rotating it (revoking the old value, generating a new one, updating the config) is where teams get stuck.

**Scope:**
- Detect secret *type* from the gitleaks rule ID (AWS key, GitHub PAT, Stripe key, etc.)
- For supported types: call the provider API to revoke the old secret and issue a new one
- Write new secret to the configured secret store (GitHub Actions secrets, GitLab CI variables, HashiCorp Vault)
- Open a PR/MR replacing the hardcoded value with `os.environ.get("SECRET_NAME")`
- Supported providers: AWS IAM, GitHub PATs, GitLab PATs

**Out of scope:** GCP/Azure credentials; Slack tokens; database passwords; arbitrary secret types.

**Technical approach:**
- New `ez_appsec/secret_rotator.py` with provider plugin architecture
- Each provider implements: `can_rotate(rule_id) → bool`, `rotate(value) → new_value`
- Extend `fix-pr` command (PLAN-04) with `--rotate-secrets` flag

**Done criteria:**
- `tests/test_secret_rotator.py` with mocked provider APIs: correct provider dispatch, new secret returned, PR body contains env var name
- Existing test suite passes

---

#### PLAN-18: Multi-Tenant Organization Management

**Problem:** Enterprise customers need to manage ez-appsec across hundreds of repos. Today each repo is configured individually.

**Scope:**
- Organization-level `.ez-appsec.yaml` in a designated config repo
- Child repos inherit org policy; local `.ez-appsec.yaml` can override specific rules
- `ez-appsec org-sync --org <github-org>` discovers all repos, installs/updates workflows
- Org-level dashboard aggregates findings across all repos with drill-down

**Out of scope:** SSO; RBAC beyond GitHub/GitLab native permissions; multi-cloud org management.

**Technical approach:**
- New `ez_appsec/org_manager.py` with repo discovery via GitHub/GitLab API
- Config inheritance: merge org config + repo config with repo taking precedence on conflicts
- New `org-sync` CLI command

**Done criteria:**
- `tests/test_org_manager.py` covering: repo discovery, config merge precedence, sync dry-run output
- Existing test suite passes
- Docs: new `docs/enterprise.md`

---

### Phase 6 — Observability

> Know that the scanner itself is healthy, measure what it does, and prove it ran.

---

#### PLAN-19: Scan Telemetry & Metrics

**Problem:** There is no way to know how long scans take, which scanners are slow, or how finding counts change over time across the entire fleet. Operators can't detect regressions in scanner performance without instrumenting the scanner itself.

**Scope:**
- Emit structured metrics at the end of every scan: scan duration (total and per-scanner), finding count by scanner/severity, scanner exit codes, image size used
- Export via two backends: `--metrics-file <path>` writes `metrics.json` locally; `--metrics-otlp <endpoint>` pushes spans/metrics to any OpenTelemetry-compatible collector (Prometheus, Datadog, Grafana Cloud, etc.)
- Dashboard UI surfaces aggregate metrics for each project: avg scan duration, scanner error rate, last-scan timestamp
- Grafana dashboard JSON bundled in `docs/grafana/ez-appsec-dashboard.json` as a ready-to-import starter

**Out of scope:** Custom metric dimensions per rule; distributed tracing within the scanner; alerting rules.

**Technical approach:**
- New `ez_appsec/telemetry.py` with `ScanMetrics` dataclass and two emitters: `JsonFileEmitter` and `OtlpEmitter` (uses `opentelemetry-sdk`, optional dep)
- `ScanMetrics` populated in `ez_appsec/scanner.py` via context manager wrapping each scanner call
- `metrics.json` schema mirrors the history entry shape from PLAN-05 with added `duration_ms` and `scanner_errors` fields
- `opentelemetry-sdk` added as an optional `extras_require` group in `setup.py`

**Done criteria:**
- `tests/test_telemetry.py` covering: correct per-scanner duration capture, JSON file written with correct schema, OTLP emitter calls mocked collector endpoint with correct span attributes
- Existing test suite passes
- `docs/observability.md` documents the `metrics.json` schema, OTLP setup, and Grafana import steps

---

#### PLAN-20: Audit Log

**Problem:** Compliance frameworks (SOC 2 CC7, PCI DSS 10.x) require evidence that security scans ran, when they ran, who triggered them, and what changed. Today there is no tamper-evident record.

**Scope:**
- Append-only `data/projects/<slug>/audit.json` written by the scanner at the end of each run
- Each entry records: ISO timestamp, trigger actor (`CI_COMMIT_AUTHOR` / `GITHUB_ACTOR` / `--actor` flag), trigger type (`push`, `schedule`, `manual`), scanner version, finding delta vs previous scan, policy outcome
- `ez-appsec audit --project <slug>` CLI command prints the log in human-readable table form
- `ez-appsec audit --project <slug> --format json` outputs the raw array (pipe-friendly)
- Dashboard surface: "Last scan by / at" shown on each project card; full log accessible via a project detail panel

**Out of scope:** Cryptographic signing of log entries; log forwarding to SIEM; retention policy enforcement.

**Technical approach:**
- New `ez_appsec/audit.py` with `AuditEntry` dataclass and `append_audit_entry(slug, entry, dashboard_repo)` function
- Called at end of scan pipeline in `ez_appsec/scanner.py`, after policy evaluation
- Dashboard repo write via the same `git commit` mechanism used for `vulnerabilities.json` ingest
- `audit` sub-command added to the CLI via `ez_appsec/cli.py`

**Done criteria:**
- `tests/test_audit.py` covering: entry appended on scan completion, finding delta calculated correctly, missing previous scan treated as all-new, `--format json` output is valid JSON array
- Existing test suite passes
- Docs: `docs/observability.md` extended with audit log schema reference and compliance mapping (SOC 2 CC7, PCI DSS 10.2)

---

### Phase 7 — Agentic

> Make ez-appsec a first-class participant in multi-agent systems, not just a CLI tool.

---

#### PLAN-21: Reusable Security Agent with MCP & Multi-Transport

**Problem:** The current `ez-appsec-mcp` server is a thin tool wrapper with no agent loop, no multi-step reasoning, and no ability to autonomously triage and act on findings. It only supports stdio transport, locking it to Claude Code and Cursor. As AI orchestration evolves (MCP HTTP, A2A, OpenAI tool format), ez-appsec needs a proper agent core that works across all of them.

**Scope:**
- `ez_appsec/agent.py` — Claude-powered security agent using the Anthropic SDK with a full tool-use loop; callable from Python, CLI, MCP, and HTTP
- Upgrade `ez-appsec-mcp` to use the agent as its backend (replacing direct function calls)
- HTTP+SSE MCP transport alongside existing stdio — enables Claude.ai web and any HTTP-capable MCP client
- MCP Resources — `vulnerabilities.json`, `history.json`, project list as browsable resources
- MCP Prompts — reusable `security-audit`, `cve-triage`, `compliance-check` prompts
- A2A agent card (`/.well-known/agent.json`) — makes ez-appsec callable from Google ADK, LangGraph, CrewAI, and any A2A 0.2+ orchestrator
- Pluggable tool registry — PLAN-01 through PLAN-20 features register agent tools without modifying `agent.py`

**Out of scope:** Building a multi-agent orchestration platform; replacing the MCP server entirely; IDE integrations (see PLAN-13).

**Technical approach:**
- `SecurityAgent` class with `run(task: str) -> AgentResult` and `register_tool()` for extensibility
- Anthropic SDK tool-use loop with prompt caching on system prompt + tool definitions
- `ez-appsec-mcp` gains `--transport http --port 8080` flag; HTTP server is FastAPI + SSE
- A2A: `GET /.well-known/agent.json` agent card + `POST /a2a` Task/TaskResult endpoints
- `ez-appsec agent "<natural language task>"` CLI command

**Security requirements:**
- **Input validation:** all tool arguments (`path`, `task`, A2A `message`) must be validated before use; path arguments must be resolved and checked against an allowlist/CWD to prevent path traversal; task strings must be length-capped (4 096 chars) to prevent prompt injection amplification
- **Least privilege:** the agent may only read/write files under the path it was invoked on; it must not accept shell commands or eval arbitrary code from tool arguments or model output
- **Secret hygiene:** `AgentResult` and all log output must redact values that match secret patterns (gitleaks rule IDs); the agent must never echo raw secret values in its summary or tool responses
- **Transport security:** HTTP transport must require TLS in production (document how to run behind a reverse proxy with TLS termination); API key must be a minimum 32-byte random value; keys must be compared with `hmac.compare_digest` to prevent timing attacks
- **Prompt injection hardening:** findings content injected into agent context must be wrapped in a clearly delimited block (`<finding>…</finding>`) so the model can distinguish data from instructions; the system prompt must include an explicit instruction not to follow commands embedded in finding content
- **Rate limiting:** HTTP transport must enforce per-IP rate limiting (default: 60 req/min) via middleware; configurable via `EZ_APPSEC_RATE_LIMIT` env var
- **Dependency pinning:** `pyproject.toml` must pin Anthropic SDK to a minor version range (`>=0.40,<1.0`) to prevent silent breaking changes from auto-upgrades
- **`tests/test_agent_security.py`:** path traversal attempt raises `ValueError`; secret value redacted in `AgentResult.summary`; task string over 4 096 chars raises `ValueError`; prompt injection marker in finding content does not change agent tool-call behavior (mocked model returns canonical response regardless)

**Done criteria:**
- `tests/test_agent.py` — mocked Anthropic SDK: tool-use loop completes; `register_tool` adds to schema; `AgentResult` contains findings and summary
- `tests/test_agent_security.py` — all security requirement cases above pass
- `ez-appsec-mcp` tests: existing 4 tools backwards compatible; HTTP transport SSE stream works; `X-API-Key` missing → 401; API key compared with `hmac.compare_digest`
- `tests/test_a2a.py` — valid agent card; `POST /a2a` with Task → TaskResult with findings
- MCP Resources and Prompts render correctly in Claude Code (manual verification)
- `pytest tests/` passes in both repos

---

## Execution Plan

### Step 1 — This document ✅
Create `ROADMAP.md` as the canonical source of truth for planned work.

### Step 2 — GitHub Project
Create a GitHub Project at `github.com/orgs/ez-appsec/projects` with one issue per PLAN. Issues use the labels: `roadmap`, `phase-1` through `phase-6`, and `good first issue` for PLAN-01, PLAN-02, PLAN-03.

### Step 3 — GitLab Mirror
Create a GitLab group-level board at `gitlab.com/jfelten.work-group/ez_appsec` mirroring the GitHub issues. GitLab is used for sprint reporting and burn-down tracking.

### Step 4 — Issue Templates
Add `.github/ISSUE_TEMPLATE/ai-plan.md` — a structured template for contributors (human or AI) claiming a PLAN. Fields: plan ID, approach notes, test strategy, PR link.

### Step 5 — Claiming Work
Any contributor (human or AI agent) claims a plan by:
1. Opening an issue on GitHub using the `ai-plan` template
2. Self-assigning and moving to "In Progress" on the project board
3. Opening a draft PR that references the issue
4. Passing all existing tests + adding the plan's required tests before requesting review

---

## Contribution Notes

- **No plan modifies another plan's primary module.** If PLAN-09 and PLAN-02 both touch `config.py`, the second to merge resolves any conflict — the modules are written to be additive.
- **Tests first.** Each plan's done criteria lists test file names. Write the tests before or alongside the implementation.
- **Schema stability.** The unified `vulnerabilities.json` schema is append-only — new fields may be added but existing fields must not be renamed or removed.
- **Docker size budget.** Plans that add new runtime dependencies must verify the standard image stays under 2 GB (`docker image inspect` after build).

---

## Proposed

> Ideas that have been accepted but not yet fully spec'd into a PLAN issue.
> Each entry is a one-liner. A maintainer converts it to a full plan issue when someone is ready to implement it.
> To propose something new, open a [Plan Proposal issue](https://github.com/ez-appsec/ez-appsec/issues/new?template=plan-proposal.md) or start a discussion in [Ideas](https://github.com/ez-appsec/ez-appsec/discussions/categories/ideas).

| ID | Problem | Phase | Source |
|---|---|---|---|
| PLAN-19 | Scan telemetry — emit structured metrics per scanner run and expose via OTLP | 6 | [ROADMAP](ROADMAP.md) |
| PLAN-20 | Audit log — append-only tamper-evident record of every scan run for SOC2/PCI evidence | 6 | [ROADMAP](ROADMAP.md) |
| PLAN-22 | Schema v2 — stable `finding_id`/`scan_id` primary keys, `first_seen`/`last_seen`/`sla_deadline` time fields, `trend` | 8 | [#23](https://github.com/ez-appsec/ez-appsec/issues/23) |
| PLAN-23 | AI remediation attributes + storage adapters — `fix_type`, `fix_complexity`, `ai_context`; pluggable SQL/NoSQL `StorageBackend` | 8 | [#23](https://github.com/ez-appsec/ez-appsec/issues/23) |
| PLAN-24 | Dashboard export + observability feed — CSV/SARIF/JSON export buttons; `otel_attributes` block; Prometheus `/metrics` endpoint | 8 | [#23](https://github.com/ez-appsec/ez-appsec/issues/23) |
