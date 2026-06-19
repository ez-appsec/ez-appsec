"""Main CLI entry point for ez-appsec"""

import json
import os
import click
import sys
from pathlib import Path

from ez_appsec.scanner import SecurityScanner
from ez_appsec.config import Config
from ez_appsec.baseline import load_baseline, diff_findings
from ez_appsec.notifier import notify_on_new_findings
from ez_appsec.jira_sync import JiraConfig, sync_findings as jira_sync_findings, should_sync as jira_should_sync


@click.group()
@click.version_option()
def main():
    """ez-appsec: AI-powered application security scanning"""
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--ai-prompt", help="Custom AI prompt for security analysis")
@click.option("--languages", multiple=True, help="Programming languages to scan")
@click.option("--severity", default=None, help="Minimum severity level to report")
@click.option("--output", type=click.Path(), help="Output file for results (JSON)")
@click.option("--config", "config_file", type=click.Path(), default=".ez-appsec.yaml", help="Path to config file")
@click.option("--baseline", "baseline_path", type=str, default=None, help="Baseline file path or URL for new-findings-only mode")
@click.option("--baseline-threshold", type=int, default=0, help="Max new findings before non-zero exit (default: 0)")
@click.option("--slack-webhook", envvar="EZ_APPSEC_SLACK_WEBHOOK", default=None, help="Slack incoming webhook URL for notifications")
@click.option("--teams-webhook", envvar="EZ_APPSEC_TEAMS_WEBHOOK", default=None, help="Teams incoming webhook URL for notifications")
@click.option("--project-name", envvar="EZ_APPSEC_PROJECT_NAME", default=None, help="Project name for notifications")
@click.option("--dashboard-url", envvar="EZ_APPSEC_DASHBOARD_URL", default=None, help="Dashboard URL included in notifications")
@click.option("--jira-url", envvar="EZ_APPSEC_JIRA_URL", default=None, help="Jira instance URL (e.g. https://myteam.atlassian.net)")
@click.option("--jira-email", envvar="EZ_APPSEC_JIRA_EMAIL", default=None, help="Jira user email for API auth")
@click.option("--jira-token", envvar="EZ_APPSEC_JIRA_TOKEN", default=None, help="Jira API token")
@click.option("--jira-project", envvar="EZ_APPSEC_JIRA_PROJECT", default=None, help="Jira project key for new issues")
@click.option("--sbom/--no-sbom", default=False, help="Generate CycloneDX SBOM alongside scan results")
@click.option("--sbom-output", type=click.Path(), default="sbom.cdx.json", help="Output path for SBOM file (default: sbom.cdx.json)")
@click.option("--license-check", is_flag=True, default=False, help="Run license compliance check (requires syft)")
def scan(path, ai_prompt, languages, severity, output, config_file, baseline_path, baseline_threshold, slack_webhook, teams_webhook, project_name, dashboard_url, jira_url, jira_email, jira_token, jira_project, sbom, sbom_output, license_check):
    """Scan a codebase for security vulnerabilities using AI analysis

    PATH: Directory or file to scan (default: current directory)
    """
    try:
        config = Config.from_file(config_file)
        if languages:
            config.languages = list(languages)
        if severity:
            config.severity = severity
        if output:
            config.output_file = output

        scanner = SecurityScanner(config, license_check=license_check)
        results = scanner.scan(path, ai_prompt)

        if baseline_path:
            baseline = load_baseline(baseline_path)
            new_findings, existing_findings = diff_findings(results["issues"], baseline)
            results["issues"] = new_findings
            results["total"] = len(new_findings)
            results["baseline_existing"] = len(existing_findings)

            click.echo(f"\n✓ Security scan completed (baseline mode)")
            click.echo(f"  {len(new_findings)} new, {len(existing_findings)} existing (baseline-suppressed)")
        else:
            click.echo(f"\n✓ Security scan completed")
            click.echo(f"  Total issues found: {len(results['issues'])}")

        # v2 trend signal - surface new/resolved counts and aging when the
        # scanner computed them. This is the headline value of schema v2:
        # answering "what changed since last scan?" without digging into JSON.
        scan_record = results.get("scan_record") or {}
        new_count = scan_record.get("new_count")
        resolved_count = scan_record.get("resolved_count")
        if not baseline_path and (new_count is not None or resolved_count is not None):
            parts = []
            if new_count is not None:
                parts.append(f"{new_count} new")
            if resolved_count is not None:
                parts.append(f"{resolved_count} resolved")
            if parts:
                click.echo(f"  Trend: {', '.join(parts)} since last scan")
            aging = [
                i for i in results["issues"]
                if isinstance(i.get("age_days"), int) and i["age_days"] > 30
            ]
            if aging:
                click.echo(f"  Aging: {len(aging)} finding(s) older than 30 days")

        if results.get('suppressed', 0) > 0:
            click.echo(f"  [suppressed] {results['suppressed']} finding(s) matched ignore rules")

        if results['issues']:
            click.echo("\nTop Issues:")
            for issue in results['issues'][:5]:
                click.echo(f"  [{issue['severity']}] {issue['title']}")
                click.echo(f"    {issue['description']}")

        if output:
            if results.get("output_path"):
                click.echo(f"\n✓ Results saved to: {results['output_path']}")
            else:
                try:
                    with open(output, 'w') as f:
                        json.dump(results, f, indent=2)
                    click.echo(f"\n✓ Results saved to: {output}")
                except Exception as e:
                    click.echo(f"\n✗ Error writing results to file: {str(e)}", err=True)
                    sys.exit(1)

        if slack_webhook or teams_webhook:
            proj = project_name or os.path.basename(os.path.abspath(path))
            notif = notify_on_new_findings(
                results["issues"],
                project_name=proj,
                dashboard_url=dashboard_url or "",
                slack_webhook=slack_webhook,
                teams_webhook=teams_webhook,
            )
            if notif["notified"]:
                click.echo(f"\n✓ Notifications sent", nl=False)
                parts = []
                if notif["slack"]:
                    parts.append("Slack")
                if notif["teams"]:
                    parts.append("Teams")
                click.echo(f" ({', '.join(parts)})")
            elif notif["reason"]:
                click.echo(f"\n  Notifications skipped: {notif['reason']}")

        jira_cfg = None
        if jira_url and jira_email and jira_token and jira_project:
            jira_cfg = JiraConfig(
                url=jira_url.rstrip("/"),
                email=jira_email,
                token=jira_token,
                project_key=jira_project,
            )
        elif not jira_url and not jira_email and not jira_token and not jira_project:
            jira_cfg = JiraConfig.from_env()

        if jira_cfg and results["issues"] and jira_should_sync(results["issues"]):
            proj = project_name or os.path.basename(os.path.abspath(path))
            map_path = os.path.join("data", "projects", proj, "jira_map.json")
            jira_result = jira_sync_findings(
                results["issues"],
                jira_cfg,
                map_path,
                dashboard_url=dashboard_url or "",
            )
            created = jira_result["created"]
            closed = jira_result["closed"]
            errors = jira_result["errors"]
            parts = []
            if created:
                parts.append(f"{len(created)} created")
            if closed:
                parts.append(f"{len(closed)} closed")
            if jira_result["skipped_existing"]:
                parts.append(f"{len(jira_result['skipped_existing'])} existing")
            if parts:
                click.echo(f"\n✓ Jira sync: {', '.join(parts)}")
            if errors:
                click.echo(f"  ⚠ {len(errors)} Jira error(s)", err=True)

        if sbom:
            from ez_appsec.sbom import generate_cyclonedx
            try:
                generate_cyclonedx(path, sbom_output)
                click.echo(f"\n✓ SBOM generated: {sbom_output}")
            except Exception as sbom_err:
                click.echo(f"\n⚠ SBOM generation failed: {sbom_err}", err=True)

        # License compliance results
        if results.get("license_summary"):
            ls = results["license_summary"]
            click.echo(f"\n  License check: {ls['total']} package(s) - "
                        f"{ls['allowed']} allowed, {ls['denied']} denied, {ls['unknown']} unknown")
            license_findings = [i for i in results['issues'] if i.get('category') == 'license_compliance']
            if ls["denied"] > 0:
                click.echo(f"  ✗ {ls['denied']} denied license(s) found:", err=True)
                for f in license_findings:
                    if f['severity'] == 'high':
                        extras = ""
                        if len(f.get('all_licenses', [])) > 1:
                            extras = f" (also declares: {', '.join(l for l in f['all_licenses'] if l != f['license'])})"
                        click.echo(f"    - {f['package']}@{f['package_version']}: {f['license']}{extras}", err=True)
            if ls["unknown"] > 0:
                click.echo(f"  ⚠ {ls['unknown']} unknown license(s) - review and add to allowed_licenses or denied_licenses:")
                for f in license_findings:
                    if f['severity'] == 'medium':
                        click.echo(f"    - {f['package']}@{f['package_version']}: {f['license']}")

        # Policy evaluation results
        if results.get("policy_violations"):
            for v in results["policy_violations"]:
                prefix = "✗ FAIL" if v["action"] == "fail" else "⚠ WARN"
                click.echo(f"\n  {prefix}: {v['description']}", err=(v["action"] == "fail"))

        if results.get("policy_failed"):
            click.echo(f"\n✗ Policy check failed", err=True)
            sys.exit(1)

        if baseline_path and len(results["issues"]) > baseline_threshold:
            click.echo(f"\n✗ {len(results['issues'])} new finding(s) exceed threshold ({baseline_threshold})", err=True)
            sys.exit(1)

    except Exception as e:
        click.echo(f"✗ Error: {str(e)}", err=True)
        sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--ai-prompt", help="Custom AI prompt for security analysis")
@click.option("--severity", default=None, help="Minimum severity level to report")
@click.option("--output", type=click.Path(), help="Output file for GitLab vulnerability report (JSON)")
@click.option("--config", "config_file", type=click.Path(), default=".ez-appsec.yaml", help="Path to config file")
def gitlab_scan(path, ai_prompt, severity, output, config_file):
    """Scan a codebase and output results in GitLab vulnerability format

    PATH: Directory or file to scan (default: current directory)
    """
    try:
        config = Config.from_file(config_file)
        if severity:
            config.severity = severity

        scanner = SecurityScanner(config)
        results = scanner.scan_to_gitlab_format(path, output, ai_prompt)

        click.echo(f"\n✓ GitLab vulnerability scan completed")
        click.echo(f"  Total vulnerabilities found: {len(results['vulnerabilities'])}")
        if results.get('suppressed_count', 0) > 0:
            click.echo(f"  [suppressed] {results['suppressed_count']} finding(s) matched ignore rules")

        if results['vulnerabilities']:
            click.echo("\nTop Vulnerabilities:")
            for vuln in results['vulnerabilities'][:5]:
                click.echo(f"  [{vuln['severity']}] {vuln['name']}")
                click.echo(f"    {vuln['message']}")

        if output:
            click.echo(f"\n✓ GitLab report saved to: {output}")
        else:
            click.echo("  Use --output to save report to file")

    except Exception as e:
        click.echo(f"✗ Error: {str(e)}", err=True)
        sys.exit(1)


@main.command()
def init():
    """Initialize ez-appsec configuration in current directory"""
    config_path = Path(".ez-appsec.yaml")

    if config_path.exists():
        click.echo("✓ Configuration already exists at .ez-appsec.yaml")
        return

    config_content = """# ez-appsec configuration
languages:
  - python
  - javascript
  - go
  - java

severity: medium

# AI model configuration
ai:
  model: gpt-4
  temperature: 0.5

# Ignore rules - suppress known false positives
# ignore:
#   - rule_id: generic-api-key
#     file_path: "tests/**"
#     reason: "Test fixtures with dummy credentials"
#     permanent: true
#   - cve_id: CVE-2023-1234
#     reason: "Mitigated, revisit later"
#     until: "2025-06-01"

# Policy rules - enforce security standards
# policy:
#   - severity: critical
#     action: fail
#     max_count: 0
#   - severity: high
#     category: secrets
#     action: fail
#     max_count: 0
#   - severity: high
#     action: warn
#     max_count: 5

# License compliance - SPDX identifiers (see https://spdx.org/licenses/)
# Supports wildcards: GPL* matches GPL-2.0, GPL-3.0-only, etc.
# Run with: ez-appsec scan --license-check
# license_policy:
#   allowed_licenses:
#     - MIT
#     - Apache-2.0
#     - BSD-2-Clause
#     - BSD-3-Clause
#     - ISC
#     - 0BSD
#     - Unlicense
#   denied_licenses:
#     - GPL*
#     - AGPL*
#     - SSPL*
#     - EUPL*
"""

    with open(config_path, "w") as f:
        f.write(config_content)

    click.echo(f"✓ Configuration created at {config_path}")


@main.command()
@click.argument("path", type=click.Path(exists=True), default=".")
def check(path):
    """Quick secrets check using gitleaks only"""
    try:
        scanner = SecurityScanner(Config())
        results = scanner.quick_check(path)

        click.echo(f"Quick Check Results:")
        click.echo(f"  Files scanned: {results['files_scanned']}")
        click.echo(f"  Potential issues: {results['issue_count']}")

        if results['issue_count'] == 0:
            click.echo("  ✓ No secrets detected")
        else:
            click.echo("  ⚠️  Potential secrets found - review above")

    except Exception as e:
        click.echo(f"✗ Error: {str(e)}", err=True)
        sys.exit(1)


@main.command("check-config")
@click.argument("config_path", type=click.Path(), default=".ez-appsec.yaml")
def check_config(config_path):
    """Validate an .ez-appsec.yaml configuration file

    CONFIG_PATH: Path to config file (default: .ez-appsec.yaml)
    """
    config_file = Path(config_path)
    if not config_file.exists():
        click.echo(f"✗ Config file not found: {config_path}", err=True)
        sys.exit(1)

    try:
        import yaml as _yaml
        with open(config_file) as f:
            raw = _yaml.safe_load(f)
        if not isinstance(raw, dict):
            click.echo(f"✗ Config file must be a YAML mapping, got {type(raw).__name__}", err=True)
            sys.exit(1)
    except _yaml.YAMLError as e:
        click.echo(f"✗ Invalid YAML syntax: {e}", err=True)
        sys.exit(1)

    errors = []

    valid_severities = {"all", "critical", "high", "medium", "low"}
    if "severity" in raw and raw["severity"] not in valid_severities:
        errors.append(f"Invalid severity '{raw['severity']}' - must be one of: {', '.join(sorted(valid_severities))}")

    ignore_data = raw.get("ignore", [])
    if not isinstance(ignore_data, list):
        errors.append(f"'ignore' must be a list, got {type(ignore_data).__name__}")
        ignore_data = []

    for i, item in enumerate(ignore_data):
        prefix = f"ignore[{i}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: must be a mapping, got {type(item).__name__}")
            continue
        has_matcher = any(item.get(k) for k in ("rule_id", "file_path", "message", "cve_id"))
        if not has_matcher:
            errors.append(f"{prefix}: must specify at least one matcher (rule_id, file_path, message, or cve_id)")
        if not item.get("permanent") and not item.get("until"):
            errors.append(f"{prefix}: must set 'permanent: true' or provide 'until' date")
        if item.get("until"):
            try:
                from datetime import datetime
                datetime.fromisoformat(item["until"])
            except (ValueError, TypeError):
                errors.append(f"{prefix}: 'until' must be ISO date (YYYY-MM-DD), got '{item['until']}'")
        if not item.get("reason"):
            errors.append(f"{prefix}: 'reason' is required")

    # Validate policy rules if present
    policy_data = raw.get("policy", [])
    if not isinstance(policy_data, list):
        errors.append(f"'policy' must be a list, got {type(policy_data).__name__}")
        policy_data = []

    valid_policy_severities = {"critical", "high", "medium", "low"}
    valid_policy_categories = {"secrets", "sast", "iac", "cve", "dependency_scanning"}
    valid_policy_actions = {"fail", "warn", "ignore"}

    for i, item in enumerate(policy_data):
        prefix = f"policy[{i}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: must be a mapping, got {type(item).__name__}")
            continue
        if "action" not in item:
            errors.append(f"{prefix}: 'action' is required")
        elif item["action"] not in valid_policy_actions:
            errors.append(f"{prefix}: invalid action '{item['action']}' - must be one of: {', '.join(sorted(valid_policy_actions))}")
        if "severity" in item and item["severity"] not in valid_policy_severities:
            errors.append(f"{prefix}: invalid severity '{item['severity']}' - must be one of: {', '.join(sorted(valid_policy_severities))}")
        if "category" in item and item["category"] not in valid_policy_categories:
            errors.append(f"{prefix}: invalid category '{item['category']}' - must be one of: {', '.join(sorted(valid_policy_categories))}")
        if "max_count" in item and not isinstance(item["max_count"], int):
            errors.append(f"{prefix}: 'max_count' must be an integer")

    # Validate license_policy if present
    license_data = raw.get("license_policy")
    if license_data is not None:
        if not isinstance(license_data, dict):
            errors.append(f"'license_policy' must be a mapping, got {type(license_data).__name__}")
        else:
            allowed = license_data.get("allowed_licenses", [])
            denied = license_data.get("denied_licenses", [])
            if not isinstance(allowed, list):
                errors.append(f"license_policy.allowed_licenses must be a list, got {type(allowed).__name__}")
            if not isinstance(denied, list):
                errors.append(f"license_policy.denied_licenses must be a list, got {type(denied).__name__}")
            if isinstance(allowed, list) and isinstance(denied, list) and not allowed and not denied:
                errors.append("license_policy must specify at least one of allowed_licenses or denied_licenses")

    if errors:
        click.echo(f"✗ {len(errors)} error(s) in {config_path}:")
        for err in errors:
            click.echo(f"  - {err}")
        sys.exit(1)

    try:
        config = Config.from_file(config_path)
    except Exception as e:
        click.echo(f"✗ Config loading failed: {e}", err=True)
        sys.exit(1)

    rule_count = len(config.ignore_rules)
    active_count = sum(1 for r in config.ignore_rules if r.is_active())
    click.echo(f"✓ {config_path} is valid")
    click.echo(f"  Severity: {config.severity}")
    if rule_count:
        click.echo(f"  Ignore rules: {rule_count} ({active_count} active)")
    if config.policy_rules:
        click.echo(f"  Policy rules: {len(config.policy_rules)}")
    if config.license_policy:
        lp = config.license_policy
        parts = []
        if lp.allowed_licenses:
            parts.append(f"{len(lp.allowed_licenses)} allowed")
        if lp.denied_licenses:
            parts.append(f"{len(lp.denied_licenses)} denied")
        click.echo(f"  License policy: {', '.join(parts)}")


@main.command()
def status():
    """Check status of all security scanners"""
    from ez_appsec.external_scanners import ExternalScannerManager

    manager = ExternalScannerManager()
    installed = manager.get_installed()

    click.echo("Scanner Status:")
    for name, is_installed in installed.items():
        status = "✓ installed" if is_installed else "✗ not installed"
        click.echo(f"  {name}: {status}")

    missing = [name for name, inst in installed.items() if not inst]
    if missing:
        click.echo("\nInstall missing scanners:")
        for line in manager.get_install_instructions().split("\n"):
            click.echo(f"  {line}")


@main.command("serve-metrics")
@click.option(
    "--host",
    default="127.0.0.1",
    show_default=True,
    help="Bind host (use 0.0.0.0 to expose; ensure an auth layer is in front)",
)
@click.option("--port", default=9108, show_default=True, help="Listen port")
@click.option(
    "--findings",
    "storage_path",
    type=click.Path(),
    default="vulnerabilities.json",
    show_default=True,
    help="Path to vulnerabilities.json produced by scan",
)
@click.option("--project", default=None, help="Override the project label")
@click.option(
    "--storage-backend",
    type=click.Choice(["json", "sql"]),
    default=None,
    help="Storage backend (default: from EZ_APPSEC_STORAGE_BACKEND, else json)",
)
def serve_metrics(host, port, storage_path, project, storage_backend):
    """Serve Prometheus metrics for the latest scan findings

    Exposes GET /metrics in Prometheus text exposition format, grouped by
    severity, category, and project. Reads findings from the configured
    storage backend (JSON file or SQL via EZ_APPSEC_STORAGE_URL).

    Requires the optional 'metrics' extra: pip install 'ez-appsec[metrics]'.

    \b
    Examples:
      ez-appsec serve-metrics
      ez-appsec serve-metrics --findings /data/vulnerabilities.json --project api
      EZ_APPSEC_STORAGE_URL=sqlite:///findings.db ez-appsec serve-metrics --storage-backend sql

    \b
    Note: --host 0.0.0.0 binds to all interfaces. The endpoint is
    unauthenticated; put it behind a reverse proxy with auth, or bind to
    loopback (the default) and scrape from the same host.
    """
    import os

    if storage_backend:
        os.environ["EZ_APPSEC_STORAGE_BACKEND"] = storage_backend

    from ez_appsec.metrics_endpoint import (
        MetricsDependencyError,
        serve_metrics as _serve,
    )

    try:
        click.echo(f"Serving ez-appsec metrics on http://{host}:{port}/metrics")
        click.echo(f"  findings: {storage_path}")
        if storage_backend:
            click.echo(f"  backend:  {storage_backend}")
        click.echo("  (Ctrl-C to stop)")
        _serve(host=host, port=port, storage_path=storage_path, project=project)
    except MetricsDependencyError as exc:
        click.echo(f"✗ {exc}", err=True)
        sys.exit(1)
    except Exception as exc:
        click.echo(f"✗ Error: {exc}", err=True)
        sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--output", type=click.Path(), help="Output directory for web dashboard", default="./web/data")
def web_report(path, output):
    """Generate web dashboard for vulnerability reporting

    Generates a JSON report compatible with the web vulnerability dashboard
    and optionally creates the dashboard files.

    PATH: Directory to scan (default: current directory)
    """
    try:
        import json
        from pathlib import Path as PathlibPath

        config = Config()
        scanner = SecurityScanner(config)

        # Generate GitLab format report
        gitlab_report = scanner.scan_to_gitlab_format(path)

        # Create output directory
        output_dir = PathlibPath(output)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Save vulnerabilities to web data directory
        report_file = output_dir / "vulnerabilities.json"
        with open(report_file, 'w') as f:
            json.dump(gitlab_report, f, indent=2)

        click.echo(f"\n✓ Web report generated")
        click.echo(f"  Vulnerabilities: {len(gitlab_report['vulnerabilities'])}")
        click.echo(f"  Report saved: {report_file}")
        click.echo(f"\n📊 To view the dashboard:")
        click.echo(f"  cd web && python -m http.server 8000")
        click.echo(f"  Then open http://localhost:8000")

    except Exception as e:
        click.echo(f"✗ Error: {str(e)}", err=True)
        sys.exit(1)


@main.command("update-web")
@click.argument("vulns_file", type=click.Path(exists=True))
@click.option(
    "--web-dir",
    type=click.Path(),
    default=None,
    help="Web dashboard directory (default: /web if present, else ./web)",
)
@click.option("--serve", is_flag=True, help="Serve the dashboard on a local HTTP server after updating")
@click.option("--port", default=8000, show_default=True, help="Port for --serve")
def update_web(vulns_file, web_dir, serve, port):
    """Update the web dashboard with a vulnerabilities.json file

    \b
    VULNS_FILE: path to a GitLab-format vulnerabilities.json produced by gitlab-scan
    """
    import json
    import shutil
    import webbrowser
    from pathlib import Path as PL

    # Resolve web directory: explicit arg → /web (Docker) → ./web
    if web_dir:
        resolved = PL(web_dir)
    elif PL("/web/data").exists() or PL("/web/index.html").exists():
        resolved = PL("/web")
    else:
        resolved = PL("./web")

    data_dir = resolved / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    dest = data_dir / "vulnerabilities.json"
    shutil.copy2(vulns_file, dest)

    # Quick summary from the copied file
    try:
        with open(dest) as fh:
            report = json.load(fh)
        vulns = report.get("vulnerabilities", [])
        from collections import Counter
        by_sev = Counter(v.get("severity", "unknown") for v in vulns)
        click.echo(f"Vulnerabilities copied to: {dest}")
        click.echo(f"  Total : {len(vulns)}")
        for sev in ("critical", "high", "medium", "low", "info"):
            if by_sev.get(sev):
                click.echo(f"  {sev.capitalize():8}: {by_sev[sev]}")
    except Exception:
        click.echo(f"Copied {vulns_file} → {dest}")

    if serve:
        import http.server
        import functools
        import threading

        handler = functools.partial(
            http.server.SimpleHTTPRequestHandler,
            directory=str(resolved),
        )
        server = http.server.HTTPServer(("", port), handler)
        url = f"http://localhost:{port}"
        click.echo(f"\nServing dashboard at {url}  (Ctrl-C to stop)")
        webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


@main.command("github-scan")
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--ai-prompt", help="Custom AI prompt for security analysis")
@click.option("--languages", multiple=True, help="Programming languages to scan")
@click.option("--severity", default=None, help="Minimum severity level to report")
@click.option("--output", type=click.Path(), help="Output file for SARIF report")
@click.option("--config", "config_file", type=click.Path(), default=".ez-appsec.yaml", help="Path to config file")
def github_scan(path, ai_prompt, languages, severity, output, config_file):
    """Scan a codebase and output results in GitHub SARIF format

    PATH: Directory or file to scan (default: current directory)

    The SARIF format is compatible with GitHub Advanced Security and can be
    uploaded to GitHub's Security tab using the SARIF upload action.
    """
    try:
        config = Config.from_file(config_file)
        if languages:
            config.languages = list(languages)
        if severity:
            config.severity = severity
        if output:
            config.output_file = output

        scanner = SecurityScanner(config)
        results = scanner.scan_to_github_format(path, output, ai_prompt)

        click.echo(f"\n✓ GitHub SARIF scan completed")
        click.echo(f"  Total findings: {len(results['runs'][0]['results'])}")

        if results['runs'][0]['results']:
            click.echo("\nTop Findings:")
            for result in results['runs'][0]['results'][:5]:
                click.echo(f"  [{result['level']}] {result['ruleId']}")
                click.echo(f"    {result['message']['text']}")

        if output:
            click.echo(f"\n✓ SARIF report saved to: {output}")
        else:
            click.echo("  Use --output to save SARIF report to file")

    except Exception as e:
        click.echo(f"✗ Error: {str(e)}", err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


@main.command("pr-comment")
@click.option("--platform", type=click.Choice(["github", "gitlab"]), required=True, help="Platform (github or gitlab)")
@click.option("--findings", type=click.Path(exists=True), required=True, help="Path to vulnerabilities.json or SARIF file")
@click.option("--pr", type=int, help="Pull request number (GitHub)")
@click.option("--mr", type=int, help="Merge request IID (GitLab)")
@click.option("--repo", help="Repository (GitHub: owner/repo, GitLab: project ID)")
@click.option("--gitlab-url", default="https://gitlab.com", help="GitLab instance URL")
def pr_comment(platform, findings, pr, mr, repo, gitlab_url):
    """Post security findings as inline PR/MR comments

    Posts findings from a scan as inline review comments on pull requests
    (GitHub) or merge requests (GitLab). Only comments on lines that were
    changed in the diff.

    For GitHub, uses GITHUB_TOKEN and GITHUB_REPOSITORY env vars if not provided.

    For GitLab, uses GITLAB_ACCESS_TOKEN, CI_PROJECT_ID, and CI_MERGE_REQUEST_IID
    env vars if not provided.
    """
    from ez_appsec.pr_commenter import (
        GitHubPRCommenter,
        GitLabMRCommenter,
        load_findings_from_json
    )

    # Load findings
    click.echo(f"Loading findings from {findings}...")
    all_findings = load_findings_from_json(findings)

    if not all_findings:
        click.echo("No findings found in the specified file.")
        return

    click.echo(f"Loaded {len(all_findings)} findings.")

    try:
        if platform == "github":
            # Get parameters from env vars if not provided
            github_token = os.environ.get("GITHUB_TOKEN")
            if not github_token:
                click.echo("Error: GITHUB_TOKEN environment variable is required", err=True)
                sys.exit(1)

            repo_arg = repo or os.environ.get("GITHUB_REPOSITORY")
            if not repo_arg:
                click.echo("Error: --repo or GITHUB_REPOSITORY environment variable is required", err=True)
                sys.exit(1)

            pr_arg = pr or os.environ.get("GITHUB_EVENT_PATH")
            if pr_arg and not pr:
                # Try to extract PR number from event file
                event_path = os.environ.get("GITHUB_EVENT_PATH")
                if event_path and os.path.exists(event_path):
                    try:
                        with open(event_path) as f:
                            event = json.load(f)
                        pr_arg = event.get("pull_request", {}).get("number")
                    except (json.JSONDecodeError, FileNotFoundError):
                        pass

            if not pr_arg:
                click.echo("Error: --pr or GITHUB_EVENT_PATH with PR number is required", err=True)
                sys.exit(1)

            # Post comments
            click.echo(f"Posting comments to {repo_arg} PR #{pr_arg}...")
            commenter = GitHubPRCommenter(repo_arg, pr_arg, github_token)
            results = commenter.post_findings(all_findings)

            click.echo(f"\nResults:")
            click.echo(f"  Posted: {results['posted']} findings")
            click.echo(f"  Skipped: {results['skipped']} findings (not on changed lines)")
            if results['files_commented']:
                click.echo(f"  Files commented: {', '.join(results['files_commented'])}")

        elif platform == "gitlab":
            # Get parameters from env vars if not provided
            gitlab_token = os.environ.get("GITLAB_ACCESS_TOKEN")
            if not gitlab_token:
                click.echo("Error: GITLAB_ACCESS_TOKEN environment variable is required", err=True)
                sys.exit(1)

            project_id = repo or os.environ.get("CI_PROJECT_ID")
            if not project_id:
                click.echo("Error: --repo or CI_PROJECT_ID environment variable is required", err=True)
                sys.exit(1)

            mr_arg = mr or os.environ.get("CI_MERGE_REQUEST_IID")
            if not mr_arg:
                click.echo("Error: --mr or CI_MERGE_REQUEST_IID environment variable is required", err=True)
                sys.exit(1)

            # Post comments
            click.echo(f"Posting comments to {project_id} MR !{mr_arg}...")
            commenter = GitLabMRCommenter(project_id, mr_arg, gitlab_token, gitlab_url)
            results = commenter.post_findings(all_findings)

            click.echo(f"\nResults:")
            click.echo(f"  Posted: {results['posted']} findings")
            click.echo(f"  Skipped: {results['skipped']} findings (not on changed lines)")
            if results['files_commented']:
                click.echo(f"  Files commented: {', '.join(results['files_commented'])}")

    except Exception as e:
        click.echo(f"\n✗ Error: {str(e)}", err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


@main.command("fix-pr")
@click.option("--repo", required=True, help="Repository (GitHub: owner/repo, GitLab: project ID)")
@click.option("--platform", type=click.Choice(["github", "gitlab"]), default="github", help="Platform")
@click.option("--findings", type=click.Path(exists=True), required=True, help="Path to grype JSON, vulnerabilities.json, or gitleaks JSON")
@click.option("--format", "findings_format", type=click.Choice(["grype", "gitlab", "gitleaks"]), default="grype",
              help="Findings file format (raw grype JSON, GitLab vulnerabilities.json, or gitleaks JSON)")
@click.option("--path", "repo_path", type=click.Path(exists=True), default=".", help="Local repo checkout path")
@click.option("--gitlab-url", default="https://gitlab.com", help="GitLab instance URL")
@click.option("--dry-run", is_flag=True, help="Show what would be changed without creating a PR")
@click.option("--rotate-secrets", is_flag=True, help="Rotate detected secrets and replace with env var references")
@click.option("--secret-store", type=click.Choice(["github", "gitlab", "vault"]), default=None,
              help="Secret store to write rotated secrets to")
def fix_pr(repo, platform, findings, findings_format, repo_path, gitlab_url, dry_run,
           rotate_secrets, secret_store):
    """Open a PR/MR that bumps vulnerable dependencies to fixed versions

    Reads grype scan output (or GitLab-format vulnerabilities.json), groups
    fixable CVEs by package ecosystem, bumps versions in manifest files,
    and opens one PR per ecosystem.

    With --rotate-secrets, reads gitleaks JSON output, rotates exposed secrets
    via provider APIs (AWS IAM, GitHub PATs, GitLab PATs), writes new values
    to the configured --secret-store, and opens a PR replacing hardcoded
    values with environment variable references.

    Supports: package.json, requirements.txt, go.mod, Gemfile, pom.xml
    """
    if rotate_secrets:
        _handle_rotate_secrets(repo, platform, findings, findings_format,
                               repo_path, gitlab_url, dry_run, secret_store)
        return

    from ez_appsec.fix_pr import (
        parse_grype_findings,
        parse_gitlab_findings,
        group_by_ecosystem,
        create_github_pr,
        create_gitlab_mr,
        build_pr_body,
        build_branch_name,
    )

    try:
        if findings_format == "grype":
            deps = parse_grype_findings(findings)
        else:
            deps = parse_gitlab_findings(findings)

        if not deps:
            click.echo("No fixable dependency findings found.")
            return

        click.echo(f"Found {len(deps)} fixable dependency CVE(s).")

        plans = group_by_ecosystem(deps, repo_path)
        if not plans:
            click.echo("No matching package manifests found in the repository.")
            return

        for plan in plans:
            click.echo(f"  {plan.ecosystem} ({plan.manifest_file}): {len(plan.fixes)} fix(es)")

        if platform == "github":
            token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
            result = create_github_pr(repo, repo_path, plans, token=token, dry_run=dry_run)
        else:
            token = os.environ.get("GITLAB_ACCESS_TOKEN") or os.environ.get("GITLAB_TOKEN")
            result = create_gitlab_mr(repo, repo_path, plans, token=token,
                                      gitlab_url=gitlab_url, dry_run=dry_run)

        if result.get("error"):
            click.echo(f"\n✗ {result['error']}", err=True)
            sys.exit(1)

        if dry_run:
            click.echo(f"\n[dry-run] Branch: {result['branch']}")
            click.echo(f"[dry-run] Files modified: {', '.join(result['files_modified'])}")
            click.echo(f"\n[dry-run] PR body preview:\n")
            click.echo(build_pr_body(plans))
        else:
            url_key = "pr_url" if platform == "github" else "mr_url"
            click.echo(f"\n✓ {'PR' if platform == 'github' else 'MR'} created: {result[url_key]}")
            click.echo(f"  Branch: {result['branch']}")
            click.echo(f"  Files: {', '.join(result['files_modified'])}")

    except Exception as e:
        click.echo(f"✗ Error: {str(e)}", err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


@main.command()
@click.option(
    "--framework",
    type=click.Choice(["soc2", "pci-dss", "hipaa"]),
    required=True,
    help="Compliance framework to map findings against",
)
@click.option(
    "--findings",
    type=click.Path(exists=True),
    required=True,
    help="Path to vulnerabilities.json (ez-appsec or GitLab format)",
)
@click.option(
    "--output",
    type=click.Path(),
    default=None,
    help="Output HTML file (default: <framework>-report.html)",
)
def report(framework, findings, output):
    """Generate a compliance report mapping findings to a control framework

    Maps security scan findings to compliance control IDs (SOC 2, PCI DSS 4.0,
    or HIPAA §164.312) and renders a self-contained HTML report.
    """
    from ez_appsec.compliance_reporter import (
        ComplianceReporter,
        load_findings_from_file,
    )

    try:
        finding_list = load_findings_from_file(findings)
    except FileNotFoundError as e:
        click.echo(f"✗ {e}", err=True)
        sys.exit(1)
    except (json.JSONDecodeError, KeyError) as e:
        click.echo(f"✗ Invalid findings file: {e}", err=True)
        sys.exit(1)

    output_path = output or f"{framework}-report.html"

    try:
        reporter = ComplianceReporter(framework)
        result = reporter.generate(finding_list, output_path)
    except ValueError as e:
        click.echo(f"✗ {e}", err=True)
        sys.exit(1)

    click.echo(f"✓ {framework.upper()} compliance report generated")
    total = result["total"]
    mapped = result["mapped"]
    unmapped = result["unmapped"]
    if unmapped:
        click.echo(f"  Findings: {total} total, {mapped} mapped to controls, {unmapped} unmapped")
    else:
        click.echo(f"  Findings mapped: {total}")
    click.echo(f"  Controls assessed: {result['controls_total']}")
    click.echo(f"  Report: {result['path']}")


@main.command("agent")
@click.argument("task")
@click.option("--model", default="claude-sonnet-4-20250514", help="Anthropic model to use")
@click.option("--path", "root_path", type=click.Path(exists=True), default=".", help="Project root for path validation")
def agent_cmd(task, model, root_path):
    """Run the AI security agent with a natural language task

    TASK: What the agent should do, e.g. "scan /path and summarize critical findings"

    Requires ANTHROPIC_API_KEY environment variable.
    """
    from ez_appsec.agent import SecurityAgent

    try:
        agent = SecurityAgent(model=model, allowed_root=root_path)
        result = agent.run(task)

        if result.actions_taken:
            click.echo(f"\nActions taken:")
            for action in result.actions_taken:
                click.echo(f"  - {action}")

        if result.findings:
            click.echo(f"\nFindings: {len(result.findings)}")

        if result.summary:
            click.echo(f"\n{result.summary}")

    except Exception as e:
        click.echo(f"✗ Error: {str(e)}", err=True)
        sys.exit(1)


def _handle_rotate_secrets(repo, platform, findings, findings_format,
                           repo_path, gitlab_url, dry_run, secret_store_type):
    """Handle the --rotate-secrets flow for fix-pr."""
    from ez_appsec.secret_rotator import (
        parse_gitleaks_findings,
        rotate_secrets as do_rotate,
        create_secret_store,
        create_rotation_pr,
        build_rotation_pr_body,
    )

    try:
        secrets = parse_gitleaks_findings(findings)
        if not secrets:
            click.echo("No rotatable secrets found in findings.")
            return

        click.echo(f"Found {len(secrets)} rotatable secret(s).")
        for s in secrets:
            click.echo(f"  {s.rule_id} in {s.file}:{s.line}")

        store = None
        if secret_store_type:
            token = None
            project_id = None
            if platform == "github":
                token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
            else:
                token = os.environ.get("GITLAB_ACCESS_TOKEN") or os.environ.get("GITLAB_TOKEN")
                project_id = repo

            store = create_secret_store(
                secret_store_type, repo=repo, project_id=project_id,
                gitlab_url=gitlab_url, token=token,
            )

        results = do_rotate(secrets, store=store, dry_run=dry_run)

        rotated_count = sum(1 for r in results if r.rotated)
        click.echo(f"\nRotated {rotated_count}/{len(results)} secret(s).")

        result = create_rotation_pr(
            repo, repo_path, results, platform=platform,
            token=(os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
                   if platform == "github"
                   else os.environ.get("GITLAB_ACCESS_TOKEN") or os.environ.get("GITLAB_TOKEN")),
            gitlab_url=gitlab_url, dry_run=dry_run,
        )

        if result.get("error"):
            click.echo(f"\n✗ {result['error']}", err=True)
            sys.exit(1)

        if dry_run:
            click.echo(f"\n[dry-run] Branch: {result['branch']}")
            click.echo(f"[dry-run] Files modified: {', '.join(result['files_modified'])}")
            click.echo(f"\n[dry-run] PR body preview:\n")
            click.echo(build_rotation_pr_body(results))
        else:
            url_key = "pr_url" if platform == "github" else "mr_url"
            click.echo(f"\n✓ {'PR' if platform == 'github' else 'MR'} created: {result[url_key]}")
            click.echo(f"  Branch: {result['branch']}")
            click.echo(f"  Files: {', '.join(result['files_modified'])}")

    except Exception as e:
        click.echo(f"✗ Error: {str(e)}", err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


@main.command("org-sync")
@click.option("--org", required=True, help="GitHub organization name")
@click.option("--config-repo", default=None, help="Config repo (default: <org>/.ez-appsec-config)")
@click.option("--dry-run", is_flag=True, help="Show what would be changed without making changes")
def org_sync(org, config_repo, dry_run):
    """Sync ez-appsec across all repositories in a GitHub organization

    Discovers all repos in the org, merges org-level and repo-level configs,
    and installs/updates the ez-appsec scan workflow in each repository.

    Requires GITHUB_TOKEN with org:read and repo:write permissions.
    """
    from ez_appsec.org_manager import OrgManager

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        click.echo("✗ GITHUB_TOKEN environment variable is required", err=True)
        sys.exit(1)

    try:
        manager = OrgManager(org, token, config_repo=config_repo)

        click.echo(f"Discovering repos in {org}...")
        results = manager.sync_all(dry_run=dry_run)

        if not results:
            click.echo(f"No repositories found in {org}.")
            return

        prefix = "[dry-run] " if dry_run else ""
        success = 0
        errors = 0

        for r in results:
            if r.get("error"):
                click.echo(f"  ✗ {r['repo']}: {r['error']}", err=True)
                errors += 1
            else:
                for action in r["actions"]:
                    click.echo(f"  {prefix}{r['repo']}: {action}")
                success += 1

        click.echo(f"\n{prefix}✓ {success} repo(s) synced")
        if errors:
            click.echo(f"  ⚠ {errors} repo(s) failed", err=True)

    except Exception as e:
        click.echo(f"✗ Error: {str(e)}", err=True)
        sys.exit(1)
if __name__ == "__main__":
    main()
