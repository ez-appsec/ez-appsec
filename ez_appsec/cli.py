"""Main CLI entry point for ez-appsec"""

import click
import sys
from pathlib import Path

from ez_appsec.scanner import SecurityScanner
from ez_appsec.config import Config


@click.group()
@click.version_option()
def main():
    """ez-appsec: AI-powered application security scanning"""
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--ai-prompt", help="Custom AI prompt for security analysis")
@click.option("--languages", multiple=True, help="Programming languages to scan")
@click.option("--severity", default="all", help="Minimum severity level to report")
@click.option("--output", type=click.Path(), help="Output file for results (JSON)")
def scan(path, ai_prompt, languages, severity, output):
    """Scan a codebase for security vulnerabilities using AI analysis
    
    PATH: Directory or file to scan (default: current directory)
    """
    try:
        config = Config(
            languages=languages if languages else None,
            severity=severity,
            output_file=output
        )
        
        scanner = SecurityScanner(config)
        results = scanner.scan(path, ai_prompt)
        
        click.echo(f"\n✓ Security scan completed")
        click.echo(f"  Total issues found: {len(results['issues'])}")
        
        if results['issues']:
            click.echo("\nTop Issues:")
            for issue in results['issues'][:5]:
                click.echo(f"  [{issue['severity']}] {issue['title']}")
                click.echo(f"    {issue['description']}")
        
        if output:
            click.echo(f"\n✓ Results saved to: {output}")
            
    except Exception as e:
        click.echo(f"✗ Error: {str(e)}", err=True)
        sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--ai-prompt", help="Custom AI prompt for security analysis")
@click.option("--severity", default="all", help="Minimum severity level to report")
@click.option("--output", type=click.Path(), help="Output file for GitLab vulnerability report (JSON)")
def gitlab_scan(path, ai_prompt, severity, output):
    """Scan a codebase and output results in GitLab vulnerability format
    
    PATH: Directory or file to scan (default: current directory)
    """
    try:
        config = Config(severity=severity)
        
        scanner = SecurityScanner(config)
        results = scanner.scan_to_gitlab_format(path, output, ai_prompt)
        
        click.echo(f"\n✓ GitLab vulnerability scan completed")
        click.echo(f"  Total vulnerabilities found: {len(results['vulnerabilities'])}")
        
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

# Custom rules
custom_rules: []
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


if __name__ == "__main__":
    main()
