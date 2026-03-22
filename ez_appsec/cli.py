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
    """Quick security check without full AI analysis"""
    try:
        scanner = SecurityScanner(Config())
        results = scanner.quick_check(path)
        
        click.echo(f"Quick Check Results:")
        click.echo(f"  Files scanned: {results['files_scanned']}")
        click.echo(f"  Potential issues: {results['issue_count']}")
        
    except Exception as e:
        click.echo(f"✗ Error: {str(e)}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
