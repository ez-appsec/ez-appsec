"""PHP Vulnerability Scanner for ez-appsec
Simple version without complex regex to avoid parsing issues
"""

import re
import json
import logging
from pathlib import Path
from typing import List, Dict, Any
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class PHPVulnerabilityScanner(ABC):
    """PHP vulnerability detection patterns"""

    @abstractmethod
    def scan(self, path: str) -> List[Dict[str, Any]]:
        """Scan PHP files for vulnerabilities"""
        pass


class SQLInjectionScanner(PHPVulnerabilityScanner):
    """SQL injection vulnerability detection"""

    def scan(self, path: str) -> List[Dict[str, Any]]:
        """Scan for SQL injection vulnerabilities"""
        issues = []
        base_path = Path(path)

        # Scan all PHP files
        for php_file in base_path.rglob('*.php'):
            try:
                with open(php_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Pattern 1: String concatenation with user input
                if '$_GET[' in content or '$_POST[' in content:
                    if 'SELECT' in content or 'UPDATE' in content or 'INSERT' in content or 'DELETE' in content:
                        self._add_vulnerability(
                            issues,
                            php_file,
                            'SQL Injection',
                            'CRITICAL',
                            f'File {php_file.name}: SQL injection via string concatenation with user input'
                        )

                # Pattern 2: MySQL function with user input
                if 'mysql_query(' in content:
                    self._add_vulnerability(
                            issues,
                            php_file,
                            'SQL Injection',
                            'ERROR',
                            f'File {php_file.name}: SQL injection via unsanitized mysql_query() with user input'
                        )

            except Exception as e:
                logger.warning(f"Error scanning {php_file}: {str(e)}")

        return issues

    def _add_vulnerability(self, issues: List, file_path: str, vuln_type: str, severity: str, message: str):
        """Add vulnerability to results list"""
        issues.append({
            "type": vuln_type,
            "title": f"{vuln_type} in {file_path.name}",
            "description": message,
            "file": str(file_path),
            "severity": severity,
            "scanner": "php-vuln-scanner",
            "language": "php"
        })


class XSSScanner(PHPVulnerabilityScanner):
    """XSS vulnerability detection"""

    def scan(self, path: str) -> List[Dict[str, Any]]:
        """Scan for XSS vulnerabilities"""
        issues = []
        base_path = Path(path)

        # Scan all PHP files
        for php_file in base_path.rglob('*.php'):
            try:
                with open(php_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Pattern 1: Reflected XSS via echo
                if re.search(r'echo \$\$_GET\[', content):
                    self._add_vulnerability(
                        issues,
                        php_file,
                        'XSS',
                        'HIGH',
                        f'File {php_file.name}: Reflected XSS via echo statement'
                    )

                # Pattern 2: Stored XSS via database
                if re.search(r'INSERT INTO.*\$[\w\[]\]', content):
                    self._add_vulnerability(
                        issues,
                        php_file,
                        'XSS',
                        'HIGH',
                        f'File {php_file.name}: Stored XSS via database input'
                    )

                # Pattern 3: DOM XSS via innerHTML
                if re.search(r'innerHTML\s*=\s*\$[\w\[]\]', content):
                    self._add_vulnerability(
                        issues,
                        php_file,
                        'XSS',
                        'HIGH',
                        f'File {php_file.name}: DOM XSS via innerHTML assignment'
                    )

            except Exception as e:
                logger.warning(f"Error scanning {php_file}: {str(e)}")

        return issues


class CommandInjectionScanner(PHPVulnerabilityScanner):
    """Command injection vulnerability detection"""

    def scan(self, path: str) -> List[Dict[str, Any]]:
        """Scan for command injection vulnerabilities"""
        issues = []
        base_path = Path(path)

        # Scan all PHP files
        for php_file in base_path.rglob('*.php'):
            try:
                with open(php_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Pattern 1: system() with user input
                if re.search(r'system\(\s*\$[\w\[]\]', content):
                    self._add_vulnerability(
                        issues,
                        php_file,
                        'Command Injection',
                        'CRITICAL',
                        f'File {php_file.name}: OS command injection via system() with user input'
                    )

                # Pattern 2: exec() with user input
                if re.search(r'exec\(\s*\$[\w\[]\]', content):
                    self._add_vulnerability(
                        issues,
                        php_file,
                        'Command Injection',
                        'CRITICAL',
                        f'File {php_file.name}: OS command injection via exec() with user input'
                    )

            except Exception as e:
                logger.warning(f"Error scanning {php_file}: {str(e)}")

        return issues


def run_php_scanners(path: str) -> List[Dict[str, Any]]:
    """Run all PHP vulnerability scanners and combine results"""
    all_issues = []

    scanners = [
        SQLInjectionScanner(),
        XSSScanner(),
        CommandInjectionScanner()
    ]

    for scanner in scanners:
        try:
            issues = scanner.scan(path)
            all_issues.extend(issues)
        except Exception as e:
            logger.warning(f"Error in {scanner.__class__.__name__}: {str(e)}")

    return all_issues


def main():
    """Main entry point"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 php_vuln_scanner_simple.py <path>")
        sys.exit(1)

    target_path = sys.argv[1]

    print(f"Scanning PHP files in: {target_path}")
    issues = run_php_scanners(target_path)

    print(f"\n✓ PHP vulnerability scan completed")
    print(f" Total issues found: {len(issues)}")

    if issues:
        print("\nVulnerabilities found:")
        for issue in issues[:10]:
            severity_emoji = "🔴" if issue['severity'] == 'CRITICAL' else "🟠"
            print(f" [{severity_emoji}] {issue['severity']}] {issue['title']}")
            print(f"    {issue['description']}")
            print(f"    File: {issue['file']}:{issue['line']}")

    # Save results
    output_path = f"{target_path}/php-vulnerabilities.json"
    with open(output_path, 'w') as f:
        json.dump({
            "issues": issues,
            "total": len(issues),
            "scanner": "php-vuln-scanner-simple",
            "language": "php"
        }, indent=2)

    print(f"\n✓ Results saved to: {output_path}")
