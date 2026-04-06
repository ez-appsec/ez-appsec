"""PHP Vulnerability Scanner for ez-appsec
Simple scanner to detect PHP security vulnerabilities in DVWA and similar applications
"""

import re
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
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
                if re.search(r"(SELECT|UPDATE|INSERT|DELETE)\s+.*\$(?:_GET|_POST|_REQUEST|\$_COOKIE)\'", content):
                    self._add_vulnerability(
                        issues,
                        php_file,
                        'SQL Injection',
                        'CRITICAL',
                        f'Line {line_num(1, content)}: SQL injection via string concatenation with user input'
                    )

                # Pattern 2: MySQL function with user input
                if re.search(r'mysql_query\(\s*\$(?:_GET|_POST|_REQUEST|\$_COOKIE)[^"]+\)', content):
                    self._add_vulnerability(
                        issues,
                        php_file,
                        'SQL Injection',
                        'ERROR',
                        f'Line {line_num(2, content)}: SQL injection via unsanitized mysql_query() with user input'
                    )

                # Pattern 3: Integer bypass
                if re.search(r"(SELECT|UPDATE|INSERT|DELETE).*\s*\d+\s*\$", content):
                    self._add_vulnerability(
                        issues,
                        php_file,
                        'SQL Injection',
                        'ERROR',
                        f'Line {line_num(3, content)}: SQL injection via integer bypass (quotes removed)'
                    )

            except Exception as e:
                logger.warning(f"Error scanning {php_file}: {str(e)}")

        return issues

    def _add_vulnerability(self, issues: List, file_path: str, vuln_type: str, severity: str, message: str):
        """Add vulnerability to results list"""
        with open(file_path, 'r', errors='ignore') as f:
            line_num = 1
            for line in f:
                if re.search(r'Line \d+', line):
                    line_num = re.search(r'Line \d+', line).group(1)
                    break

        issues.append({
            "type": "SQL Injection",
            "title": f"{vuln_type} in {file_path.name}",
            "description": message,
            "file": str(file_path),
            "line": line_num,
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
                if re.search(r'echo\s*\$(?:_GET|_POST|\$_REQUEST|\$_COOKIE)[^";]', content):
                    self._add_vulnerability(
                        issues,
                        php_file,
                        'XSS',
                        'HIGH',
                        f'Line {line_num(1, content)}: Reflected XSS via unsanitized echo statement'
                    )

                # Pattern 2: Stored XSS via database
                if re.search(r'(INSERT|UPDATE).*INTO.*\$(?:_GET|_POST|\$_REQUEST|\$_COOKIE)[^"]+\)', content):
                    self._add_vulnerability(
                        issues,
                        php_file,
                        'XSS',
                        'HIGH',
                        f'Line {line_num(2, content)}: Stored XSS via unsanitized database input'
                    )

                # Pattern 3: DOM XSS via innerHTML
                if re.search(r'innerHTML\s*=\s*\$(?:_GET|_POST|\$_REQUEST|\$_COOKIE)[^;]', content):
                    self._add_vulnerability(
                        issues,
                        php_file,
                        'XSS',
                        'HIGH',
                        f'Line {line_num(3, content)}: DOM XSS via unsafe innerHTML assignment'
                    )

                # Pattern 4: DOM XSS via outerHTML
                if re.search(r'outerHTML\s*=\s*\$(?:_GET|_POST|\$_REQUEST|\$_COOKIE)[^;]', content):
                    self._add_vulnerability(
                        issues,
                        php_file,
                        'XSS',
                        'HIGH',
                        f'Line {line_num(4, content)}: DOM XSS via unsafe outerHTML assignment'
                    )

            except Exception as e:
                logger.warning(f"Error scanning {php_file}: {str(e)}")

        return issues

    def _add_vulnerability(self, issues: List, file_path: str, vuln_type: str, severity: str, message: str):
        """Add vulnerability to results list"""
        with open(file_path, 'r', errors='ignore') as f:
            line_num = 1
            for line in f:
                if re.search(r'Line \d+', line):
                    line_num = re.search(r'Line \d+', line).group(1)
                    break

        issues.append({
            "type": vuln_type,
            "title": f"{vuln_type} in {file_path.name}",
            "description": message,
            "file": str(file_path),
            "line": line_num,
            "severity": severity,
            "scanner": "php-vuln-scanner",
            "language": "php"
        })


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
                if re.search(r'system\(\s*\$(?:_GET|_POST|\$_REQUEST|\$_COOKIE)[^"]+\)', content):
                    self._add_vulnerability(
                        issues,
                        php_file,
                        'Command Injection',
                        'CRITICAL',
                        f'Line {line_num(1, content)}: OS command injection via system() with user input'
                    )

                # Pattern 2: exec() with user input
                if re.search(r'exec\(\s*\$(?:_GET|_POST|\$_REQUEST|\$_COOKIE)[^"]+\)', content):
                    self._add_vulnerability(
                        issues,
                        php_file,
                        'Command Injection',
                        'CRITICAL',
                        f'Line {line_num(2, content)}: OS command injection via exec() with user input'
                    )

                # Pattern 3: shell_exec() with user input
                if re.search(r'shell_exec\(\s*\$(?:_GET|_POST|\$_REQUEST|\$_COOKIE)[^"]+\)', content):
                    self._add_vulnerability(
                        issues,
                        php_file,
                        'Command Injection',
                        'CRITICAL',
                        f'Line {line_num(3, content)}: OS command injection via shell_exec() with user input'
                    )

            except Exception as e:
                logger.warning(f"Error scanning {php_file}: {str(e)}")

        return issues


class FileInclusionScanner(PHPVulnerabilityScanner):
    """File inclusion vulnerability detection"""

    def scan(self, path: str) -> List[Dict[str, Any]]:
        """Scan for file inclusion vulnerabilities"""
        issues = []
        base_path = Path(path)

        # Scan all PHP files
        for php_file in base_path.rglob('*.php'):
            try:
                with open(php_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Pattern 1: include() with user input
                if re.search(r'include\(\s*\$(?:_GET|_POST|\$_REQUEST|\$_COOKIE)[^"]+\)', content):
                    self._add_vulnerability(
                        issues,
                        php_file,
                        'File Inclusion',
                        'CRITICAL',
                        f'Line {line_num(1, content)}: Local file inclusion via include() with user input'
                    )

                # Pattern 2: require() with user input
                if re.search(r'require\(\s*\$(?:_GET|_POST|\$_REQUEST|\$_COOKIE)[^"]+\)', content):
                    self._add_vulnerability(
                        issues,
                        php_file,
                        'File Inclusion',
                        'CRITICAL',
                        f'Line {line_num(2, content)}: Local file inclusion via require() with user input'
                    )

                # Pattern 3: Path traversal via ../
                if re.search(r'include.*\.\./|\.\.\.', content):
                    self._add_vulnerability(
                        issues,
                        php_file,
                        'File Inclusion',
                        'HIGH',
                        f'Line {line_num(3, content)}: Path traversal via ../ patterns'
                    )

            except Exception as e:
                logger.warning(f"Error scanning {php_file}: {str(e)}")

        return issues


class CSRFCanner(PHPVulnerabilityScanner):
    """CSRF vulnerability detection"""

    def scan(self, path: str) -> List[Dict[str, Any]]:
        """Scan for CSRF vulnerabilities"""
        issues = []
        base_path = Path(path)

        # Scan all PHP and HTML files
        for html_file in base_path.rglob('*.{php,html}'):
            try:
                with open(html_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Pattern 1: Form without CSRF token
                if re.search(r'<form[^>]*>(?!.*<input[^>]+type=["\']hidden["']|name=["\']csrf["']|token["'])', content):
                    self._add_vulnerability(
                        issues,
                        html_file,
                        'CSRF',
                        'HIGH',
                        f'Line {line_num(1, content)}: CSRF vulnerability - no CSRF token in form'
                    )

            except Exception as e:
                logger.warning(f"Error scanning {html_file}: {str(e)}")

        return issues


def run_php_scanners(path: str) -> List[Dict[str, Any]]:
    """Run all PHP vulnerability scanners and combine results"""
    all_issues = []

    scanners = [
        SQLInjectionScanner(),
        XSSScanner(),
        CommandInjectionScanner(),
        FileInclusionScanner(),
        CSRFCanner()
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
        print("Usage: python3 php_vuln_scanner.py <path>")
        sys.exit(1)

    target_path = sys.argv[1]

    print(f"Scanning PHP files in: {target_path}")
    issues = run_php_scanners(target_path)

    print(f"\n✓ PHP vulnerability scan completed")
    print(f"  Total issues found: {len(issues)}")

    if issues:
        print("\nVulnerabilities found:")
        for issue in issues[:10]:
            severity_emoji = "🔴" if issue['severity'] == 'CRITICAL' else "🟠" if issue['severity'] == 'ERROR' else "🟡"
            print(f"  [{severity_emoji}] {issue['severity']}] {issue['title']}")
            print(f"    {issue['description']}")
            print(f"    File: {issue['file']}:{issue['line']}")

    # Save results
    output_path = f"{target_path}/php-vulnerabilities.json"
    with open(output_path, 'w') as f:
        json.dump({
            "issues": issues,
            "total": len(issues),
            "scanner": "php-vuln-scanner",
            "language": "php"
        }, indent=2)

    print(f"\n✓ Results saved to: {output_path}")
