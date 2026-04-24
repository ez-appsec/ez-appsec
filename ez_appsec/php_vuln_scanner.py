"""PHP Vulnerability Scanner for ez-appsec
Simple scanner to detect PHP security vulnerabilities in DVWA and similar applications
"""

import re
import json
import logging
from pathlib import Path
from typing import List, Dict, Any
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


def _find_line(content: str, pattern: str) -> int:
    """Return the 1-based line number of the first line matching pattern, or 1 if not found."""
    for i, line in enumerate(content.splitlines(), start=1):
        if re.search(pattern, line, re.IGNORECASE):
            return i
    return 1


class PHPVulnerabilityScanner(ABC):
    """Base class for PHP vulnerability detection"""

    @abstractmethod
    def scan(self, path: str) -> List[Dict[str, Any]]:
        """Scan PHP files for vulnerabilities"""
        pass

    def _add_vulnerability(self, issues: List, file_path: Path, vuln_type: str,
                           severity: str, message: str, line_num: int = 1):
        """Append a normalised vulnerability dict to issues."""
        issues.append({
            "type": vuln_type,
            "title": f"{vuln_type} in {file_path.name}",
            "description": message,
            "file": str(file_path),
            "line": line_num,
            "severity": severity.lower(),
            "scanner": "php-vuln-scanner",
            "language": "php",
        })


class SQLInjectionScanner(PHPVulnerabilityScanner):
    """SQL injection vulnerability detection"""

    def scan(self, path: str) -> List[Dict[str, Any]]:
        issues = []
        for php_file in Path(path).rglob("*.php"):
            try:
                content = php_file.read_text(encoding="utf-8", errors="ignore")

                # Pattern 1: string concatenation with user input
                p1 = r"(SELECT|UPDATE|INSERT|DELETE)\s+.*\$(?:_GET|_POST|_REQUEST|_COOKIE)"
                if re.search(p1, content, re.IGNORECASE):
                    self._add_vulnerability(
                        issues, php_file, "SQL Injection", "critical",
                        "SQL injection via string concatenation with user input",
                        _find_line(content, p1),
                    )

                # Pattern 2: mysql_query with user input
                p2 = r"mysql_query\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)"
                if re.search(p2, content, re.IGNORECASE):
                    self._add_vulnerability(
                        issues, php_file, "SQL Injection", "critical",
                        "SQL injection via unsanitized mysql_query() with user input",
                        _find_line(content, p2),
                    )

                # Pattern 3: integer bypass (quotes stripped from user input)
                p3 = r"(SELECT|UPDATE|INSERT|DELETE).*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\+\s*\d+"
                if re.search(p3, content, re.IGNORECASE):
                    self._add_vulnerability(
                        issues, php_file, "SQL Injection", "critical",
                        "SQL injection via integer bypass (quotes removed from user input)",
                        _find_line(content, p3),
                    )

            except Exception as e:
                logger.warning(f"Error scanning {php_file}: {e}")

        return issues


class XSSScanner(PHPVulnerabilityScanner):
    """XSS vulnerability detection"""

    def scan(self, path: str) -> List[Dict[str, Any]]:
        issues = []
        for php_file in Path(path).rglob("*.php"):
            try:
                content = php_file.read_text(encoding="utf-8", errors="ignore")

                # Pattern 1: reflected XSS via echo
                p1 = r"echo\s+\$(?:_GET|_POST|_REQUEST|_COOKIE)"
                if re.search(p1, content, re.IGNORECASE):
                    self._add_vulnerability(
                        issues, php_file, "XSS", "high",
                        "Reflected XSS via unsanitized echo of user input",
                        _find_line(content, p1),
                    )

                # Pattern 2: stored XSS via database insert
                p2 = r"(INSERT|UPDATE).*INTO.*\$(?:_GET|_POST|_REQUEST|_COOKIE)"
                if re.search(p2, content, re.IGNORECASE):
                    self._add_vulnerability(
                        issues, php_file, "XSS", "high",
                        "Stored XSS via unsanitized user input in database write",
                        _find_line(content, p2),
                    )

                # Pattern 3: DOM XSS via innerHTML / outerHTML
                p3 = r"(?:innerHTML|outerHTML)\s*=\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)"
                if re.search(p3, content, re.IGNORECASE):
                    self._add_vulnerability(
                        issues, php_file, "XSS", "high",
                        "DOM XSS via unsafe innerHTML/outerHTML assignment of user input",
                        _find_line(content, p3),
                    )

            except Exception as e:
                logger.warning(f"Error scanning {php_file}: {e}")

        return issues


class CommandInjectionScanner(PHPVulnerabilityScanner):
    """Command injection vulnerability detection"""

    def scan(self, path: str) -> List[Dict[str, Any]]:
        issues = []
        for php_file in Path(path).rglob("*.php"):
            try:
                content = php_file.read_text(encoding="utf-8", errors="ignore")

                for func in ("system", "exec", "shell_exec", "passthru", "popen"):
                    pattern = rf"{func}\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)"
                    if re.search(pattern, content, re.IGNORECASE):
                        self._add_vulnerability(
                            issues, php_file, "Command Injection", "critical",
                            f"OS command injection via {func}() with unsanitized user input",
                            _find_line(content, pattern),
                        )

            except Exception as e:
                logger.warning(f"Error scanning {php_file}: {e}")

        return issues


class FileInclusionScanner(PHPVulnerabilityScanner):
    """File inclusion vulnerability detection"""

    def scan(self, path: str) -> List[Dict[str, Any]]:
        issues = []
        for php_file in Path(path).rglob("*.php"):
            try:
                content = php_file.read_text(encoding="utf-8", errors="ignore")

                for func in ("include", "require", "include_once", "require_once"):
                    pattern = rf"{func}\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)"
                    if re.search(pattern, content, re.IGNORECASE):
                        self._add_vulnerability(
                            issues, php_file, "File Inclusion", "critical",
                            f"Local/remote file inclusion via {func}() with user-controlled path",
                            _find_line(content, pattern),
                        )

                # Path traversal patterns
                p_trav = r"\.\./|\.\.\\"
                if re.search(p_trav, content):
                    self._add_vulnerability(
                        issues, php_file, "File Inclusion", "high",
                        "Potential path traversal via ../ or ..\\ sequences",
                        _find_line(content, p_trav),
                    )

            except Exception as e:
                logger.warning(f"Error scanning {php_file}: {e}")

        return issues


class CSRFScanner(PHPVulnerabilityScanner):
    """CSRF vulnerability detection"""

    def scan(self, path: str) -> List[Dict[str, Any]]:
        issues = []
        # Scan both PHP and HTML files
        files = list(Path(path).rglob("*.php")) + list(Path(path).rglob("*.html"))
        for html_file in files:
            try:
                content = html_file.read_text(encoding="utf-8", errors="ignore")

                # Flag forms that lack any CSRF token field
                has_form = re.search(r"<form[^>]*>", content, re.IGNORECASE)
                has_token = re.search(
                    r'(?:csrf|_token|authenticity_token)',
                    content, re.IGNORECASE
                )
                if has_form and not has_token:
                    self._add_vulnerability(
                        issues, html_file, "CSRF", "high",
                        "Form present without a detectable CSRF token field",
                        _find_line(content, r"<form[^>]*>"),
                    )

            except Exception as e:
                logger.warning(f"Error scanning {html_file}: {e}")

        return issues


def run_php_scanners(path: str) -> List[Dict[str, Any]]:
    """Run all PHP vulnerability scanners and combine results."""
    all_issues: List[Dict[str, Any]] = []
    for scanner in [
        SQLInjectionScanner(),
        XSSScanner(),
        CommandInjectionScanner(),
        FileInclusionScanner(),
        CSRFScanner(),
    ]:
        try:
            all_issues.extend(scanner.scan(path))
        except Exception as e:
            logger.warning(f"Error in {scanner.__class__.__name__}: {e}")
    return all_issues


def main():
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
            sev = issue["severity"].upper()
            print(f"  [{sev}] {issue['title']}")
            print(f"    {issue['description']}")
            print(f"    File: {issue['file']}:{issue['line']}")

    output_path = f"{target_path}/php-vulnerabilities.json"
    with open(output_path, "w") as f:
        json.dump({"issues": issues, "total": len(issues),
                   "scanner": "php-vuln-scanner", "language": "php"}, f, indent=2)
    print(f"\n✓ Results saved to: {output_path}")
