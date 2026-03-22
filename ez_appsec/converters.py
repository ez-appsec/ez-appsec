"""Converters for external scanner outputs to GitLab vulnerability format"""

import json
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path


class GitLabVulnerabilityFormat:
    """GitLab vulnerability report format converter"""

    @staticmethod
    def create_report(vulnerabilities: List[Dict[str, Any]], scanner_name: str) -> Dict[str, Any]:
        """Create a GitLab vulnerability report"""
        return {
            "version": "15.0.0",
            "vulnerabilities": vulnerabilities,
            "remediations": []
        }

    @staticmethod
    def create_vulnerability(
        name: str,
        message: str,
        description: str,
        severity: str,
        confidence: str = "medium",
        solution: str = "",
        location: Dict[str, Any] = None,
        identifiers: List[Dict[str, Any]] = None,
        links: List[Dict[str, Any]] = None,
        scanner: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Create a single vulnerability entry in GitLab format"""

        vuln_id = str(uuid.uuid4())

        vulnerability = {
            "id": vuln_id,
            "category": "sast",  # or "secret_detection", "dependency_scanning", etc.
            "name": name,
            "message": message,
            "description": description,
            "cve": "",
            "severity": severity,
            "confidence": confidence,
            "solution": solution,
            "scanner": scanner or {
                "id": "ez-appsec",
                "name": "ez-appsec"
            },
            "location": location or {},
            "identifiers": identifiers or [],
            "links": links or []
        }

        return vulnerability


class GitleaksConverter:
    """Convert gitleaks output to GitLab vulnerability format"""

    @staticmethod
    def convert(gitleaks_json_path: str) -> Dict[str, Any]:
        """Convert gitleaks JSON output to GitLab format"""

        vulnerabilities = []

        try:
            with open(gitleaks_json_path, 'r') as f:
                gitleaks_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return GitLabVulnerabilityFormat.create_report([], "gitleaks")

        for finding in gitleaks_data:
            # Map gitleaks severity to GitLab severity
            severity = GitleaksConverter._map_severity(finding.get("Info", {}).get("Severity", "medium"))

            vulnerability = GitLabVulnerabilityFormat.create_vulnerability(
                name=f"Secret: {finding.get('Description', 'Unknown secret')}",
                message=f"Potential secret found: {finding.get('Match', '')[:50]}...",
                description=f"Gitleaks detected a potential secret leak. Rule: {finding.get('RuleID', 'unknown')}",
                severity=severity,
                confidence="high",
                solution="Review and rotate the exposed secret. Remove from version control if committed.",
                location={
                    "file": finding.get("File", "unknown"),
                    "start_line": finding.get("StartLine", 1),
                    "end_line": finding.get("EndLine", 1),
                    "class": "secret",
                    "method": finding.get("RuleID", "unknown")
                },
                identifiers=[{
                    "type": "gitleaks_rule",
                    "name": finding.get("RuleID", "unknown"),
                    "value": finding.get("RuleID", "unknown")
                }],
                scanner={
                    "id": "gitleaks",
                    "name": "Gitleaks"
                }
            )

            vulnerabilities.append(vulnerability)

        return GitLabVulnerabilityFormat.create_report(vulnerabilities, "gitleaks")

    @staticmethod
    def _map_severity(gitleaks_severity: str) -> str:
        """Map gitleaks severity to GitLab severity levels"""
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info"
        }
        return mapping.get(gitleaks_severity.lower(), "medium")


class SemgrepConverter:
    """Convert semgrep output to GitLab vulnerability format"""

    @staticmethod
    def convert(semgrep_json_path: str) -> Dict[str, Any]:
        """Convert semgrep JSON output to GitLab format"""

        vulnerabilities = []

        try:
            with open(semgrep_json_path, 'r') as f:
                semgrep_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return GitLabVulnerabilityFormat.create_report([], "semgrep")

        results = semgrep_data.get("results", [])

        for result in results:
            path = result.get("path", "unknown")
            start_line = result.get("start", {}).get("line", 1)
            end_line = result.get("end", {}).get("line", start_line)

            # Map semgrep severity
            severity = SemgrepConverter._map_severity(
                result.get("extra", {}).get("severity", "medium")
            )

            vulnerability = GitLabVulnerabilityFormat.create_vulnerability(
                name=f"Semgrep: {result.get('check_id', 'unknown')}",
                message=result.get("extra", {}).get("message", "Code pattern detected"),
                description=f"Semgrep rule violation: {result.get('check_id', 'unknown')}",
                severity=severity,
                confidence="medium",
                solution=result.get("extra", {}).get("fix", "Review the code pattern and fix according to security best practices."),
                location={
                    "file": path,
                    "start_line": start_line,
                    "end_line": end_line,
                    "class": result.get("check_id", "unknown"),
                    "method": result.get("check_id", "unknown")
                },
                identifiers=[{
                    "type": "semgrep_rule",
                    "name": result.get("check_id", "unknown"),
                    "value": result.get("check_id", "unknown")
                }],
                scanner={
                    "id": "semgrep",
                    "name": "Semgrep"
                }
            )

            vulnerabilities.append(vulnerability)

        return GitLabVulnerabilityFormat.create_report(vulnerabilities, "semgrep")

    @staticmethod
    def _map_severity(semgrep_severity: str) -> str:
        """Map semgrep severity to GitLab severity levels"""
        mapping = {
            "ERROR": "high",
            "WARNING": "medium",
            "INFO": "low"
        }
        return mapping.get(semgrep_severity.upper(), "medium")


class KicsConverter:
    """Convert KICS output to GitLab vulnerability format"""

    @staticmethod
    def convert(kics_json_path: str) -> Dict[str, Any]:
        """Convert KICS JSON output to GitLab format"""

        vulnerabilities = []

        try:
            with open(kics_json_path, 'r') as f:
                kics_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return GitLabVulnerabilityFormat.create_report([], "kics")

        queries = kics_data.get("queries", [])

        for query in queries:
            query_name = query.get("queryName", "unknown")
            severity = KicsConverter._map_severity(query.get("severity", "medium"))

            files = query.get("files", [])
            for file_info in files:
                vulnerability = GitLabVulnerabilityFormat.create_vulnerability(
                    name=f"KICS: {query_name}",
                    message=query.get("description", "Infrastructure as Code security issue"),
                    description=f"KICS detected: {query_name}",
                    severity=severity,
                    confidence="medium",
                    solution="Review the infrastructure configuration and apply security best practices.",
                    location={
                        "file": file_info,
                        "start_line": 1,
                        "end_line": 1,
                        "class": "iac",
                        "method": query_name
                    },
                    identifiers=[{
                        "type": "kics_query",
                        "name": query_name,
                        "value": query_name
                    }],
                    scanner={
                        "id": "kics",
                        "name": "KICS"
                    }
                )

                vulnerabilities.append(vulnerability)

        return GitLabVulnerabilityFormat.create_report(vulnerabilities, "kics")

    @staticmethod
    def _map_severity(kics_severity: str) -> str:
        """Map KICS severity to GitLab severity levels"""
        mapping = {
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFO": "info"
        }
        return mapping.get(kics_severity.upper(), "medium")


class GrypeConverter:
    """Convert grype output to GitLab vulnerability format"""

    @staticmethod
    def convert(grype_json_path: str) -> Dict[str, Any]:
        """Convert grype JSON output to GitLab format"""

        vulnerabilities = []

        try:
            with open(grype_json_path, 'r') as f:
                grype_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return GitLabVulnerabilityFormat.create_report([], "grype")

        matches = grype_data.get("matches", [])

        for match in matches:
            artifact = match.get("artifact", {})
            vulnerability = match.get("vulnerability", {})

            # Map grype severity
            severity = GrypeConverter._map_severity(vulnerability.get("severity", "medium"))

            vulnerability_entry = GitLabVulnerabilityFormat.create_vulnerability(
                name=f"Dependency: {artifact.get('name', 'unknown')} - {vulnerability.get('id', 'unknown')}",
                message=f"Vulnerable package: {artifact.get('name', 'unknown')} {artifact.get('version', '')}",
                description=vulnerability.get("description", "Known vulnerability in dependency"),
                severity=severity,
                confidence="high",
                solution=f"Update {artifact.get('name', 'package')} to a version that fixes {vulnerability.get('id', 'this vulnerability')}.",
                location={
                    "file": "dependency",
                    "dependency": {
                        "package": {
                            "name": artifact.get("name", "unknown")
                        },
                        "version": artifact.get("version", "")
                    }
                },
                identifiers=[{
                    "type": "cve",
                    "name": vulnerability.get("id", "unknown"),
                    "value": vulnerability.get("id", "unknown"),
                    "url": vulnerability.get("dataSource", "")
                }],
                links=[{
                    "url": vulnerability.get("dataSource", "")
                }],
                scanner={
                    "id": "grype",
                    "name": "Grype"
                }
            )

            vulnerabilities.append(vulnerability_entry)

        return GitLabVulnerabilityFormat.create_report(vulnerabilities, "grype")

    @staticmethod
    def _map_severity(grype_severity: str) -> str:
        """Map grype severity to GitLab severity levels"""
        mapping = {
            "Critical": "critical",
            "High": "high",
            "Medium": "medium",
            "Low": "low",
            "Negligible": "info",
            "Unknown": "medium"
        }
        return mapping.get(grype_severity, "medium")


class VulnerabilityConverters:
    """Main converter class for all scanner types"""

    CONVERTERS = {
        "gitleaks": GitleaksConverter,
        "semgrep": SemgrepConverter,
        "kics": KicsConverter,
        "grype": GrypeConverter
    }

    @staticmethod
    def convert_scanner_output(scanner_name: str, output_path: str, output_file: str = None) -> Dict[str, Any]:
        """Convert scanner output to GitLab vulnerability format"""

        if scanner_name not in VulnerabilityConverters.CONVERTERS:
            raise ValueError(f"Unknown scanner: {scanner_name}")

        converter_class = VulnerabilityConverters.CONVERTERS[scanner_name]
        report = converter_class.convert(output_path)

        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)

        return report

    @staticmethod
    def merge_reports(reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge multiple vulnerability reports into one"""

        all_vulnerabilities = []
        for report in reports:
            all_vulnerabilities.extend(report.get("vulnerabilities", []))

        return GitLabVulnerabilityFormat.create_report(all_vulnerabilities, "ez-appsec")


# CLI utilities for standalone conversion
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python converters.py <scanner> <input_file> [output_file]")
        sys.exit(1)

    scanner = sys.argv[1]
    input_file = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else None

    try:
        report = VulnerabilityConverters.convert_scanner_output(scanner, input_file, output_file)

        if output_file:
            print(f"Converted {scanner} output to GitLab format: {output_file}")
        else:
            print(json.dumps(report, indent=2))

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)