"""Core security scanning engine"""

import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from ez_appsec.config import Config
from ez_appsec.detectors import (
    SastDetector,
    DependencyDetector,
    SecretsDetector,
)
from ez_appsec.ai_analyzer import AIAnalyzer
from ez_appsec.external_scanners import ExternalScannerManager
from ez_appsec.converters import VulnerabilityConverters, GitLabVulnerabilityFormat


class SecurityScanner:
    """Main security scanner orchestrating all detection mechanisms"""
    
    def __init__(self, config: Config, use_external_scanners: bool = True):
        self.config = config
        self.use_external = use_external_scanners
        
        # External scanners only - custom detectors removed
        self.external = ExternalScannerManager() if use_external_scanners else None
        
        # AI analyzer
        self.ai = AIAnalyzer(config)


class SecurityScanner:
    """Main security scanner orchestrating all detection mechanisms"""
    
    def __init__(self, config: Config, use_external_scanners: bool = True):
        self.config = config
        self.use_external = use_external_scanners
        
        # External scanners only - custom detectors removed
        self.external = ExternalScannerManager() if use_external_scanners else None
        
        # AI analyzer
        self.ai = AIAnalyzer(config)
    
    def scan(self, path: str, custom_prompt: str = None) -> Dict[str, Any]:
        """Execute full security scan using external scanners only"""
        
        base_path = Path(path)
        issues = []
        scanner_results = {}
        
        # Run external scanners only (custom detectors removed)
        if self.use_external and self.external:
            external_issues = self.external.scan_all(path)
            issues.extend(external_issues)
            scanner_results["external"] = len(external_issues)
        
        # AI-powered analysis and remediation
        if issues:
            ai_results = self.ai.analyze(issues, base_path, custom_prompt)
            issues = ai_results.get("enhanced_issues", issues)
        
        # Filter by severity
        if self.config.severity != "all":
            issues = self._filter_by_severity(issues, self.config.severity)
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        issues.sort(
            key=lambda x: severity_order.get(x.get("severity", "low"), 4)
        )
        
        return {
            "issues": issues,
            "total": len(issues),
            "path": str(base_path),
            "scanner_results": scanner_results,
        }
    
    def scan_to_gitlab_format(self, path: str, output_file: str = None, custom_prompt: str = None) -> Dict[str, Any]:
        """Execute full security scan and output in GitLab vulnerability format"""
        
        base_path = Path(path)
        scanner_results = {}
        raw_outputs = {}
        
        # Run external scanners with raw output capture
        if self.use_external and self.external:
            issues, raw_outputs = self.external.scan_all_with_raw_outputs(path)
            scanner_results["external"] = len(issues)
        
        # Convert raw outputs to GitLab format
        gitlab_reports = []
        for scanner_name, raw_path in raw_outputs.items():
            if os.path.exists(raw_path):
                try:
                    report = VulnerabilityConverters.convert_scanner_output(scanner_name, raw_path)
                    gitlab_reports.append(report)
                except Exception as e:
                    print(f"Error converting {scanner_name} output: {e}")
                finally:
                    # Clean up temporary file
                    try:
                        os.unlink(raw_path)
                    except:
                        pass
        
        # Merge all reports
        if gitlab_reports:
            merged_report = VulnerabilityConverters.merge_reports(gitlab_reports)
        else:
            merged_report = GitLabVulnerabilityFormat.create_report([], "ez-appsec")
        
        # AI-powered analysis and remediation (optional for GitLab format)
        if merged_report.get("vulnerabilities") and self.ai:
            # Convert GitLab format back to internal format for AI analysis
            internal_issues = []
            for vuln in merged_report["vulnerabilities"]:
                internal_issues.append({
                    "type": vuln.get("category", "unknown"),
                    "title": vuln.get("name", ""),
                    "description": vuln.get("description", ""),
                    "file": vuln.get("location", {}).get("file", "unknown"),
                    "line": vuln.get("location", {}).get("start_line", 1),
                    "severity": vuln.get("severity", "medium"),
                    "scanner": "gitlab-converted"
                })
            
            ai_results = self.ai.analyze(internal_issues, base_path, custom_prompt)
            
            # Update GitLab report with AI-enhanced descriptions
            for i, vuln in enumerate(merged_report["vulnerabilities"]):
                if i < len(ai_results.get("enhanced_issues", [])):
                    enhanced = ai_results["enhanced_issues"][i]
                    vuln["description"] = enhanced.get("description", vuln["description"])
                    vuln["solution"] = enhanced.get("solution", vuln.get("solution", ""))
        
        # Filter by severity
        if self.config.severity != "all":
            filtered_vulns = self._filter_gitlab_vulnerabilities(merged_report["vulnerabilities"], self.config.severity)
            merged_report["vulnerabilities"] = filtered_vulns
        
        # Save to file if requested
        if output_file:
            import json
            with open(output_file, 'w') as f:
                json.dump(merged_report, f, indent=2)
        
        return merged_report
    
    def quick_check(self, path: str) -> Dict[str, Any]:
        """Fast security check using external scanners only"""
        
        base_path = Path(path)
        file_count = sum(1 for _ in base_path.rglob("*") if _.is_file())
        
        issues = []
        if self.use_external and self.external:
            # Only run gitleaks for quick secrets check
            if hasattr(self.external, 'scanners') and 'gitleaks' in self.external.scanners:
                gitleaks = self.external.scanners['gitleaks']
                if gitleaks.enabled and gitleaks.is_installed():
                    try:
                        issues = gitleaks.scan(path)
                    except Exception:
                        pass
        
        return {
            "files_scanned": file_count,
            "issue_count": len(issues),
        }
    
    def _filter_by_severity(self, issues: List[Dict], min_severity: str) -> List[Dict]:
        """Filter issues by minimum severity level"""
        severity_levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        min_level = severity_levels.get(min_severity, 0)
        
        return [
            issue for issue in issues
            if severity_levels.get(issue.get("severity", "low"), 0) >= min_level
        ]
    
    def _filter_gitlab_vulnerabilities(self, vulnerabilities: List[Dict], min_severity: str) -> List[Dict]:
        """Filter GitLab vulnerabilities by minimum severity level"""
        severity_levels = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        min_level = severity_levels.get(min_severity, 0)
        
        return [
            vuln for vuln in vulnerabilities
            if severity_levels.get(vuln.get("severity", "medium"), 1) >= min_level
        ]
