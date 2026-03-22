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
