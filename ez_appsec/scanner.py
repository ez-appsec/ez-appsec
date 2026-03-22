"""Core security scanning engine"""

import os
from pathlib import Path
from typing import Dict, List, Any
from ez_appsec.config import Config
from ez_appsec.detectors import (
    SastDetector,
    DependencyDetector,
    SecretsDetector,
)
from ez_appsec.ai_analyzer import AIAnalyzer


class SecurityScanner:
    """Main security scanner orchestrating all detection mechanisms"""
    
    def __init__(self, config: Config):
        self.config = config
        self.sast = SastDetector()
        self.dependencies = DependencyDetector()
        self.secrets = SecretsDetector()
        self.ai = AIAnalyzer(config)
    
    def scan(self, path: str, custom_prompt: str = None) -> Dict[str, Any]:
        """Execute full security scan with AI analysis"""
        
        base_path = Path(path)
        issues = []
        
        # Run all detectors
        issues.extend(self.sast.detect(base_path))
        issues.extend(self.dependencies.detect(base_path))
        issues.extend(self.secrets.detect(base_path))
        
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
        }
    
    def quick_check(self, path: str) -> Dict[str, Any]:
        """Fast security check without AI analysis"""
        
        base_path = Path(path)
        file_count = sum(1 for _ in base_path.rglob("*") if _.is_file())
        
        issues = []
        issues.extend(self.secrets.detect(base_path))
        
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
