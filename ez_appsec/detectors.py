"""Security detectors - DEPRECATED: Now using external scanners only"""

from pathlib import Path
from typing import List, Dict, Any


class SastDetector:
    """Static Application Security Testing detector - DEPRECATED"""
    """Now handled by semgrep external scanner"""

    def detect(self, path: Path) -> List[Dict[str, Any]]:
        """No longer used - semgrep handles SAST"""
        return []


class DependencyDetector:
    """Dependency vulnerability detector - DEPRECATED"""
    """Now handled by grype external scanner"""

    def detect(self, path: Path) -> List[Dict[str, Any]]:
        """No longer used - grype handles dependency scanning"""
        return []


class SecretsDetector:
    """Secrets detector - DEPRECATED"""
    """Now handled by gitleaks external scanner"""

    def detect(self, path: Path) -> List[Dict[str, Any]]:
        """No longer used - gitleaks handles secrets detection"""
        return []
