"""Security detectors for different vulnerability types"""

import re
from pathlib import Path
from typing import List, Dict, Any


class SastDetector:
    """Static Application Security Testing detector"""
    
    PATTERNS = {
        "sql_injection": r"(execute|query)\s*\(\s*['\"]?[^)]*\$|['\"]?\s*\+\s*",
        "hardcoded_secrets": r"(password|api_key|secret)\s*=\s*['\"]([^'\"]+)['\"]",
        "unsafe_eval": r"(eval|exec|pickle\.loads)\s*\(",
        "xxe_vulnerability": r"XMLParser\s*\(",
        "insecure_deserialization": r"pickle\.loads|yaml\.load",
    }
    
    def detect(self, path: Path) -> List[Dict[str, Any]]:
        """Scan for SAST vulnerabilities"""
        issues = []
        
        for file_path in path.rglob("*"):
            if not file_path.is_file() or not self._should_scan(file_path):
                continue
            
            try:
                content = file_path.read_text(errors="ignore")
                
                for vuln_type, pattern in self.PATTERNS.items():
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    
                    for match in matches:
                        issues.append({
                            "type": "SAST",
                            "title": f"Potential {vuln_type.replace('_', ' ')}",
                            "description": f"Found suspicious pattern: {match.group()}",
                            "file": str(file_path),
                            "severity": "medium",
                            "line": content[:match.start()].count("\n") + 1,
                        })
            except Exception:
                pass
        
        return issues
    
    def _should_scan(self, path: Path) -> bool:
        """Check if file should be scanned"""
        extensions = {".py", ".js", ".java", ".go", ".rb", ".php"}
        return path.suffix in extensions


class DependencyDetector:
    """Detect vulnerable dependencies"""
    
    def detect(self, path: Path) -> List[Dict[str, Any]]:
        """Scan for vulnerable dependencies"""
        issues = []
        
        # Check for common dependency files
        dependency_files = [
            ("requirements.txt", "python"),
            ("package.json", "javascript"),
            ("pom.xml", "java"),
            ("go.mod", "go"),
        ]
        
        for dep_file, lang in dependency_files:
            dep_path = path / dep_file
            if dep_path.exists():
                issues.extend(self._scan_dependencies(dep_path, lang))
        
        return issues
    
    def _scan_dependencies(self, file_path: Path, language: str) -> List[Dict[str, Any]]:
        """Scan a specific dependency file"""
        issues = []
        content = file_path.read_text()
        
        # Known vulnerable packages (simplified)
        vulnerable = {
            "django": ["1.0", "1.1", "1.2"],
            "requests": ["2.5.0", "2.5.1"],
        }
        
        for package, versions in vulnerable.items():
            if package in content:
                issues.append({
                    "type": "Dependency",
                    "title": f"Potentially vulnerable package: {package}",
                    "description": f"Found {package} in {file_path.name}. Check version against known CVEs.",
                    "file": str(file_path),
                    "severity": "high",
                })
        
        return issues


class SecretsDetector:
    """Detect hardcoded secrets"""
    
    PATTERNS = {
        "api_key": r"api[_-]?key\s*=\s*['\"]?([a-zA-Z0-9]{20,})",
        "private_key": r"private[_-]?key\s*=\s*['\"]?-----BEGIN",
        "aws_key": r"AKIA[0-9A-Z]{16}",
        "github_token": r"ghp_[A-Za-z0-9_]{36,}",
        "slack_token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}",
    }
    
    def detect(self, path: Path) -> List[Dict[str, Any]]:
        """Scan for hardcoded secrets"""
        issues = []
        
        for file_path in path.rglob("*"):
            if not file_path.is_file() or self._should_skip(file_path):
                continue
            
            try:
                content = file_path.read_text(errors="ignore")
                
                for secret_type, pattern in self.PATTERNS.items():
                    matches = re.finditer(pattern, content)
                    
                    for match in matches:
                        issues.append({
                            "type": "Secrets",
                            "title": f"Potential {secret_type.replace('_', ' ')} detected",
                            "description": f"Possible hardcoded {secret_type}. Review and rotate if exposed.",
                            "file": str(file_path),
                            "severity": "critical",
                            "line": content[:match.start()].count("\n") + 1,
                        })
            except Exception:
                pass
        
        return issues
    
    def _should_skip(self, path: Path) -> bool:
        """Skip common non-source files"""
        skip_dirs = {".git", ".env", "node_modules", "__pycache__", ".venv"}
        skip_extensions = {".bin", ".exe", ".so", ".dll"}
        
        if any(skip_dir in path.parts for skip_dir in skip_dirs):
            return True
        if path.suffix in skip_extensions:
            return True
        
        return False
