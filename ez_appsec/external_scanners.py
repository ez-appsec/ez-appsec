"""Wrappers for external open-source security scanners"""

import subprocess
import json
import logging
import tempfile
import os
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class ScannerWrapper(ABC):
    """Base class for external scanner wrappers"""
    
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.name = self.__class__.__name__
    
    @abstractmethod
    def is_installed(self) -> bool:
        """Check if scanner is installed"""
        pass
    
    @abstractmethod
    def scan(self, path: str) -> List[Dict[str, Any]]:
        """Run scan and return normalized results"""
        pass
    
    @abstractmethod
    def scan_with_raw_output(self, path: str) -> Tuple[List[Dict[str, Any]], str]:
        """Run scan and return both normalized results and raw output file path"""
        pass
    
    @abstractmethod
    def install_command(self) -> str:
        """Return installation command"""
        pass


class GitleaksScanner(ScannerWrapper):
    """Wrapper for gitleaks secrets detection"""
    
    def is_installed(self) -> bool:
        """Check if gitleaks is installed"""
        try:
            subprocess.run(["gitleaks", "version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def install_command(self) -> str:
        """Return installation command"""
        return "brew install gitleaks  # or: go install github.com/gitleaks/gitleaks/v8@latest"
    
    def scan(self, path: str) -> List[Dict[str, Any]]:
        """Run gitleaks scan"""
        issues, _ = self.scan_with_raw_output(path)
        return issues
    
    def scan_with_raw_output(self, path: str) -> Tuple[List[Dict[str, Any]], str]:
        """Run gitleaks scan and return raw output file path"""
        if not self.is_installed():
            logger.warning("gitleaks not installed")
            return [], ""
        
        # Create temporary file for raw output
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
            raw_output_path = temp_file.name
        
        try:
            result = subprocess.run(
                ["gitleaks", "detect", "--source", path, "--report-path", raw_output_path, "--report-format", "json"],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            try:
                with open(raw_output_path) as f:
                    data = json.load(f)
            except FileNotFoundError:
                return [], raw_output_path
            
            issues = []
            for match in data:
                issues.append({
                    "type": "Secrets",
                    "title": f"Exposed {match.get('RuleID', 'Secret')}",
                    "description": f"Potential secret found: {match.get('Match', '')[:50]}...",
                    "file": match.get("File", "unknown"),
                    "line": match.get("StartLine", 1),
                    "severity": "critical",
                    "scanner": "gitleaks",
                })
            
            return issues, raw_output_path
        except subprocess.TimeoutExpired:
            logger.error("gitleaks scan timed out")
            return [], raw_output_path
        except Exception as e:
            logger.error(f"gitleaks scan failed: {e}")
            return [], raw_output_path


class SemgrepScanner(ScannerWrapper):
    """Wrapper for semgrep SAST analysis"""
    
    def is_installed(self) -> bool:
        """Check if semgrep is installed"""
        try:
            subprocess.run(["semgrep", "--version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def install_command(self) -> str:
        """Return installation command"""
        return "brew install semgrep  # or: python3 -m pip install semgrep"
    
    def scan(self, path: str) -> List[Dict[str, Any]]:
        """Run semgrep scan"""
        issues, _ = self.scan_with_raw_output(path)
        return issues
    
    def scan_with_raw_output(self, path: str) -> Tuple[List[Dict[str, Any]], str]:
        """Run semgrep scan and return raw output file path"""
        if not self.is_installed():
            logger.warning("semgrep not installed")
            return [], ""
        
        # Create temporary file for raw output
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
            raw_output_path = temp_file.name
        
        try:
            # Prefer bundled GitLab SAST rules (language subdirs + ruby pack); fall back to registry
            sast_rules_root = "/usr/local/share/sast-rules"
            sast_langs = ["c", "csharp", "go", "java", "javascript", "python", "scala"]
            config_flags = [
                f"--config={os.path.join(sast_rules_root, lang)}"
                for lang in sast_langs
                if os.path.isdir(os.path.join(sast_rules_root, lang))
            ]
            ruby_rules = os.path.join(sast_rules_root, "ruby.yml")
            if os.path.isfile(ruby_rules):
                config_flags.append(f"--config={ruby_rules}")
            if not config_flags:
                config_flags = ["--config=p/security-audit"]
            result = subprocess.run(
                ["semgrep"] + config_flags + ["--json", "--output", raw_output_path, path],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            try:
                with open(raw_output_path) as f:
                    data = json.load(f)
            except FileNotFoundError:
                return [], raw_output_path
            
            issues = []
            
            for result_item in data.get("results", []):
                issues.append({
                    "type": "SAST",
                    "title": result_item.get("check_id", "semgrep finding"),
                    "description": result_item.get("extra", {}).get("message", "Code pattern security issue"),
                    "file": result_item.get("path", "unknown"),
                    "line": result_item.get("start", {}).get("line", 1),
                    "severity": self._map_severity(
                        result_item.get("extra", {}).get("severity"),
                        result_item.get("extra", {}).get("metadata", {}).get("security-severity", "")
                        or result_item.get("extra", {}).get("metadata", {}).get("impact", ""),
                    ),
                    "scanner": "semgrep",
                })
            
            return issues, raw_output_path
        except subprocess.TimeoutExpired:
            logger.error("semgrep scan timed out")
            return [], raw_output_path
        except json.JSONDecodeError:
            logger.error("semgrep output is not valid JSON")
            return [], raw_output_path
        except Exception as e:
            logger.error(f"semgrep scan failed: {e}")
            return [], raw_output_path
    
    def _map_severity(self, semgrep_severity: str, security_severity: str = "") -> str:
        """Map semgrep severity + GitLab security-severity metadata to standard levels.
        ERROR + High → critical; WARNING + High → high; otherwise by semgrep level."""
        sev = (semgrep_severity or "").upper()
        ssev = security_severity.lower()
        if sev == "ERROR" and ssev == "high":
            return "critical"
        if ssev == "high":
            return "high"
        mapping = {
            "ERROR": "high",
            "WARNING": "medium",
            "INFO": "low",
        }
        return mapping.get(sev, "medium")


class KicsScanner(ScannerWrapper):
    """Wrapper for KICS infrastructure as code scanning"""
    
    def is_installed(self) -> bool:
        """Check if kics is installed"""
        try:
            subprocess.run(["kics", "version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def install_command(self) -> str:
        """Return installation command"""
        return "brew install kics  # or: docker pull checkmarx/kics:latest"
    
    def scan(self, path: str) -> List[Dict[str, Any]]:
        """Run KICS scan"""
        issues, _ = self.scan_with_raw_output(path)
        return issues
    
    def scan_with_raw_output(self, path: str) -> Tuple[List[Dict[str, Any]], str]:
        """Run KICS scan and return raw output file path"""
        if not self.is_installed():
            logger.warning("kics not installed")
            return [], ""

        # kics -o expects a directory; it writes results.json inside it
        output_dir = tempfile.mkdtemp()
        raw_output_path = os.path.join(output_dir, "results.json")

        try:
            subprocess.run(
                ["kics", "scan", "-p", path, "-f", "json", "-o", output_dir],
                capture_output=True,
                text=True,
                timeout=120
            )

            try:
                with open(raw_output_path) as f:
                    data = json.load(f)
            except FileNotFoundError:
                return [], raw_output_path

            issues = []
            for query in data.get("queries", []):
                for result_item in query.get("results", []):
                    issues.append({
                        "type": "Infrastructure as Code",
                        "title": query.get("queryName", "IaC Security Issue"),
                        "description": query.get("description", "Infrastructure configuration security issue"),
                        "file": result_item.get("file", "unknown"),
                        "line": result_item.get("line", 1),
                        "severity": self._map_severity(query.get("severity")),
                        "scanner": "kics",
                    })

            return issues, raw_output_path
        except subprocess.TimeoutExpired:
            logger.error("kics scan timed out")
            return [], raw_output_path
        except json.JSONDecodeError:
            logger.error("kics output is not valid JSON")
            return [], raw_output_path
        except Exception as e:
            logger.error(f"kics scan failed: {e}")
            return [], raw_output_path
    
    def _map_severity(self, kics_severity: str) -> str:
        """Map KICS severity to standard levels"""
        mapping = {
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFO": "low",
        }
        return mapping.get(kics_severity, "medium")


class GrypeScanner(ScannerWrapper):
    """Wrapper for grype vulnerability scanning"""
    
    def is_installed(self) -> bool:
        """Check if grype is installed"""
        try:
            subprocess.run(["grype", "--version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def install_command(self) -> str:
        """Return installation command"""
        return "brew install grype  # or: curl https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh"
    
    def _install_dependencies(self, path: str) -> None:
        """Install project dependencies so grype/syft can enumerate packages."""
        from pathlib import Path
        p = Path(path)
        installers = [
            (p / "package-lock.json", None),  # lockfile already present, no install needed
            (p / "yarn.lock",         None),  # yarn lockfile already present
            (p / "package.json",      ["npm", "install", "--ignore-scripts", "--package-lock-only"]),
            (p / "Pipfile.lock",      ["pipenv", "install", "--deploy"]),
            (p / "requirements.txt",  ["pip", "install", "-r", str(p / "requirements.txt"), "--target", str(p / ".grype-deps")]),
            (p / "go.sum",            ["go", "mod", "download"]),
            (p / "Gemfile.lock",      ["bundle", "install"]),
        ]
        for marker, cmd in installers:
            if marker.exists():
                if cmd is None:
                    return  # lockfile already present, grype can use it directly
                logger.info(f"Generating dependency manifest via: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=path, timeout=300)
                if result.returncode != 0:
                    logger.warning(f"Dependency manifest generation failed: {result.stderr[:200]}")
                return  # only run the first matching installer

    def scan(self, path: str) -> List[Dict[str, Any]]:
        """Run grype scan"""
        issues, _ = self.scan_with_raw_output(path)
        return issues
    
    def scan_with_raw_output(self, path: str) -> Tuple[List[Dict[str, Any]], str]:
        """Run grype scan and return raw output file path"""
        if not self.is_installed():
            logger.warning("grype not installed")
            return [], ""
        
        # Create temporary file for raw output
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
            raw_output_path = temp_file.name
        
        try:
            # Ensure the vulnerability database is present before scanning
            db_check = subprocess.run(["grype", "db", "status"], capture_output=True)
            if db_check.returncode != 0:
                logger.info("grype database missing, updating...")
                subprocess.run(["grype", "db", "update"], capture_output=True, timeout=120)

            # Install dependencies so grype/syft can enumerate packages
            self._install_dependencies(path)

            result = subprocess.run(
                ["grype", "dir:" + path, "-o", "json", "--file", raw_output_path],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            try:
                with open(raw_output_path) as f:
                    data = json.load(f)
            except FileNotFoundError:
                return [], raw_output_path
            
            issues = []
            
            for match in data.get("matches", []):
                vulnerability = match.get("vulnerability", {})
                issues.append({
                    "type": "Dependency",
                    "title": f"{match.get('artifact', {}).get('name')} - {vulnerability.get('id')}",
                    "description": vulnerability.get("description", "Known vulnerability in dependency"),
                    "file": "dependency: " + match.get('artifact', {}).get('name', 'unknown'),
                    "severity": vulnerability.get("severity", "medium").lower(),
                    "scanner": "grype",
                    "cve": vulnerability.get("id"),
                })
            
            return issues, raw_output_path
        except subprocess.TimeoutExpired:
            logger.error("grype scan timed out")
            return [], raw_output_path
        except json.JSONDecodeError:
            logger.error("grype output is not valid JSON")
            return [], raw_output_path
        except Exception as e:
            logger.error(f"grype scan failed: {e}")
            return [], raw_output_path


class ExternalScannerManager:
    """Manages all external scanners"""
    
    def __init__(self, enabled_scanners: Optional[List[str]] = None):
        """
        Initialize scanner manager
        
        Args:
            enabled_scanners: List of scanner names to enable (None = all)
        """
        self.scanners = {
            "gitleaks": GitleaksScanner(),
            "semgrep": SemgrepScanner(),
            "kics": KicsScanner(),
            "grype": GrypeScanner(),
        }
        
        if enabled_scanners:
            for scanner_name in self.scanners:
                self.scanners[scanner_name].enabled = scanner_name in enabled_scanners
    
    def get_installed(self) -> Dict[str, bool]:
        """Get status of all scanners"""
        return {
            name: scanner.is_installed()
            for name, scanner in self.scanners.items()
        }
    
    def get_install_instructions(self) -> str:
        """Get installation instructions for missing scanners"""
        instructions = []
        for name, scanner in self.scanners.items():
            if not scanner.is_installed():
                instructions.append(f"{name}: {scanner.install_command()}")
        
        return "\n".join(instructions)
    
    def scan_all(self, path: str) -> List[Dict[str, Any]]:
        """Run all enabled scanners and aggregate results"""
        all_issues = []
        
        for name, scanner in self.scanners.items():
            if scanner.enabled:
                logger.info(f"Running {name} scan...")
                try:
                    issues = scanner.scan(path)
                    all_issues.extend(issues)
                    logger.info(f"{name} found {len(issues)} issues")
                except Exception as e:
                    logger.error(f"Error running {name}: {e}")
        
        return all_issues
    
    def scan_all_with_raw_outputs(self, path: str) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
        """Run all enabled scanners and return both results and raw output file paths"""
        all_issues = []
        raw_outputs = {}
        
        for name, scanner in self.scanners.items():
            if scanner.enabled:
                logger.info(f"Running {name} scan...")
                try:
                    issues, raw_path = scanner.scan_with_raw_output(path)
                    all_issues.extend(issues)
                    if raw_path:
                        raw_outputs[name] = raw_path
                    logger.info(f"{name} found {len(issues)} issues")
                except Exception as e:
                    logger.error(f"Error running {name}: {e}")
        
        return all_issues, raw_outputs
