"""Wrappers for external open-source security scanners"""

import subprocess
import json
import logging
import tempfile
import shutil
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

    # Semgrep check IDs that are code quality, not security - exclude to reduce false positives
    CODE_QUALITY_CHECK_IDS = {
        # Code style and formatting
        "python.use-none-param",
        "python.bad-open-file-mode",
        "python.bad-exception-caught",
        "python.bad-open-mode",
        "python.duplicate-function-def",
        "python.useless-return",
        "python.useless-else",
        "python.redundant-unless",
        "python.unreachable-code",
        # Best practices (not security)
        "python.use-setliteral",
        "python.use-dict-literal",
        "python.use-list-literal",
        "javascript.comparison-with-nan",
        "javascript.useless-assignment",
        "javascript.no-delete-var",
        "javascript.no-empty-block",
        "javascript.no-template-curly-in-string",
        "javascript.no-const-assign",
        # Error handling (code quality)
        "javascript.no-throw-literal",
        "javascript.catch-error-name",
        "javascript.no-console-spam",
        # Performance/optimization
        "javascript.performance",
        "javascript.performance.*",
        "python.performance.*",
        # Testing
        "pytest.*",
        "unittest.*",
        "mocha.*",
        "jest.*",
        # Code complexity (not security)
        "complexity",
        "cyclomatic-complexity",
        "cognitive-complexity",
        "max-params",
        "max-lines",
        "max-len",
    }

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
            # Check if PHP files exist in the target
            has_php = any(Path(path).rglob('*.php'))

            # Check if JS/TS files exist in the target
            has_js = any(Path(path).rglob('*.{js,ts,jsx,tsx}'))

            # Build config flags
            config_flags = []

            # Add custom PHP rules if PHP files exist
            if has_php:
                custom_rules = Path(__file__).parent.parent / "custom-semgrep-rules.yaml"
                if custom_rules.exists():
                    config_flags.append(f"--config={custom_rules}")
                    logger.info(f"Using custom PHP vulnerability rules from {custom_rules}")

            # Add custom JS/TS rules if JS files exist
            if has_js:
                js_rules = Path(__file__).parent.parent / "js-semgrep-rules.yaml"
                if js_rules.exists():
                    config_flags.append(f"--config={js_rules}")
                    logger.info(f"Using custom JavaScript/TypeScript vulnerability rules from {js_rules}")

            # Prefer bundled GitLab SAST rules (language subdirs + ruby pack); fall back to registry
            sast_rules_root = "/usr/local/share/sast-rules"
            sast_langs = ["c", "csharp", "go", "java", "javascript", "python", "scala"]
            for lang in sast_langs:
                if os.path.isdir(os.path.join(sast_rules_root, lang)):
                    config_flags.append(f"--config={os.path.join(sast_rules_root, lang)}")

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
            filtered_count = 0

            for result_item in data.get("results", []):
                check_id = result_item.get("check_id", "")
                severity = result_item.get("extra", {}).get("severity", "")
                metadata = result_item.get("extra", {}).get("metadata", {})
                message = result_item.get("extra", {}).get("message", "")

                # Skip code quality findings to reduce false positives
                if self._is_code_quality(check_id, metadata, message):
                    filtered_count += 1
                    continue

                # Downgrade INFO severity to low impact or skip entirely
                if severity.upper() == "INFO":
                    # Only keep INFO if it has explicit security metadata
                    if not self._is_security_finding(metadata):
                        filtered_count += 1
                        continue

                issues.append({
                    "type": "SAST",
                    "title": check_id,
                    "description": message,
                    "file": result_item.get("path", "unknown"),
                    "line": result_item.get("start", {}).get("line", 1),
                    "severity": self._map_severity(severity, metadata),
                    "scanner": "semgrep",
                })

            if filtered_count > 0:
                logger.info(f"Semgrep: Filtered out {filtered_count} code quality/low-severity findings")

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

    def _is_code_quality(self, check_id: str, metadata: dict, message: str) -> bool:
        """Check if a Semgrep finding is code quality (not security)"""
        # Direct match against code quality check IDs
        for quality_check in self.CODE_QUALITY_CHECK_IDS:
            if quality_check in check_id.lower():
                return True

        # Check metadata for non-security categories
        category = metadata.get("category", "").lower()
        technology = metadata.get("technology", "").lower()
        cwe = metadata.get("cwe", "")

        # Code quality categories
        quality_categories = [
            "best practice",
            "performance",
            "correctness",
            "maintainability",
            "readability",
            "code style",
            "style",
            "complexity",
            "testing",
            "quality",
            "error-handling",
        ]

        for qc in quality_categories:
            if qc in category:
                return True

        # Findings without CWE or OWASP references are likely code quality
        if not cwe and "owasp" not in category and "security" not in category:
            # Check if message mentions security
            if not any(security_term in message.lower()
                      for security_term in ["vulnerability", "injection", "xss", "csrf", "sql", "secret", "credential", "auth"]):
                return True

        return False

    def _is_security_finding(self, metadata: dict) -> bool:
        """Check if a finding has explicit security metadata"""
        if metadata.get("cwe"):
            return True
        if "owasp" in metadata.get("category", "").lower():
            return True
        if metadata.get("security-severity"):
            return True
        if metadata.get("impact"):
            return True
        return False

    def _map_severity(self, semgrep_severity: str, metadata: dict = None) -> str:
        """Map semgrep severity + GitLab security-severity metadata to standard levels."""
        if metadata is None:
            metadata = {}

        sev = (semgrep_severity or "").upper()

        # Use GitLab security-severity if available (more accurate)
        security_severity = metadata.get("security-severity", "").lower()
        if security_severity:
            return security_severity

        # Fallback to semgrep severity level
        # ERROR → high, WARNING → medium, INFO → skip (handled by caller)
        mapping = {
            "ERROR": "high",
            "WARNING": "medium",
        }
        return mapping.get(sev, "medium")


class KicsScanner(ScannerWrapper):
    """Wrapper for KICS infrastructure as code scanning"""

    # KICS queries that are code quality, not security - exclude these to reduce false positives
    CODE_QUALITY_QUERIES = {
        # Code quality/pattern matching
        "Unused container instruction",
        "Container image tag",
        "Container image digest is missing",
        "Container image uses latest tag",
        "Dockerfile command not latest",
        "Dockerfile instruction should not be used multiple times",
        "Dockerfile line length should be less than 200 characters",
        "Dockerfile use JSON array for RUN instructions",
        "File permissions",
        "Inappropriate file permissions",
        "Root user in container",
        "User in Dockerfile",
        "Missing health check",
        "Health check not enabled",
        "Kubernetes labels not present",
        "Kubernetes annotations not present",
        "Metadata labels not set",
        "Missing Kubernetes labels",
        "Missing Kubernetes annotations",
        "Terraform output not defined",
        "Terraform module has no source",
        "Terraform module source is missing",
        "Terraform variable not defined",
        "Terraform variable is not used",
        "Terraform output description",
        "Terraform variable description",
        "Terraform resource description",
        "Terraform module description",
        "Terraform provider description",
        "Terraform resource tag",
        "Terraform module tag",
        "Terraform provider tag",
        "Terraform variable tag",
        "Terraform output tag",
        "AWS resource missing tags",
        "Missing tags",
        "Resource tagging",
        "Description missing",
        "Description is missing",
        "Comment missing",
        "Best practices",
        "Optimization",
        "Performance",
        "Cost optimization",
        "Cost",
        "Resource naming",
        "Naming convention",
        "Naming",
        "Consistency",
        "Maintainability",
        "Readability",
        "Code style",
        "Style",
        "Format",
        "Formatting",
        "Lint",
        "Linter",
        "Best Practice",
        "Code organization",
        "Code structure",
        "Code layout",
        "Code pattern",
        "Pattern",
    }

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

        # kics -o expects a directory; it writes results.json inside it.
        # We use a temp dir for kics output, then copy results to a standalone
        # temp file so the caller can os.unlink it without leaving the dir behind.
        output_dir = tempfile.mkdtemp()
        kics_output_path = os.path.join(output_dir, "results.json")

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as standalone:
            standalone_path = standalone.name

        try:
            subprocess.run(
                ["kics", "scan", "-p", path, "-f", "json", "-o", output_dir],
                capture_output=True,
                text=True,
                timeout=120
            )

            try:
                with open(kics_output_path) as f:
                    data = json.load(f)
            except FileNotFoundError:
                return [], standalone_path

            issues = []
            filtered_count = 0
            for query in data.get("queries", []):
                query_name = query.get("queryName", "")
                description = query.get("description", "")

                # Skip code quality findings to reduce false positives
                if self._is_code_quality(query_name, description):
                    filtered_count += len(query.get("results", []))
                    continue

                # Skip INFO severity findings (mostly informational, low security impact)
                severity = query.get("severity", "MEDIUM")
                if severity == "INFO":
                    filtered_count += len(query.get("results", []))
                    continue

                for result_item in query.get("results", []):
                    issues.append({
                        "type": "Infrastructure as Code",
                        "title": query_name,
                        "description": description,
                        "file": result_item.get("file", "unknown"),
                        "line": result_item.get("line", 1),
                        "severity": self._map_severity(severity),
                        "scanner": "kics",
                    })

            if filtered_count > 0:
                logger.info(f"KICS: Filtered out {filtered_count} code quality/low-severity findings")

            # Copy kics results to the standalone file for the caller
            shutil.copy2(kics_output_path, standalone_path)
            return issues, standalone_path
        except subprocess.TimeoutExpired:
            logger.error("kics scan timed out")
            return [], standalone_path
        except json.JSONDecodeError:
            logger.error("kics output is not valid JSON")
            return [], standalone_path
        except Exception as e:
            logger.error(f"kics scan failed: {e}")
            return [], standalone_path
        finally:
            shutil.rmtree(output_dir, ignore_errors=True)

    def _is_code_quality(self, query_name: str, description: str) -> bool:
        """Check if a KICS query is code quality (not security)"""
        query_lower = query_name.lower()
        desc_lower = description.lower()

        # Direct matches against code quality keywords
        for quality_keyword in self.CODE_QUALITY_QUERIES:
            if quality_keyword.lower() in query_lower:
                return True
            if quality_keyword.lower() in desc_lower:
                return True

        # Pattern-based exclusion
        code_quality_patterns = [
            # Best practice/optimization
            "best practice",
            "optimization",
            "performance",
            "cost optimization",
            "resource naming",
            "naming convention",
            "maintainability",
            "readability",
            "code style",
            "code organization",
            "code structure",
            "code layout",
            "code pattern",
            # Formatting/low-impact
            "line length",
            "formatting",
            "format",
            "indentation",
            # Documentation
            "description missing",
            "comment missing",
            "documentation",
            # Tags/metadata (low security impact)
            "missing tags",
            "resource tagging",
            "metadata labels",
            "metadata annotations",
            # Container health/monitoring (important but not security-critical)
            "health check",
            "liveness probe",
            "readiness probe",
            # User/permissions (context-dependent, often false positive)
            "root user",
            "user in dockerfile",
        ]

        for pattern in code_quality_patterns:
            if pattern in query_lower or pattern in desc_lower:
                return True

        return False

    def _map_severity(self, kics_severity: str) -> str:
        """Map KICS severity to standard levels"""
        mapping = {
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
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
        p = Path(path)
        installers = [
            (p / "package-lock.json", None),
            (p / "yarn.lock",         None),
            (p / "package.json",      ["npm", "install", "--ignore-scripts", "--package-lock-only"]),
            (p / "Pipfile.lock",      ["pipenv", "install", "--deploy"]),
            (p / "requirements.txt",  ["pip", "install", "-r", str(p / "requirements.txt"), "--target", str(p / ".grype-deps")]),
            (p / "go.sum",            ["go", "mod", "download"]),
            (p / "Gemfile.lock",      ["bundle", "install"]),
        ]
        for marker, cmd in installers:
            if marker.exists():
                if cmd is None:
                    return
                logger.info(f"Generating dependency manifest via: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=path, timeout=300)
                if result.returncode != 0:
                    logger.warning(f"Dependency manifest generation failed: {result.stderr[:200]}")
                return

    def scan(self, path: str) -> List[Dict[str, Any]]:
        """Run grype scan"""
        issues, _ = self.scan_with_raw_output(path)
        return issues

    def scan_with_raw_output(self, path: str) -> Tuple[List[Dict[str, Any]], str]:
        """Run grype scan and return raw output file path"""
        if not self.is_installed():
            logger.warning("grype not installed")
            return [], ""

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
            raw_output_path = temp_file.name

        try:
            db_check = subprocess.run(["grype", "db", "status"], capture_output=True)
            if db_check.returncode != 0:
                logger.info("grype database missing, updating...")
                subprocess.run(["grype", "db", "update"], capture_output=True, timeout=120)

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


class PHPVulnScanner(ScannerWrapper):
    """Custom PHP vulnerability scanner with SQLi, XSS, and command injection detection"""

    def is_installed(self) -> bool:
        """Check if PHP scanner is available (always available for this package)"""
        return True

    def install_command(self) -> str:
        """Return installation command"""
        return "Included with ez-appsec"

    def scan(self, path: str) -> List[Dict[str, Any]]:
        """Run PHP vulnerability scan"""
        issues, _ = self.scan_with_raw_output(path)
        return issues

    def scan_with_raw_output(self, path: str) -> Tuple[List[Dict[str, Any]], str]:
        """Run PHP vulnerability scan and return raw output file path"""
        try:
            from ez_appsec.php_vuln_scanner_simple import run_php_scanners

            issues = run_php_scanners(path)

            with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
                raw_output_path = temp_file.name
                json.dump({
                    "issues": issues,
                    "total": len(issues),
                    "scanner": "php-vuln-scanner",
                    "language": "php"
                }, temp_file, indent=2)

            return issues, raw_output_path
        except ImportError as e:
            logger.error(f"PHP scanner not available: {e}")
            return [], ""
        except Exception as e:
            logger.error(f"PHP scan failed: {e}")
            return [], ""


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
            "php-vuln": PHPVulnScanner(),
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
