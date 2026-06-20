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
from ez_appsec.schema import compute_finding_id

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

    def _add_v2_fields(self, finding: Dict[str, Any], category: str) -> Dict[str, Any]:
        """
        Inject v2 fields into a finding dict.
        Computes finding_id from rule_id, file, and line.
        Adds category (scanner-specific) and schema_version.
        """
        rule_id = finding.get("rule_id") or finding.get("title") or "unknown"
        file_path = finding.get("file", "unknown")
        line = finding.get("line", 1)

        finding["finding_id"] = compute_finding_id(rule_id, file_path, line)
        finding["category"] = category
        finding["schema_version"] = "2"
        return finding

    def _add_ai_remediation_fields(
        self,
        finding: Dict[str, Any],
        source: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Default AI remediation enrichment: no-op. Scanners override this when
        their raw output exposes fix/remediation signal (e.g. grype fix versions,
        semgrep autofix, kics remediation).
        """
        return finding


class GitleaksScanner(ScannerWrapper):
    """Wrapper for gitleaks secrets detection"""

    def _add_ai_remediation_fields(
        self,
        finding: Dict[str, Any],
        source: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Secrets always need rotation + scrubbing; populate fix metadata."""
        src = source or {}
        rule_id = src.get("RuleID") or finding.get("rule_id") or "secret"
        finding["fix_type"] = "code_change"
        finding["fix_complexity"] = "moderate"
        finding["effort_mins"] = 30
        finding["affected_symbol"] = rule_id
        finding["ai_context"] = {
            "secret_kind": rule_id,
            "remediation_steps": [
                "rotate the exposed secret immediately",
                "remove the secret from the working tree and rewrite history",
                "store the new secret in a secrets manager",
            ],
        }
        return finding

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
                finding = {
                    "type": "Secrets",
                    "rule_id": match.get("RuleID", "exposed-secret"),
                    "title": f"Exposed {match.get('RuleID', 'Secret')}",
                    "description": f"Potential secret found: {match.get('Match', '')[:50]}...",
                    "file": match.get("File", "unknown"),
                    "line": match.get("StartLine", 1),
                    "severity": "critical",
                    "scanner": "gitleaks",
                }
                finding = self._add_v2_fields(finding, "hardcoded-secret")
                finding = self._add_ai_remediation_fields(finding, match)
                issues.append(finding)

            return issues, raw_output_path
        except subprocess.TimeoutExpired:
            logger.error("gitleaks scan timed out")
            return [], raw_output_path
        except Exception as e:
            logger.error(f"gitleaks scan failed: {e}")
            return [], raw_output_path


RULES_LANGUAGE_MAP = {
    "python": "python",
    "ruby": "ruby",
    "java": "java",
    "javascript": "javascript",
    "js": "javascript",
    "typescript": "javascript",
    "ts": "javascript",
    "php": "php",
    "laravel": "php",
    "django": "python",
    "rails": "ruby",
    "spring": "java",
    "express": "javascript",
}


def resolve_rules_dirs(language_names: List[str]) -> List[str]:
    """Map language/framework names to rule directory paths."""
    package_rules = Path(__file__).parent.parent / "rules"
    docker_rules = Path("/app/rules")
    rules_root = package_rules if package_rules.is_dir() else docker_rules

    dirs: List[str] = []
    for name in language_names:
        key = name.lower()
        if key == "all":
            for lang_dir in sorted(rules_root.iterdir()):
                if lang_dir.is_dir() and not lang_dir.name.startswith("."):
                    dirs.append(str(lang_dir))
            break
        mapped = RULES_LANGUAGE_MAP.get(key, key)
        candidate = rules_root / mapped
        if candidate.is_dir():
            dirs.append(str(candidate))
        else:
            logger.warning(f"No rule pack found for '{name}' (looked in {candidate})")
    return dirs


class SemgrepScanner(ScannerWrapper):
    """Wrapper for semgrep SAST analysis"""

    def __init__(self, enabled: bool = True, extra_rules_dirs: Optional[List[str]] = None):
        super().__init__(enabled)
        self.extra_rules_dirs = extra_rules_dirs or []

    def _add_ai_remediation_fields(
        self,
        finding: Dict[str, Any],
        source: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Use semgrep's autofix and metadata to populate remediation hints."""
        src = source or {}
        extra = src.get("extra", {}) if isinstance(src, dict) else {}
        metadata = extra.get("metadata", {}) if isinstance(extra, dict) else {}
        autofix = extra.get("fix") if isinstance(extra, dict) else None

        if autofix:
            finding["fix_type"] = "code_change"
            finding["fix_complexity"] = "trivial"
            finding["effort_mins"] = 5
        else:
            finding["fix_type"] = "code_change"
            finding["fix_complexity"] = "moderate"
            finding["effort_mins"] = 30

        check_id = src.get("check_id") if isinstance(src, dict) else None
        if check_id:
            finding["affected_symbol"] = str(check_id).rsplit(".", 1)[-1]

        cwe = metadata.get("cwe") if isinstance(metadata, dict) else None
        owasp = metadata.get("owasp") if isinstance(metadata, dict) else None
        references = metadata.get("references") if isinstance(metadata, dict) else None
        ai_ctx: Dict[str, Any] = {}
        if cwe:
            ai_ctx["cwe"] = cwe
        if owasp:
            ai_ctx["owasp"] = owasp
        if references:
            ai_ctx["references"] = references
        if autofix:
            ai_ctx["autofix"] = autofix
        if ai_ctx:
            finding["ai_context"] = ai_ctx
        return finding

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

            for rules_dir in self.extra_rules_dirs:
                if os.path.isdir(rules_dir):
                    config_flags.append(f"--config={rules_dir}")
                    logger.info(f"Using custom rule pack from {rules_dir}")

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

                finding = {
                    "type": "SAST",
                    "rule_id": check_id,
                    "title": check_id,
                    "description": message,
                    "file": result_item.get("path", "unknown"),
                    "line": result_item.get("start", {}).get("line", 1),
                    "severity": self._map_severity(severity, metadata),
                    "scanner": "semgrep",
                }
                finding = self._add_v2_fields(finding, "sast")
                finding = self._add_ai_remediation_fields(finding, result_item)
                issues.append(finding)

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
        category = metadata.get("category", "").lower()
        if category == "security" or "owasp" in category:
            return True
        if metadata.get("owasp"):
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

    def _add_ai_remediation_fields(
        self,
        finding: Dict[str, Any],
        source: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """KICS findings are config misconfigurations; populate config-fix metadata."""
        src = source or {}
        query = src.get("query", {}) if isinstance(src, dict) else {}
        result_item = src.get("result", {}) if isinstance(src, dict) else {}

        finding["fix_type"] = "config"
        finding["fix_complexity"] = "trivial"
        finding["effort_mins"] = 10

        query_name = query.get("queryName") if isinstance(query, dict) else None
        if query_name:
            finding["affected_symbol"] = query_name

        ai_ctx: Dict[str, Any] = {}
        expected = result_item.get("expected_value") if isinstance(result_item, dict) else None
        actual = result_item.get("actual_value") if isinstance(result_item, dict) else None
        category = query.get("category") if isinstance(query, dict) else None
        platform = query.get("platform") if isinstance(query, dict) else None
        if expected is not None:
            ai_ctx["expected_value"] = expected
        if actual is not None:
            ai_ctx["actual_value"] = actual
        if category:
            ai_ctx["category"] = category
        if platform:
            ai_ctx["platform"] = platform
        if ai_ctx:
            finding["ai_context"] = ai_ctx
        return finding

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
                    finding = {
                        "type": "Infrastructure as Code",
                        "rule_id": query_name,
                        "title": query_name,
                        "description": description,
                        "file": result_item.get("file", "unknown"),
                        "line": result_item.get("line", 1),
                        "severity": self._map_severity(severity),
                        "scanner": "kics",
                    }
                    finding = self._add_v2_fields(finding, "iac")
                    finding = self._add_ai_remediation_fields(
                        finding, {"query": query, "result": result_item}
                    )
                    issues.append(finding)

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
            "runs as root",
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

    def _add_ai_remediation_fields(
        self,
        finding: Dict[str, Any],
        source: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Grype findings are dependency CVEs; fix is usually a version upgrade."""
        src = source or {}
        vulnerability = src.get("vulnerability", {}) if isinstance(src, dict) else {}
        artifact = src.get("artifact", {}) if isinstance(src, dict) else {}
        fix = vulnerability.get("fix", {}) if isinstance(vulnerability, dict) else {}
        fix_state = fix.get("state") if isinstance(fix, dict) else None
        fix_versions = fix.get("versions") if isinstance(fix, dict) else None

        if fix_state == "fixed" and fix_versions:
            finding["fix_type"] = "upgrade"
            finding["fix_complexity"] = "trivial"
            finding["effort_mins"] = 5
        elif fix_state == "wont-fix":
            finding["fix_type"] = "suppress"
            finding["fix_complexity"] = "moderate"
            finding["effort_mins"] = 15
        else:
            finding["fix_type"] = "upgrade"
            finding["fix_complexity"] = "complex"
            finding["effort_mins"] = 60

        artifact_name = artifact.get("name") if isinstance(artifact, dict) else None
        if artifact_name:
            finding["affected_symbol"] = artifact_name

        ai_ctx: Dict[str, Any] = {}
        artifact_version = artifact.get("version") if isinstance(artifact, dict) else None
        if artifact_name:
            ai_ctx["package"] = artifact_name
        if artifact_version:
            ai_ctx["current_version"] = artifact_version
        if fix_versions:
            ai_ctx["fix_versions"] = fix_versions
        if fix_state:
            ai_ctx["fix_state"] = fix_state
        cvss = vulnerability.get("cvss") if isinstance(vulnerability, dict) else None
        if cvss:
            ai_ctx["cvss"] = cvss
        if ai_ctx:
            finding["ai_context"] = ai_ctx
        return finding

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
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, cwd=path, timeout=300)
                except FileNotFoundError:
                    logger.warning(
                        "Dependency manifest generation skipped: %s is not installed. "
                        "Commit a lockfile/SBOM or use the standard image for automatic dependency installation.",
                        cmd[0],
                    )
                    return
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
                cve_id = vulnerability.get("id")
                artifact_name = match.get("artifact", {}).get("name", "unknown")
                finding = {
                    "type": "Dependency",
                    "rule_id": cve_id or artifact_name,
                    "title": f"{artifact_name} - {cve_id}",
                    "description": vulnerability.get("description", "Known vulnerability in dependency"),
                    "file": "dependency: " + artifact_name,
                    "line": 1,
                    "severity": vulnerability.get("severity", "medium").lower(),
                    "scanner": "grype",
                    "cve_id": cve_id,
                }
                finding = self._add_v2_fields(finding, "dependency")
                finding = self._add_ai_remediation_fields(finding, match)
                issues.append(finding)

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


class GrypeImageScanner:
    """Scans container images for OS-level CVEs using grype."""

    def is_installed(self) -> bool:
        try:
            subprocess.run(["grype", "--version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def scan(self, image: str, registry_auth: str = None) -> List[Dict[str, Any]]:
        if not self.is_installed():
            logger.warning("grype not installed")
            return []

        if not image:
            raise ValueError("Image reference is required (e.g. 'nginx:latest')")

        env = os.environ.copy()
        if registry_auth:
            parts = registry_auth.split(":", 1)
            if len(parts) != 2:
                raise ValueError("--registry-auth must be in user:token format")
            env["GRYPE_REGISTRY_AUTH_USERNAME"] = parts[0]
            env["GRYPE_REGISTRY_AUTH_PASSWORD"] = parts[1]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
            raw_output_path = temp_file.name

        try:

            db_check = subprocess.run(["grype", "db", "status"], capture_output=True, env=env)
            if db_check.returncode != 0:
                logger.info("grype database missing, updating...")
                subprocess.run(["grype", "db", "update"], capture_output=True, timeout=120, env=env)

            # grype exits non-zero when it finds vulns; we read findings from
            # --file regardless, so we don't check returncode. We only surface
            # an error if the output file is missing entirely (grype crashed
            # before writing it).
            proc = subprocess.run(
                ["grype", image, "-o", "json", "--file", raw_output_path],
                capture_output=True,
                text=True,
                timeout=600,
                env=env,
            )

            try:
                with open(raw_output_path) as f:
                    data = json.load(f)
            except FileNotFoundError:
                logger.error(
                    "grype did not produce output (exit %s): %s",
                    proc.returncode,
                    (proc.stderr or "").strip()[:500],
                )
                return []

            issues = []
            for match in data.get("matches", []):
                vulnerability = match.get("vulnerability", {})
                artifact = match.get("artifact", {})
                severity_raw = (vulnerability.get("severity") or "medium").lower()
                if severity_raw not in ("low", "medium", "high", "critical"):
                    severity_raw = "medium"

                issues.append({
                    "type": "Dependency",
                    "category": "container_scanning",
                    "title": f"{artifact.get('name', 'unknown')} - {vulnerability.get('id', 'unknown')}",
                    "description": vulnerability.get("description", "Known vulnerability in container image package"),
                    "file": f"image: {image}",
                    "severity": severity_raw,
                    "scanner": "grype",
                    "cve": vulnerability.get("id"),
                })

            return issues
        except subprocess.TimeoutExpired:
            logger.error("grype image scan timed out")
            return []
        except json.JSONDecodeError:
            logger.error("grype image scan output is not valid JSON")
            return []
        except Exception as e:
            logger.error(f"grype image scan failed: {e}")
            return []
        finally:
            try:
                os.unlink(raw_output_path)
            except OSError:
                pass


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
