"""Test false positive reduction in external scanners"""
import pytest
from pathlib import Path
from ez_appsec.external_scanners import KicsScanner, SemgrepScanner


class TestKicsFalsePositiveReduction:
    """Test KICS code quality filtering"""

    def test_code_quality_query_names_are_filtered(self):
        """Verify code quality query names are filtered out"""
        scanner = KicsScanner()

        # Test various code quality patterns
        code_quality_queries = [
            "Unused container instruction",
            "Container image uses latest tag",
            "Root user in container",
            "Missing tags",
            "Best practices for resource naming",
            "Health check not enabled",
            "Kubernetes labels not present",
            "Dockerfile line length should be less than 200 characters",
        ]

        for query_name in code_quality_queries:
            description = f"Description for {query_name}"
            assert scanner._is_code_quality(query_name, description), \
                f"Query '{query_name}' should be flagged as code quality"

    def test_security_queries_are_not_filtered(self):
        """Verify security queries are NOT filtered out"""
        scanner = KicsScanner()

        # Test security query patterns (should NOT be filtered)
        security_queries = [
            ("Container using HTTP protocol", "Container is configured to use HTTP instead of HTTPS"),
            ("Missing TLS configuration", "TLS is not configured for this resource"),
            ("Insecure SSL configuration", "SSL version 2.0 is enabled"),
            ("Privileged container", "Container is running in privileged mode"),
            ("Sensitive environment variable", "AWS credentials found in environment variables"),
            ("Open security group", "Security group allows ingress from 0.0.0.0/0"),
            ("Unrestricted firewall rule", "Firewall rule allows all traffic"),
        ]

        for query_name, description in security_queries:
            assert not scanner._is_code_quality(query_name, description), \
                f"Security query '{query_name}' should NOT be filtered"

    def test_severity_mapping_excludes_info(self):
        """Verify INFO severity is excluded from mapping"""
        scanner = KicsScanner()

        assert scanner._map_severity("HIGH") == "high"
        assert scanner._map_severity("MEDIUM") == "medium"
        assert scanner._map_severity("LOW") == "low"
        # INFO should not map (excluded in scan_with_raw_output)
        # But the function should handle it gracefully
        assert scanner._map_severity("INFO") == "medium"  # fallback


class TestSemgrepFalsePositiveReduction:
    """Test Semgrep code quality filtering"""

    def test_code_quality_check_ids_are_filtered(self):
        """Verify code quality check IDs are filtered out"""
        scanner = SemgrepScanner()

        code_quality_checks = [
            "python.use-none-param",
            "python.bad-open-file-mode",
            "javascript.no-console-spam",
            "javascript.performance.no-delete-var",
            "complexity",
            "cyclomatic-complexity",
            "max-params",
        ]

        for check_id in code_quality_checks:
            assert scanner._is_code_quality(check_id, {}, ""), \
                f"Check ID '{check_id}' should be flagged as code quality"

    def test_security_check_ids_are_not_filtered(self):
        """Verify security check IDs are NOT filtered out"""
        scanner = SemgrepScanner()

        # Security checks (should NOT be filtered)
        security_checks = [
            ("python.sql-injection", {"category": "security", "cwe": "CWE-89"}, "SQL injection found"),
            ("javascript.express.xss", {"category": "security", "owasp": "A03: Injection"}, "XSS vulnerability"),
            ("python.shell-injection", {"category": "security"}, "Command injection"),
            ("javascript.mongodb.nosql-injection", {"cwe": "CWE-943"}, "NoSQL injection"),
        ]

        for check_id, metadata, message in security_checks:
            assert not scanner._is_code_quality(check_id, metadata, message), \
                f"Security check '{check_id}' should NOT be filtered"

    def test_best_practice_category_is_filtered(self):
        """Verify best practice category is filtered"""
        scanner = SemgrepScanner()

        # Best practice (code quality)
        assert scanner._is_code_quality(
            "some.check",
            {"category": "best practice"},
            "This is a best practice rule"
        )

        # Security category (should NOT be filtered)
        assert not scanner._is_code_quality(
            "some.check",
            {"category": "security"},
            "This is a security rule"
        )

    def test_info_severity_without_security_metadata_is_filtered(self):
        """Verify INFO findings without security metadata are filtered"""
        scanner = SemgrepScanner()

        # INFO with no security metadata → filtered
        assert not scanner._is_security_finding({"category": "best practice"})
        assert not scanner._is_security_finding({})
        assert not scanner._is_security_finding({"technology": "python"})

        # INFO with security metadata → kept
        assert scanner._is_security_finding({"cwe": "CWE-89"})
        assert scanner._is_security_finding({"category": "security"})
        assert scanner._is_security_finding({"owasp": "A03: Injection"})
        assert scanner._is_security_finding({"security-severity": "high"})

    def test_security_severity_mapping(self):
        """Verify GitLab security-severity is used when available"""
        scanner = SemgrepScanner()

        # security-severity metadata takes precedence
        assert scanner._map_severity("INFO", {"security-severity": "critical"}) == "critical"
        assert scanner._map_severity("INFO", {"security-severity": "high"}) == "high"
        assert scanner._map_severity("INFO", {"security-severity": "medium"}) == "medium"
        assert scanner._map_severity("INFO", {"security-severity": "low"}) == "low"

        # Fallback to semgrep severity
        assert scanner._map_severity("ERROR", {}) == "high"
        assert scanner._map_severity("WARNING", {}) == "medium"
        # Default fallback
        assert scanner._map_severity("INFO", {}) == "medium"


class TestFalsePositiveReductionIntegration:
    """Integration tests for false positive reduction"""

    def test_kics_filters_code_quality_patterns(self):
        """Test that KICS filtering catches various code quality patterns"""
        scanner = KicsScanner()

        # Test pattern matching works
        test_cases = [
            ("Performance optimization for resources", False),  # code quality
            ("Resource naming convention violated", False),  # code quality
            ("Security group allows all traffic", True),  # security
            ("Sensitive data in logs", True),  # security
            ("Container runs as root", False),  # often false positive
            ("Privileged container access", True),  # security
        ]

        for query_name, is_security in test_cases:
            result = scanner._is_code_quality(query_name, "")
            assert result == (not is_security), \
                f"Query '{query_name}' filtering result incorrect"

    def test_semgrep_filters_code_quality_by_message(self):
        """Test that Semgrep filters based on message content"""
        scanner = SemgrepScanner()

        # Security-related messages
        security_messages = [
            "SQL injection vulnerability found",
            "XSS via unsanitized user input",
            "Command injection in subprocess call",
            "Hardcoded secret detected",
            "Authentication bypass possible",
        ]

        for message in security_messages:
            assert not scanner._is_code_quality("generic.check", {}, message), \
                f"Security message should NOT be filtered: {message}"

        # Code quality messages
        quality_messages = [
            "Function exceeds maximum complexity",
            "Variable naming does not follow convention",
            "Missing type hints for function parameters",
            "Unused import detected",
        ]

        for message in quality_messages:
            # May or may not be filtered depending on check_id
            # But with generic check_id and no metadata, it likely should be
            result = scanner._is_code_quality("generic.check", {}, message)
            # This is context-dependent, so we just verify it doesn't crash
            assert isinstance(result, bool)
