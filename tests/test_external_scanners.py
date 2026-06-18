"""Tests for external scanner wrappers"""

import pytest
from ez_appsec.external_scanners import (
    GitleaksScanner,
    SemgrepScanner,
    KicsScanner,
    GrypeScanner,
)


class TestGitleaksScannerV2Fields:
    """Test that GitleaksScanner injects v2 fields"""

    def test_gitleaks_wrapper_has_add_v2_fields_method(self):
        """GitleaksScanner should have _add_v2_fields method"""
        scanner = GitleaksScanner()
        assert hasattr(scanner, "_add_v2_fields")
        assert callable(scanner._add_v2_fields)

    def test_gitleaks_add_v2_fields_adds_all_fields(self):
        """_add_v2_fields should add finding_id, category, and schema_version"""
        scanner = GitleaksScanner()
        finding = {
            "rule_id": "test-secret",
            "file": "config.py",
            "line": 10,
            "severity": "critical",
        }
        enhanced = scanner._add_v2_fields(finding, "hardcoded-secret")

        assert "finding_id" in enhanced
        assert len(enhanced["finding_id"]) == 64  # SHA256 hex digest
        assert enhanced["category"] == "hardcoded-secret"
        assert enhanced["schema_version"] == "2"
        # Original fields preserved
        assert enhanced["rule_id"] == "test-secret"
        assert enhanced["file"] == "config.py"


class TestSemgrepScannerV2Fields:
    """Test that SemgrepScanner injects v2 fields"""

    def test_semgrep_wrapper_has_add_v2_fields_method(self):
        """SemgrepScanner should have _add_v2_fields method"""
        scanner = SemgrepScanner()
        assert hasattr(scanner, "_add_v2_fields")

    def test_semgrep_add_v2_fields_adds_all_fields(self):
        """_add_v2_fields should add finding_id, category, and schema_version"""
        scanner = SemgrepScanner()
        finding = {
            "rule_id": "python.lang.security.injection.sql.sql-injection-parametrized",
            "file": "app.py",
            "line": 42,
            "severity": "high",
        }
        enhanced = scanner._add_v2_fields(finding, "sast")

        assert "finding_id" in enhanced
        assert len(enhanced["finding_id"]) == 64
        assert enhanced["category"] == "sast"
        assert enhanced["schema_version"] == "2"


class TestKicsScannerV2Fields:
    """Test that KicsScanner injects v2 fields"""

    def test_kics_wrapper_has_add_v2_fields_method(self):
        """KicsScanner should have _add_v2_fields method"""
        scanner = KicsScanner()
        assert hasattr(scanner, "_add_v2_fields")

    def test_kics_add_v2_fields_adds_all_fields(self):
        """_add_v2_fields should add finding_id, category, and schema_version"""
        scanner = KicsScanner()
        finding = {
            "rule_id": "Exposed Port",
            "file": "docker-compose.yml",
            "line": 5,
            "severity": "medium",
        }
        enhanced = scanner._add_v2_fields(finding, "iac")

        assert "finding_id" in enhanced
        assert len(enhanced["finding_id"]) == 64
        assert enhanced["category"] == "iac"
        assert enhanced["schema_version"] == "2"


class TestGrypeScannerV2Fields:
    """Test that GrypeScanner injects v2 fields"""

    def test_grype_wrapper_has_add_v2_fields_method(self):
        """GrypeScanner should have _add_v2_fields method"""
        scanner = GrypeScanner()
        assert hasattr(scanner, "_add_v2_fields")

    def test_grype_add_v2_fields_adds_all_fields(self):
        """_add_v2_fields should add finding_id, category, and schema_version"""
        scanner = GrypeScanner()
        finding = {
            "rule_id": "CVE-2021-12345",
            "file": "dependency: requests",
            "line": 1,
            "severity": "high",
            "cve_id": "CVE-2021-12345",
        }
        enhanced = scanner._add_v2_fields(finding, "dependency")

        assert "finding_id" in enhanced
        assert len(enhanced["finding_id"]) == 64
        assert enhanced["category"] == "dependency"
        assert enhanced["schema_version"] == "2"


class TestV2FieldConsistency:
    """Test that v2 fields are consistent across all scanner types"""

    def test_finding_id_deterministic(self):
        """Same finding input should produce same finding_id across scanners"""
        gitleaks = GitleaksScanner()
        semgrep = SemgrepScanner()

        finding_base = {
            "rule_id": "test-rule",
            "file": "app.py",
            "line": 10,
            "severity": "high",
        }

        gitleaks_result = gitleaks._add_v2_fields(finding_base.copy(), "hardcoded-secret")
        semgrep_result = semgrep._add_v2_fields(finding_base.copy(), "sast")

        # Both should produce same finding_id for same inputs
        assert gitleaks_result["finding_id"] == semgrep_result["finding_id"]

    def test_schema_version_consistent(self):
        """All scanners should set schema_version='2'"""
        scanners = [
            GitleaksScanner(),
            SemgrepScanner(),
            KicsScanner(),
            GrypeScanner(),
        ]

        finding_base = {
            "rule_id": "test",
            "file": "test.py",
            "line": 1,
            "severity": "low",
        }

        for scanner in scanners:
            result = scanner._add_v2_fields(finding_base.copy(), "test-cat")
            assert result["schema_version"] == "2"

    def test_categories_mapped_correctly(self):
        """Each scanner should map to its correct category"""
        test_cases = [
            (GitleaksScanner(), "hardcoded-secret"),
            (SemgrepScanner(), "sast"),
            (KicsScanner(), "iac"),
            (GrypeScanner(), "dependency"),
        ]

        finding_base = {
            "rule_id": "test",
            "file": "test.py",
            "line": 1,
            "severity": "low",
        }

        for scanner, expected_category in test_cases:
            result = scanner._add_v2_fields(finding_base.copy(), expected_category)
            assert result["category"] == expected_category


class TestV2FieldsWithMissingFields:
    """Test v2 field injection when finding has missing fields"""

    def test_missing_rule_id_uses_title(self):
        """If rule_id missing, should use title for finding_id computation"""
        scanner = SemgrepScanner()
        finding = {
            "title": "Security Issue",
            "file": "app.py",
            "line": 5,
        }
        result = scanner._add_v2_fields(finding, "sast")
        assert "finding_id" in result
        assert len(result["finding_id"]) == 64

    def test_missing_file_uses_unknown(self):
        """If file missing, should use 'unknown'"""
        scanner = GitleaksScanner()
        finding = {
            "rule_id": "secret-rule",
            "line": 1,
        }
        result = scanner._add_v2_fields(finding, "hardcoded-secret")
        assert "finding_id" in result
        assert len(result["finding_id"]) == 64

    def test_missing_line_uses_default(self):
        """If line missing, should use 1 as default"""
        scanner = KicsScanner()
        finding = {
            "rule_id": "iac-rule",
            "file": "infrastructure.tf",
        }
        result = scanner._add_v2_fields(finding, "iac")
        assert "finding_id" in result
        assert len(result["finding_id"]) == 64
