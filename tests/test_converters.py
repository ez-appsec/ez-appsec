"""Tests for vulnerability format converters"""

import pytest
import json
import tempfile
from pathlib import Path

from ez_appsec.converters import (
    GitHubSarifFormat,
    GitHubGitleaksConverter,
    GitHubSemgrepConverter,
    GitHubKicsConverter,
    GitHubGrypeConverter,
    VulnerabilityConverters,
    GitLabVulnerabilityFormat
)


class TestGitHubSarifFormat:
    """Tests for GitHub SARIF format converter"""

    def test_create_report_structure(self):
        """Test that SARIF report has correct structure"""
        report = GitHubSarifFormat.create_report([])

        assert report["version"] == "2.1.0"
        assert "$schema" in report
        assert "runs" in report
        assert len(report["runs"]) == 1
        assert "tool" in report["runs"][0]
        assert "results" in report["runs"][0]

    def test_create_rule(self):
        """Test creating a SARIF rule"""
        rule = GitHubSarifFormat.create_rule(
            rule_id="TEST-001",
            name="Test Rule",
            short_description="A test rule",
            full_description="Full description",
            help_uri="https://example.com"
        )

        assert rule["id"] == "TEST-001"
        assert rule["name"] == "Test Rule"
        assert rule["shortDescription"]["text"] == "A test rule"
        assert rule["fullDescription"]["text"] == "Full description"
        assert rule["helpUri"] == "https://example.com"

    def test_create_result(self):
        """Test creating a SARIF result"""
        result = GitHubSarifFormat.create_result(
            rule_id="TEST-001",
            message="Test message",
            level="error",
            locations=[GitHubSarifFormat.create_location("test.py", 1, 1)]
        )

        assert result["ruleId"] == "TEST-001"
        assert result["message"]["text"] == "Test message"
        assert result["level"] == "error"
        assert "locations" in result
        assert len(result["locations"]) == 1

    def test_create_location(self):
        """Test creating a SARIF location"""
        location = GitHubSarifFormat.create_location(
            file_path="test.py",
            start_line=5,
            end_line=10,
            start_column=1,
            end_column=50
        )

        assert location["physicalLocation"]["artifactLocation"]["uri"] == "test.py"
        assert location["physicalLocation"]["region"]["startLine"] == 5
        assert location["physicalLocation"]["region"]["endLine"] == 10
        assert location["physicalLocation"]["region"]["startColumn"] == 1
        assert location["physicalLocation"]["region"]["endColumn"] == 50

    def test_map_severity_to_level(self):
        """Test severity to SARIF level mapping"""
        assert GitHubSarifFormat.map_severity_to_level("critical") == "error"
        assert GitHubSarifFormat.map_severity_to_level("high") == "error"
        assert GitHubSarifFormat.map_severity_to_level("medium") == "warning"
        assert GitHubSarifFormat.map_severity_to_level("low") == "note"
        assert GitHubSarifFormat.map_severity_to_level("info") == "note"
        assert GitHubSarifFormat.map_severity_to_level("unknown") == "warning"


class TestGitHubGitleaksConverter:
    """Tests for Gitleaks to SARIF converter"""

    def test_convert_empty_file(self):
        """Test converting empty gitleaks output"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump([], f)
            f.flush()
            report = GitHubGitleaksConverter.convert(f.name)

        assert report["version"] == "2.1.0"
        assert report["runs"][0]["tool"]["driver"]["name"] == "gitleaks"
        assert len(report["runs"][0]["results"]) == 0

    def test_convert_gitleaks_output(self):
        """Test converting gitleaks JSON to SARIF"""
        gitleaks_data = [{
            "Description": "AWS Access Key",
            "RuleID": "aws-access-key",
            "Match": "EXAMPLE-AWS-ACCESS-KEY-ID",
            "File": "config.py",
            "StartLine": 10,
            "EndLine": 10,
            "Info": {"Severity": "critical"}
        }]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(gitleaks_data, f)
            f.flush()
            report = GitHubGitleaksConverter.convert(f.name)

        assert report["runs"][0]["tool"]["driver"]["name"] == "gitleaks"
        assert len(report["runs"][0]["results"]) == 1
        assert len(report["runs"][0]["tool"]["driver"]["rules"]) == 1

        result = report["runs"][0]["results"][0]
        assert result["ruleId"] == "aws-access-key"
        assert result["level"] == "error"
        assert "Potential secret found" in result["message"]["text"]
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "config.py"


class TestGitHubSemgrepConverter:
    """Tests for Semgrep to SARIF converter"""

    def test_convert_empty_file(self):
        """Test converting empty semgrep output"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"results": []}, f)
            f.flush()
            report = GitHubSemgrepConverter.convert(f.name)

        assert report["runs"][0]["tool"]["driver"]["name"] == "semgrep"
        assert len(report["runs"][0]["results"]) == 0

    def test_convert_semgrep_output(self):
        """Test converting semgrep JSON to SARIF"""
        semgrep_data = {
            "results": [{
                "check_id": "python.flask.security.detected.xss",
                "path": "app.py",
                "start": {"line": 20, "col": 1},
                "end": {"line": 20, "col": 50},
                "extra": {
                    "message": "Potential XSS vulnerability",
                    "severity": "ERROR",
                    "metadata": {
                        "security-severity": "high",
                        "description": "Flask XSS vulnerability"
                    }
                }
            }]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(semgrep_data, f)
            f.flush()
            report = GitHubSemgrepConverter.convert(f.name)

        assert report["runs"][0]["tool"]["driver"]["name"] == "semgrep"
        assert len(report["runs"][0]["results"]) == 1

        result = report["runs"][0]["results"][0]
        assert result["ruleId"] == "python.flask.security.detected.xss"
        assert result["level"] == "error"  # ERROR + high security-severity
        assert result["message"]["text"] == "Potential XSS vulnerability"


class TestGitHubKicsConverter:
    """Tests for KICS to SARIF converter"""

    def test_convert_empty_file(self):
        """Test converting empty KICS output"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"queries": []}, f)
            f.flush()
            report = GitHubKicsConverter.convert(f.name)

        assert report["runs"][0]["tool"]["driver"]["name"] == "kics"
        assert len(report["runs"][0]["results"]) == 0

    def test_convert_kics_output(self):
        """Test converting KICS JSON to SARIF"""
        kics_data = {
            "queries": [{
                "queryName": "S3 bucket public access",
                "description": "S3 bucket has public access enabled",
                "severity": "HIGH",
                "files": ["terraform/s3.tf", "infra/s3-bucket.json"]
            }]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(kics_data, f)
            f.flush()
            report = GitHubKicsConverter.convert(f.name)

        assert report["runs"][0]["tool"]["driver"]["name"] == "kics"
        assert len(report["runs"][0]["results"]) == 2  # 2 files
        assert len(report["runs"][0]["tool"]["driver"]["rules"]) == 1

        result = report["runs"][0]["results"][0]
        assert result["ruleId"] == "S3 bucket public access"
        assert result["level"] == "error"


class TestGitHubGrypeConverter:
    """Tests for Grype to SARIF converter"""

    def test_convert_empty_file(self):
        """Test converting empty grype output"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"matches": []}, f)
            f.flush()
            report = GitHubGrypeConverter.convert(f.name)

        assert report["runs"][0]["tool"]["driver"]["name"] == "grype"
        assert len(report["runs"][0]["results"]) == 0

    def test_convert_grype_output(self):
        """Test converting grype JSON to SARIF"""
        grype_data = {
            "matches": [{
                "artifact": {
                    "name": "requests",
                    "version": "2.20.0"
                },
                "vulnerability": {
                    "id": "CVE-2023-12345",
                    "severity": "High",
                    "description": "A vulnerability in requests library",
                    "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"
                }
            }]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(grype_data, f)
            f.flush()
            report = GitHubGrypeConverter.convert(f.name)

        assert report["runs"][0]["tool"]["driver"]["name"] == "grype"
        assert len(report["runs"][0]["results"]) == 1

        result = report["runs"][0]["results"][0]
        assert result["ruleId"] == "CVE-2023-12345"
        assert result["level"] == "error"
        assert "requests" in result["message"]["text"]


class TestVulnerabilityConverters:
    """Tests for main converter class"""

    def test_convert_to_github_format(self):
        """Test converting scanner output to GitHub format"""
        gitleaks_data = [{
            "Description": "AWS Access Key",
            "RuleID": "aws-access-key",
            "Match": "EXAMPLE-AWS-ACCESS-KEY-ID",
            "File": "config.py",
            "StartLine": 10,
            "EndLine": 10,
            "Info": {"Severity": "critical"}
        }]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(gitleaks_data, f)
            f.flush()
            report = VulnerabilityConverters.convert_to_github_format("gitleaks", f.name)

        assert report["version"] == "2.1.0"
        assert report["runs"][0]["tool"]["driver"]["name"] == "gitleaks"

    def test_unknown_scanner_raises_error(self):
        """Test that unknown scanner raises ValueError"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump([], f)
            f.flush()

        with pytest.raises(ValueError, match="Unknown scanner"):
            VulnerabilityConverters.convert_to_github_format("unknown-scanner", f.name)

    def test_merge_github_reports(self):
        """Test merging multiple SARIF reports"""
        report1 = GitHubSarifFormat.create_report([
            GitHubSarifFormat.create_result("RULE-1", "Test 1")
        ], "scanner1")

        report2 = GitHubSarifFormat.create_report([
            GitHubSarifFormat.create_result("RULE-2", "Test 2")
        ], "scanner2")

        merged = VulnerabilityConverters.merge_github_reports([report1, report2])

        assert len(merged["runs"][0]["results"]) == 2
        assert merged["runs"][0]["tool"]["driver"]["name"] == "ez-appsec"
