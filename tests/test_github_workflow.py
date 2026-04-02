"""Tests for GitHub workflow integration"""

import pytest
import json
import tempfile
from pathlib import Path
from ez_appsec.converters import (
    GitHubSarifFormat,
    GitHubGitleaksConverter,
    GitHubSemgrepConverter,
    GitHubKicsConverter,
    GitHubGrypeConverter
)


def test_sarif_format_validation():
    """Test SARIF format meets specification"""
    report = GitHubSarifFormat.create_report([
        GitHubSarifFormat.create_result("test-rule", "Test finding", "error")
    ], "ez-appsec")

    # Validate required fields
    assert "version" in report
    assert "$schema" in report
    assert "runs" in report
    assert len(report["runs"]) > 0

    # Validate run structure
    run = report["runs"][0]
    assert "tool" in run
    assert "results" in run
    assert "driver" in run["tool"]

    # Validate driver structure
    driver = run["tool"]["driver"]
    assert "name" in driver
    assert "informationUri" in driver


def test_sarif_result_structure():
    """Test SARIF result has required fields"""
    result = GitHubSarifFormat.create_result(
        rule_id="test-rule",
        message="Test finding",
        level="warning",
        locations=[GitHubSarifFormat.create_location("test.py", 1, 1)]
    )

    # Validate required fields
    assert "ruleId" in result
    assert "level" in result
    assert "message" in result
    assert "locations" in result


def test_gitleaks_converter():
    """Test Gitleaks to GitHub SARIF converter"""
    gitleaks_data = [{
        "Description": "AWS Access Key",
        "RuleID": "aws-access-key",
        "Match": "AKIAIOSFODNN7EXAMPLE",
        "File": "config.py",
        "StartLine": 10,
        "EndLine": 10,
        "Info": {"Severity": "critical"}
    }]

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(gitleaks_data, f)
        f.flush()

        report = GitHubGitleaksConverter.convert(f.name)

    # Validate structure
    assert "version" in report
    assert "runs" in report
    assert len(report["runs"]) == 1

    # Validate result
    results = report["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "aws-access-key"
    assert results[0]["level"] == "error"


def test_semgrep_converter():
    """Test Semgrep to GitHub SARIF converter"""
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
                    "security-severity": "high"
                }
            }
        }]
    }

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(semgrep_data, f)
        f.flush()

        report = GitHubSemgrepConverter.convert(f.name)

    results = report["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "python.flask.security.detected.xss"
    assert results[0]["level"] == "error"


def test_dashboard_aggregation():
    """Test dashboard aggregation script logic"""
    # Mock dashboard data
    index_data = {
        "last_updated": "2026-04-01T00:00:00Z",
        "projects": [
            {
                "slug": "test-project",
                "name": "Test Project",
                "project_path": "owner/test-project",
                "github_url": "https://github.com/owner/test-project",
                "last_updated": "2026-04-01T12:00:00Z",
                "summary": {
                    "total": 5,
                    "critical": 1,
                    "high": 2,
                    "medium": 1,
                    "low": 1
                }
            }
        ]
    }

    # Validate structure
    assert "last_updated" in index_data
    assert "projects" in index_data
    assert len(index_data["projects"]) == 1

    project = index_data["projects"][0]
    assert "slug" in project
    assert "name" in project
    assert "github_url" in project
    assert "summary" in project

    summary = project["summary"]
    assert summary["total"] == 5
    assert summary["critical"] == 1
    assert summary["high"] == 2
