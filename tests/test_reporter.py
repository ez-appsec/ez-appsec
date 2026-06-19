"""Tests for report format generation."""

from pathlib import Path

import pytest

from ez_appsec.reporter import Reporter


@pytest.mark.parametrize(
    ("file_value", "expected_uri"),
    [
        ({"uri": "src/app.py"}, "src/app.py"),
        ({"file": "src/file.py"}, "src/file.py"),
        ({"path": Path("src/path.py")}, "src/path.py"),
        (["src/list.py"], "src/list.py"),
        (Path("src\\windows.py"), "src/windows.py"),
        (None, "unknown"),
    ],
)
def test_to_sarif_coerces_artifact_uri_to_string(file_value, expected_uri):
    """GitHub SARIF upload requires artifactLocation.uri to be a string."""
    report = Reporter.to_sarif(
        {
            "issues": [
                {
                    "type": "TEST-001",
                    "title": "Test finding",
                    "file": file_value,
                    "line": 7,
                    "severity": "warning",
                }
            ]
        }
    )

    uri = report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == expected_uri
    assert isinstance(uri, str)
