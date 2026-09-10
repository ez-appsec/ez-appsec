"""Failure-contract tests for enabled external scanner components."""

import os
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from ez_appsec.external_scanners import (
    ExternalScannerManager,
    GitleaksScanner,
    GrypeScanner,
    KicsScanner,
    PHPVulnScanner,
    ScannerExecutionError,
    SemgrepScanner,
)
from ez_appsec.converters import VulnerabilityConverters
from ez_appsec.scanner import SecurityScanner


@pytest.mark.parametrize(
    ("scanner", "name"),
    [
        (GitleaksScanner(), "gitleaks"),
        (SemgrepScanner(), "semgrep"),
        (KicsScanner(), "kics"),
        (GrypeScanner(), "grype"),
    ],
)
def test_enabled_missing_component_is_not_empty_success(scanner, name):
    with patch.object(scanner, "is_installed", return_value=False):
        with pytest.raises(ScannerExecutionError) as raised:
            scanner.scan(".")

    assert raised.value.scanner == name
    assert raised.value.code == "not_installed"
    assert str(raised.value) == f"{name} scanner failed (not_installed)"


def test_timeout_is_a_bounded_failure(tmp_path):
    scanner = GitleaksScanner()
    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch(
            "ez_appsec.external_scanners.subprocess.run",
            side_effect=subprocess.TimeoutExpired("gitleaks", 60),
        ),
    ):
        with pytest.raises(ScannerExecutionError) as raised:
            scanner.scan(str(tmp_path))

    assert raised.value.scanner == "gitleaks"
    assert raised.value.code == "timeout"
    assert "gitleaks" in str(raised.value)
    assert str(tmp_path) not in str(raised.value)


def test_invalid_json_is_not_empty_success(tmp_path):
    scanner = SemgrepScanner()
    completed = subprocess.CompletedProcess([], 0, "", "")
    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch("ez_appsec.external_scanners.subprocess.run", return_value=completed),
    ):
        with pytest.raises(ScannerExecutionError) as raised:
            scanner.scan(str(tmp_path))

    assert raised.value.scanner == "semgrep"
    assert raised.value.code == "invalid_output"


def test_tool_specific_finding_exit_codes_are_complete(tmp_path):
    scanner = GitleaksScanner()

    def write_empty_report(command, **_kwargs):
        report_path = Path(command[command.index("--report-path") + 1])
        report_path.write_text("[]")
        return subprocess.CompletedProcess(command, 1, "", "")

    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch("ez_appsec.external_scanners.subprocess.run", side_effect=write_empty_report),
    ):
        issues, raw_path = scanner.scan_with_raw_output(str(tmp_path))

    try:
        assert issues == []
        assert Path(raw_path).read_text() == "[]"
    finally:
        os.unlink(raw_path)


def test_semgrep_finding_exit_code_is_complete(tmp_path):
    scanner = SemgrepScanner()

    def write_empty_report(command, **_kwargs):
        report_path = Path(command[command.index("--output") + 1])
        report_path.write_text('{"results": [], "errors": []}')
        return subprocess.CompletedProcess(command, 1, "", "")

    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch("ez_appsec.external_scanners.subprocess.run", side_effect=write_empty_report),
    ):
        issues, raw_path = scanner.scan_with_raw_output(str(tmp_path))

    try:
        assert issues == []
    finally:
        os.unlink(raw_path)


def test_kics_engine_exit_is_a_failure(tmp_path):
    scanner = KicsScanner()
    completed = subprocess.CompletedProcess([], 126, "", "engine failed")
    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch("ez_appsec.external_scanners.subprocess.run", return_value=completed),
    ):
        with pytest.raises(ScannerExecutionError) as raised:
            scanner.scan(str(tmp_path))

    assert raised.value.scanner == "kics"
    assert raised.value.code == "execution_failed"
    assert "engine failed" not in str(raised.value)


def test_grype_dependency_preparation_failure_is_explicit(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    scanner = GrypeScanner()
    db_ready = subprocess.CompletedProcess([], 0, "", "")
    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch(
            "ez_appsec.external_scanners.subprocess.run",
            side_effect=[db_ready, FileNotFoundError("npm")],
        ),
    ):
        with pytest.raises(ScannerExecutionError) as raised:
            scanner.scan(str(tmp_path))

    assert raised.value.scanner == "grype"
    assert raised.value.code == "not_installed"
    assert "npm" not in str(raised.value)


def test_php_failure_is_not_empty_success(tmp_path):
    scanner = PHPVulnScanner()
    with patch(
        "ez_appsec.php_vuln_scanner_simple.run_php_scanners",
        side_effect=RuntimeError("source fragment must stay private"),
    ):
        with pytest.raises(ScannerExecutionError) as raised:
            scanner.scan(str(tmp_path))

    assert raised.value.scanner == "php-vuln"
    assert raised.value.code == "execution_failed"
    assert "source fragment" not in str(raised.value)


def test_manager_propagates_failure_and_discards_prior_raw_output(tmp_path):
    completed_path = tmp_path / "completed.json"
    completed_path.write_text("{}")
    complete = Mock(enabled=True)
    complete.scan_with_raw_output.return_value = ([], str(completed_path))
    failed = Mock(enabled=True)
    failed.scan_with_raw_output.side_effect = ScannerExecutionError("semgrep", "timeout")

    manager = ExternalScannerManager(enabled_scanners=[])
    manager.scanners = {"gitleaks": complete, "semgrep": failed}

    with pytest.raises(ScannerExecutionError) as raised:
        manager.scan_all_with_raw_outputs(str(tmp_path))

    assert raised.value.scanner == "semgrep"
    assert raised.value.code == "timeout"
    assert not completed_path.exists()


def test_manager_normalizes_unexpected_component_exception():
    failed = Mock(enabled=True)
    failed.scan.side_effect = RuntimeError("unbounded implementation detail")
    manager = ExternalScannerManager(enabled_scanners=[])
    manager.scanners = {"gitleaks": failed}

    with pytest.raises(ScannerExecutionError) as raised:
        manager.scan_all(".")

    assert raised.value.scanner == "gitleaks"
    assert raised.value.code == "execution_failed"
    assert "implementation detail" not in str(raised.value)


def test_quick_check_does_not_suppress_component_failure(tmp_path):
    gitleaks = Mock(enabled=True)
    gitleaks.scan.side_effect = ScannerExecutionError("gitleaks", "timeout")
    scanner = SecurityScanner.__new__(SecurityScanner)
    scanner.use_external = True
    scanner.external = Mock(scanners={"gitleaks": gitleaks})

    with pytest.raises(ScannerExecutionError) as raised:
        scanner.quick_check(str(tmp_path))

    assert raised.value.scanner == "gitleaks"
    assert raised.value.code == "timeout"


@pytest.mark.parametrize(
    ("method_name", "converter"),
    [
        ("scan_to_gitlab_format", "convert_scanner_output"),
        ("scan_to_github_format", "convert_to_github_format"),
    ],
)
def test_output_conversion_failure_discards_all_outputs(tmp_path, method_name, converter):
    first = tmp_path / "gitleaks.json"
    second = tmp_path / "semgrep.json"
    first.write_text("[]")
    second.write_text("{}")
    scanner = SecurityScanner.__new__(SecurityScanner)
    scanner.use_external = True
    scanner.external = Mock()
    scanner.external.scan_all_with_raw_outputs.return_value = (
        [],
        {"gitleaks": str(first), "semgrep": str(second)},
    )

    with patch.object(VulnerabilityConverters, converter, side_effect=ValueError("raw source must stay private")):
        with pytest.raises(ScannerExecutionError) as raised:
            getattr(scanner, method_name)(str(tmp_path))

    assert raised.value.scanner == "gitleaks"
    assert raised.value.code == "invalid_output"
    assert "raw source" not in str(raised.value)
    assert not first.exists()
    assert not second.exists()
