"""Tests for compliance report generation (PLAN-12)"""

import json
import os
import tempfile
import pytest

from ez_appsec.compliance_reporter import (
    ComplianceReporter,
    SUPPORTED_FRAMEWORKS,
    load_framework,
    load_findings_from_file,
    normalize_category,
    _map_findings_to_controls,
    _severity_counts,
)


# --- Test fixtures ---


def _finding(severity="high", category="sast", **overrides):
    base = {
        "rule_id": "test-rule",
        "file": "src/app.py",
        "description": "Test finding",
        "severity": severity,
        "category": category,
        "title": "Test Finding",
    }
    base.update(overrides)
    return base


def _write_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f)


# --- Framework loading ---


class TestLoadFramework:
    def test_load_soc2(self):
        controls = load_framework("soc2")
        assert isinstance(controls, list)
        assert len(controls) > 0
        assert all("control_id" in c for c in controls)
        assert all("title" in c for c in controls)
        assert all("categories" in c for c in controls)

    def test_load_pci_dss(self):
        controls = load_framework("pci-dss")
        assert len(controls) > 0
        ids = [c["control_id"] for c in controls]
        assert "6.3.2" in ids

    def test_load_hipaa(self):
        controls = load_framework("hipaa")
        assert len(controls) > 0
        ids = [c["control_id"] for c in controls]
        assert any("164.312" in cid for cid in ids)

    def test_unknown_framework_raises(self):
        with pytest.raises(ValueError, match="Unsupported framework 'nist'"):
            load_framework("nist")

    def test_all_supported_frameworks_load(self):
        for fw in SUPPORTED_FRAMEWORKS:
            controls = load_framework(fw)
            assert len(controls) > 0, f"{fw} has no controls"


# --- Control mapping ---


class TestMapFindings:
    def test_finding_maps_to_correct_soc2_control(self):
        controls = load_framework("soc2")
        findings = [_finding(category="secrets")]
        enriched, unmapped = _map_findings_to_controls(findings, controls)
        cc61 = next(c for c in enriched if c["control_id"] == "CC6.1")
        assert len(cc61["findings"]) == 1
        assert cc61["findings"][0]["category"] == "secrets"
        assert unmapped == []

    def test_finding_maps_to_multiple_controls(self):
        controls = load_framework("soc2")
        findings = [_finding(category="cve")]
        enriched, unmapped = _map_findings_to_controls(findings, controls)
        matched = [c for c in enriched if c["findings"]]
        assert len(matched) >= 2
        assert unmapped == []

    def test_unmatched_category_maps_nowhere(self):
        controls = load_framework("soc2")
        findings = [_finding(category="made_up_category")]
        enriched, unmapped = _map_findings_to_controls(findings, controls)
        assert all(len(c["findings"]) == 0 for c in enriched)
        assert len(unmapped) == 1

    def test_empty_findings_all_controls_clean(self):
        controls = load_framework("soc2")
        enriched, unmapped = _map_findings_to_controls([], controls)
        assert all(len(c["findings"]) == 0 for c in enriched)
        assert unmapped == []

    def test_pci_dss_license_compliance_maps_to_632(self):
        controls = load_framework("pci-dss")
        findings = [_finding(category="license_compliance")]
        enriched, unmapped = _map_findings_to_controls(findings, controls)
        c632 = next(c for c in enriched if c["control_id"] == "6.3.2")
        assert len(c632["findings"]) == 1
        assert unmapped == []


# --- Severity counts ---


class TestSeverityCounts:
    def test_counts_all_severities(self):
        findings = [
            _finding(severity="critical"),
            _finding(severity="high"),
            _finding(severity="high"),
            _finding(severity="medium"),
            _finding(severity="low"),
            _finding(severity="low"),
            _finding(severity="low"),
        ]
        counts = _severity_counts(findings)
        assert counts == {"critical": 1, "high": 2, "medium": 1, "low": 3}

    def test_empty_findings(self):
        counts = _severity_counts([])
        assert counts == {"critical": 0, "high": 0, "medium": 0, "low": 0}

    def test_unknown_severity_ignored(self):
        counts = _severity_counts([_finding(severity="info")])
        assert counts == {"critical": 0, "high": 0, "medium": 0, "low": 0}


# --- HTML report generation ---


class TestComplianceReporter:
    def test_generate_soc2_report(self, tmp_path):
        findings = [
            _finding(severity="critical", category="secrets"),
            _finding(severity="high", category="cve", title="CVE-2024-1234"),
        ]
        reporter = ComplianceReporter("soc2")
        out = str(tmp_path / "report.html")
        result = reporter.generate(findings, out)
        assert os.path.exists(result["path"])
        html = open(result["path"]).read()
        assert "Executive Summary" in html
        assert "Findings by Control" in html
        assert "SOC 2 Type II" in html
        assert result["total"] == 2
        assert result["mapped"] == 2
        assert result["unmapped"] == 0

    def test_generate_pci_dss_report(self, tmp_path):
        reporter = ComplianceReporter("pci-dss")
        out = str(tmp_path / "pci.html")
        reporter.generate([_finding(category="sast")], out)
        html = open(out).read()
        assert "PCI DSS 4.0" in html

    def test_generate_hipaa_report(self, tmp_path):
        reporter = ComplianceReporter("hipaa")
        out = str(tmp_path / "hipaa.html")
        reporter.generate([_finding(category="secrets")], out)
        html = open(out).read()
        assert "HIPAA" in html

    def test_html_contains_finding_title(self, tmp_path):
        findings = [_finding(title="Hardcoded AWS Key", category="secrets")]
        reporter = ComplianceReporter("soc2")
        out = str(tmp_path / "report.html")
        reporter.generate(findings, out)
        html = open(out).read()
        assert "Hardcoded AWS Key" in html

    def test_html_contains_severity_badge(self, tmp_path):
        findings = [_finding(severity="critical", category="secrets")]
        reporter = ComplianceReporter("soc2")
        out = str(tmp_path / "report.html")
        reporter.generate(findings, out)
        html = open(out).read()
        assert "badge-critical" in html

    def test_html_self_contained(self, tmp_path):
        reporter = ComplianceReporter("soc2")
        out = str(tmp_path / "report.html")
        reporter.generate([_finding(category="sast")], out)
        html = open(out).read()
        assert "<style>" in html
        assert "cdn" not in html.lower()
        assert "http://" not in html or "localhost" not in html

    def test_empty_findings_report(self, tmp_path):
        reporter = ComplianceReporter("soc2")
        out = str(tmp_path / "empty.html")
        reporter.generate([], out)
        html = open(out).read()
        assert "Executive Summary" in html
        assert "No findings mapped to this control" in html

    def test_controls_clean_count(self, tmp_path):
        reporter = ComplianceReporter("soc2")
        out = str(tmp_path / "report.html")
        reporter.generate([], out)
        html = open(out).read()
        total = len(reporter.controls)
        assert f">{total}<" in html

    def test_unknown_framework_raises(self):
        with pytest.raises(ValueError):
            ComplianceReporter("gdpr")

    def test_creates_parent_dirs(self, tmp_path):
        reporter = ComplianceReporter("soc2")
        out = str(tmp_path / "nested" / "deep" / "report.html")
        result = reporter.generate([], out)
        assert os.path.exists(result["path"])

    def test_mixed_categories(self, tmp_path):
        findings = [
            _finding(category="secrets"),
            _finding(category="cve"),
            _finding(category="sast"),
            _finding(category="iac"),
            _finding(category="dependency_scanning"),
        ]
        reporter = ComplianceReporter("soc2")
        out = str(tmp_path / "mixed.html")
        reporter.generate(findings, out)
        html = open(out).read()
        assert "Findings by Control" in html


# --- Category normalization ---


class TestNormalizeCategory:
    def test_secret_detection_to_secrets(self):
        assert normalize_category({"category": "secret_detection"}) == "secrets"

    def test_secrets_passes_through(self):
        assert normalize_category({"category": "secrets"}) == "secrets"

    def test_type_field_fallback(self):
        assert normalize_category({"type": "Secrets"}) == "secrets"

    def test_type_sast_fallback(self):
        assert normalize_category({"type": "SAST"}) == "sast"

    def test_type_dependency_fallback(self):
        assert normalize_category({"type": "Dependency"}) == "dependency_scanning"

    def test_type_iac_fallback(self):
        assert normalize_category({"type": "Infrastructure as Code"}) == "iac"

    def test_category_takes_precedence_over_type(self):
        assert normalize_category({"category": "sast", "type": "Secrets"}) == "sast"

    def test_container_scanning_alias(self):
        assert normalize_category({"category": "container_scanning"}) == "dependency_scanning"

    def test_unknown_category_lowercased(self):
        assert normalize_category({"category": "custom_scanner"}) == "custom_scanner"
        assert normalize_category({"category": "CustomScanner"}) == "customscanner"

    def test_empty_both_fields(self):
        assert normalize_category({}) == ""

    def test_case_insensitive(self):
        assert normalize_category({"category": "SECRET_DETECTION"}) == "secrets"
        assert normalize_category({"category": "SAST"}) == "sast"


class TestNormalizationInMapping:
    def test_secret_detection_maps_to_soc2_controls(self):
        controls = load_framework("soc2")
        findings = [_finding(category="secret_detection")]
        enriched, unmapped = _map_findings_to_controls(findings, controls)
        cc61 = next(c for c in enriched if c["control_id"] == "CC6.1")
        assert len(cc61["findings"]) == 1
        assert unmapped == []

    def test_internal_type_field_maps_to_controls(self):
        controls = load_framework("soc2")
        findings = [{"type": "Secrets", "title": "Leaked key", "severity": "critical", "file": "x.py"}]
        enriched, unmapped = _map_findings_to_controls(findings, controls)
        cc61 = next(c for c in enriched if c["control_id"] == "CC6.1")
        assert len(cc61["findings"]) == 1
        assert unmapped == []


# --- Unmapped findings ---


class TestUnmappedFindings:
    def test_unmapped_findings_in_html(self, tmp_path):
        findings = [
            _finding(category="sast"),
            _finding(category="totally_unknown_scanner", title="Unknown Finding"),
        ]
        reporter = ComplianceReporter("soc2")
        out = str(tmp_path / "report.html")
        result = reporter.generate(findings, out)
        html = open(out).read()
        assert "Unmapped Findings" in html
        assert "Unknown Finding" in html
        assert result["unmapped"] == 1
        assert result["mapped"] == 1

    def test_no_unmapped_section_when_all_mapped(self, tmp_path):
        findings = [_finding(category="sast")]
        reporter = ComplianceReporter("soc2")
        out = str(tmp_path / "report.html")
        reporter.generate(findings, out)
        html = open(out).read()
        assert "Unmapped Findings" not in html

    def test_empty_input_warning_banner(self, tmp_path):
        reporter = ComplianceReporter("soc2")
        out = str(tmp_path / "report.html")
        reporter.generate([], out)
        html = open(out).read()
        assert "No findings provided" in html

    def test_unmapped_warning_banner(self, tmp_path):
        findings = [
            _finding(category="sast"),
            _finding(category="made_up"),
        ]
        reporter = ComplianceReporter("soc2")
        out = str(tmp_path / "report.html")
        reporter.generate(findings, out)
        html = open(out).read()
        assert "not mapped to any control" in html

    def test_print_stylesheet_present(self, tmp_path):
        reporter = ComplianceReporter("soc2")
        out = str(tmp_path / "report.html")
        reporter.generate([], out)
        html = open(out).read()
        assert "@media print" in html

    def test_word_break_in_css(self, tmp_path):
        reporter = ComplianceReporter("soc2")
        out = str(tmp_path / "report.html")
        reporter.generate([], out)
        html = open(out).read()
        assert "break-word" in html


# --- Findings file loading ---


class TestLoadFindingsFromFile:
    def test_load_internal_format(self, tmp_path):
        path = str(tmp_path / "findings.json")
        _write_json(path, {
            "issues": [
                {"title": "Bug", "severity": "high", "category": "sast"},
            ]
        })
        findings = load_findings_from_file(path)
        assert len(findings) == 1
        assert findings[0]["title"] == "Bug"

    def test_load_gitlab_format(self, tmp_path):
        path = str(tmp_path / "vulns.json")
        _write_json(path, {
            "vulnerabilities": [
                {
                    "name": "CVE-2024-1234",
                    "severity": "High",
                    "category": "dependency_scanning",
                    "description": "Remote code execution",
                    "location": {"file": "package.json"},
                },
            ]
        })
        findings = load_findings_from_file(path)
        assert len(findings) == 1
        assert findings[0]["title"] == "CVE-2024-1234"
        assert findings[0]["severity"] == "high"

    def test_load_raw_list(self, tmp_path):
        path = str(tmp_path / "raw.json")
        _write_json(path, [{"title": "A", "severity": "low", "category": "sast"}])
        findings = load_findings_from_file(path)
        assert len(findings) == 1

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError, match="Findings file not found"):
            load_findings_from_file("/tmp/does_not_exist_12345.json")

    def test_empty_issues_list(self, tmp_path):
        path = str(tmp_path / "empty.json")
        _write_json(path, {"issues": []})
        assert load_findings_from_file(path) == []

    def test_internal_format_backfills_category_from_type(self, tmp_path):
        path = str(tmp_path / "internal.json")
        _write_json(path, {
            "issues": [
                {"title": "Leak", "severity": "critical", "type": "Secrets", "file": "x.py"},
            ]
        })
        findings = load_findings_from_file(path)
        assert findings[0]["category"] == "Secrets"

    def test_internal_format_preserves_existing_category(self, tmp_path):
        path = str(tmp_path / "internal.json")
        _write_json(path, {
            "issues": [
                {"title": "Bug", "severity": "high", "category": "sast", "type": "semgrep", "file": "x.py"},
            ]
        })
        findings = load_findings_from_file(path)
        assert findings[0]["category"] == "sast"


# --- CLI integration (smoke) ---


class TestCLIReportCommand:
    def test_report_command_exists(self):
        from ez_appsec.cli import main
        commands = main.commands
        assert "report" in commands

    def test_report_generates_file(self, tmp_path):
        from click.testing import CliRunner
        from ez_appsec.cli import main

        findings_path = str(tmp_path / "findings.json")
        _write_json(findings_path, {
            "issues": [
                {"title": "XSS", "severity": "high", "category": "sast", "file": "x.js"},
            ]
        })
        out_path = str(tmp_path / "out.html")
        runner = CliRunner()
        result = runner.invoke(main, ["report", "--framework", "soc2", "--findings", findings_path, "--output", out_path])
        assert result.exit_code == 0, result.output
        assert os.path.exists(out_path)
        assert "compliance report generated" in result.output

    def test_report_invalid_framework(self, tmp_path):
        from click.testing import CliRunner
        from ez_appsec.cli import main

        findings_path = str(tmp_path / "f.json")
        _write_json(findings_path, {"issues": []})
        runner = CliRunner()
        result = runner.invoke(main, ["report", "--framework", "nist", "--findings", findings_path])
        assert result.exit_code != 0

    def test_report_missing_findings_file(self):
        from click.testing import CliRunner
        from ez_appsec.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["report", "--framework", "soc2", "--findings", "/tmp/no_such_file.json"])
        assert result.exit_code != 0

    def test_report_default_output_name(self, tmp_path, monkeypatch):
        from click.testing import CliRunner
        from ez_appsec.cli import main

        findings_path = str(tmp_path / "findings.json")
        _write_json(findings_path, {"issues": []})
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["report", "--framework", "pci-dss", "--findings", findings_path])
        assert result.exit_code == 0, result.output
        assert os.path.exists(tmp_path / "pci-dss-report.html")

    def test_report_shows_unmapped_count(self, tmp_path):
        from click.testing import CliRunner
        from ez_appsec.cli import main

        findings_path = str(tmp_path / "findings.json")
        _write_json(findings_path, {
            "issues": [
                {"title": "A", "severity": "high", "category": "sast", "file": "a.py"},
                {"title": "B", "severity": "low", "category": "alien_scanner", "file": "b.py"},
            ]
        })
        out_path = str(tmp_path / "out.html")
        runner = CliRunner()
        result = runner.invoke(main, ["report", "--framework", "soc2", "--findings", findings_path, "--output", out_path])
        assert result.exit_code == 0, result.output
        assert "1 mapped to controls" in result.output
        assert "1 unmapped" in result.output

    def test_report_all_mapped_shows_simple_count(self, tmp_path):
        from click.testing import CliRunner
        from ez_appsec.cli import main

        findings_path = str(tmp_path / "findings.json")
        _write_json(findings_path, {
            "issues": [
                {"title": "A", "severity": "high", "category": "sast", "file": "a.py"},
            ]
        })
        out_path = str(tmp_path / "out.html")
        runner = CliRunner()
        result = runner.invoke(main, ["report", "--framework", "soc2", "--findings", findings_path, "--output", out_path])
        assert result.exit_code == 0, result.output
        assert "Findings mapped: 1" in result.output
        assert "unmapped" not in result.output

    def test_report_normalizes_secret_detection(self, tmp_path):
        from click.testing import CliRunner
        from ez_appsec.cli import main

        findings_path = str(tmp_path / "findings.json")
        _write_json(findings_path, {
            "vulnerabilities": [
                {
                    "name": "Leaked API Key",
                    "severity": "Critical",
                    "category": "secret_detection",
                    "description": "API key exposed",
                    "location": {"file": "config.yml"},
                },
            ]
        })
        out_path = str(tmp_path / "out.html")
        runner = CliRunner()
        result = runner.invoke(main, ["report", "--framework", "soc2", "--findings", findings_path, "--output", out_path])
        assert result.exit_code == 0, result.output
        html = open(out_path).read()
        assert "Leaked API Key" in html
        assert "Unmapped Findings" not in html

    def test_report_internal_format_type_field(self, tmp_path):
        from click.testing import CliRunner
        from ez_appsec.cli import main

        findings_path = str(tmp_path / "findings.json")
        _write_json(findings_path, {
            "issues": [
                {"title": "Secret leak", "severity": "critical", "type": "Secrets", "file": "x.py"},
            ]
        })
        out_path = str(tmp_path / "out.html")
        runner = CliRunner()
        result = runner.invoke(main, ["report", "--framework", "soc2", "--findings", findings_path, "--output", out_path])
        assert result.exit_code == 0, result.output
        html = open(out_path).read()
        assert "Secret leak" in html
        assert "Unmapped Findings" not in html
