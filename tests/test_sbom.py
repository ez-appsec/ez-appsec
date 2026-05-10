"""Tests for SBOM generation (PLAN-10)"""

import json
import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from ez_appsec.sbom import generate_cyclonedx, _validate_cyclonedx


VALID_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "metadata": {
        "timestamp": "2026-04-29T00:00:00Z",
        "tools": [{"vendor": "anchore", "name": "grype"}],
    },
    "components": [
        {
            "type": "library",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
        },
        {
            "type": "library",
            "name": "flask",
            "version": "3.0.0",
            "purl": "pkg:pypi/flask@3.0.0",
        },
    ],
}


class TestValidateCyclonedx:
    def test_valid_sbom(self, tmp_path):
        sbom_file = tmp_path / "sbom.cdx.json"
        sbom_file.write_text(json.dumps(VALID_CYCLONEDX))
        _validate_cyclonedx(sbom_file, "1.4")

    def test_spec_version_is_1_4(self, tmp_path):
        sbom_file = tmp_path / "sbom.cdx.json"
        sbom_file.write_text(json.dumps(VALID_CYCLONEDX))
        data = json.loads(sbom_file.read_text())
        assert data["specVersion"] == "1.4"

    def test_component_count_matches(self, tmp_path):
        sbom_file = tmp_path / "sbom.cdx.json"
        sbom_file.write_text(json.dumps(VALID_CYCLONEDX))
        data = json.loads(sbom_file.read_text())
        assert len(data["components"]) == 2

    def test_required_fields_present(self, tmp_path):
        sbom_file = tmp_path / "sbom.cdx.json"
        sbom_file.write_text(json.dumps(VALID_CYCLONEDX))
        data = json.loads(sbom_file.read_text())
        assert data["bomFormat"] == "CycloneDX"
        assert "components" in data
        assert "metadata" in data

    def test_invalid_json_raises(self, tmp_path):
        sbom_file = tmp_path / "sbom.cdx.json"
        sbom_file.write_text("not json")
        with pytest.raises(RuntimeError, match="not valid JSON"):
            _validate_cyclonedx(sbom_file, "1.4")

    def test_wrong_bom_format_raises(self, tmp_path):
        bad = {**VALID_CYCLONEDX, "bomFormat": "SPDX"}
        sbom_file = tmp_path / "sbom.cdx.json"
        sbom_file.write_text(json.dumps(bad))
        with pytest.raises(RuntimeError, match="Expected bomFormat"):
            _validate_cyclonedx(sbom_file, "1.4")

    def test_missing_components_raises(self, tmp_path):
        bad = {k: v for k, v in VALID_CYCLONEDX.items() if k != "components"}
        sbom_file = tmp_path / "sbom.cdx.json"
        sbom_file.write_text(json.dumps(bad))
        with pytest.raises(RuntimeError, match="missing required key.*components"):
            _validate_cyclonedx(sbom_file, "1.4")

    def test_missing_metadata_raises(self, tmp_path):
        bad = {k: v for k, v in VALID_CYCLONEDX.items() if k != "metadata"}
        sbom_file = tmp_path / "sbom.cdx.json"
        sbom_file.write_text(json.dumps(bad))
        with pytest.raises(RuntimeError, match="missing required key.*metadata"):
            _validate_cyclonedx(sbom_file, "1.4")


class TestGenerateCyclonedx:
    @patch("ez_appsec.sbom._grype_installed", return_value=False)
    def test_grype_not_installed_raises(self, mock_installed, tmp_path):
        with pytest.raises(FileNotFoundError, match="grype is not installed"):
            generate_cyclonedx("/some/path", str(tmp_path / "sbom.cdx.json"))

    @patch("ez_appsec.sbom._grype_installed", return_value=True)
    @patch("ez_appsec.sbom.subprocess.run")
    def test_generates_sbom_file(self, mock_run, mock_installed, tmp_path):
        out_path = tmp_path / "sbom.cdx.json"

        def write_sbom(*args, **kwargs):
            out_path.write_text(json.dumps(VALID_CYCLONEDX))
            return MagicMock(returncode=0, stderr="")

        mock_run.side_effect = write_sbom

        result = generate_cyclonedx("/project", str(out_path))
        assert result == str(out_path)
        assert out_path.exists()

        data = json.loads(out_path.read_text())
        assert data["bomFormat"] == "CycloneDX"
        assert data["specVersion"] == "1.4"
        assert len(data["components"]) == 2

    @patch("ez_appsec.sbom._grype_installed", return_value=True)
    @patch("ez_appsec.sbom.subprocess.run")
    def test_grype_called_with_correct_args(self, mock_run, mock_installed, tmp_path):
        out_path = tmp_path / "sbom.cdx.json"

        def write_sbom(*args, **kwargs):
            out_path.write_text(json.dumps(VALID_CYCLONEDX))
            return MagicMock(returncode=0, stderr="")

        mock_run.side_effect = write_sbom
        generate_cyclonedx("/project", str(out_path))

        call_args = mock_run.call_args[0][0]
        assert "grype" in call_args
        assert "cyclonedx-json" in call_args
        assert f"dir:/project" in call_args

    @patch("ez_appsec.sbom._grype_installed", return_value=True)
    @patch("ez_appsec.sbom.subprocess.run")
    def test_no_output_file_raises(self, mock_run, mock_installed, tmp_path):
        mock_run.return_value = MagicMock(returncode=1, stderr="grype failed")
        out_path = tmp_path / "sbom.cdx.json"

        with pytest.raises(RuntimeError, match="did not produce SBOM"):
            generate_cyclonedx("/project", str(out_path))

    @patch("ez_appsec.sbom._grype_installed", return_value=True)
    @patch("ez_appsec.sbom.subprocess.run")
    def test_creates_parent_directories(self, mock_run, mock_installed, tmp_path):
        out_path = tmp_path / "nested" / "dir" / "sbom.cdx.json"

        def write_sbom(*args, **kwargs):
            out_path.write_text(json.dumps(VALID_CYCLONEDX))
            return MagicMock(returncode=0, stderr="")

        mock_run.side_effect = write_sbom
        generate_cyclonedx("/project", str(out_path))
        assert out_path.exists()


class TestCLISbomFlag:
    """Test that --sbom flag is wired into the scan command."""

    @patch("ez_appsec.cli.SecurityScanner")
    def test_scan_without_sbom_flag(self, mock_scanner_cls):
        from click.testing import CliRunner
        from ez_appsec.cli import scan, main

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {"issues": [], "suppressed": 0}
        mock_scanner_cls.return_value = mock_scanner

        runner = CliRunner()
        with runner.isolated_filesystem():
            os.makedirs("src", exist_ok=True)
            Path("src/dummy.py").write_text("x = 1")
            result = runner.invoke(main, ["scan", "src"])

        assert result.exit_code == 0
        assert "SBOM" not in result.output

    @patch("ez_appsec.sbom.generate_cyclonedx")
    @patch("ez_appsec.cli.SecurityScanner")
    def test_scan_with_sbom_flag(self, mock_scanner_cls, mock_gen):
        from click.testing import CliRunner
        from ez_appsec.cli import main

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {"issues": [], "suppressed": 0}
        mock_scanner_cls.return_value = mock_scanner
        mock_gen.return_value = "sbom.cdx.json"

        runner = CliRunner()
        with runner.isolated_filesystem():
            os.makedirs("src", exist_ok=True)
            Path("src/dummy.py").write_text("x = 1")
            result = runner.invoke(main, ["scan", "src", "--sbom"])

        assert result.exit_code == 0
        assert "SBOM generated" in result.output
        mock_gen.assert_called_once()

    @patch("ez_appsec.sbom.generate_cyclonedx", side_effect=RuntimeError("grype broke"))
    @patch("ez_appsec.cli.SecurityScanner")
    def test_sbom_failure_warns_but_does_not_exit(self, mock_scanner_cls, mock_gen):
        from click.testing import CliRunner
        from ez_appsec.cli import main

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {"issues": [], "suppressed": 0}
        mock_scanner_cls.return_value = mock_scanner

        runner = CliRunner()
        with runner.isolated_filesystem():
            os.makedirs("src", exist_ok=True)
            Path("src/dummy.py").write_text("x = 1")
            result = runner.invoke(main, ["scan", "src", "--sbom"])

        assert result.exit_code == 0
        assert "SBOM generation failed" in result.output
