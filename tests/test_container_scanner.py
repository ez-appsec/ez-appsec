"""Unit tests for container image scanning (PLAN-15)"""

import json
import os
import pytest
import tempfile
from unittest.mock import patch, MagicMock

from ez_appsec.external_scanners import GrypeImageScanner


SAMPLE_GRYPE_OUTPUT = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2023-44487",
                "severity": "High",
                "description": "HTTP/2 rapid reset vulnerability",
            },
            "artifact": {
                "name": "libnghttp2",
                "version": "1.52.0-1",
            },
        },
        {
            "vulnerability": {
                "id": "CVE-2024-0567",
                "severity": "Critical",
                "description": "GnuTLS verification bypass",
            },
            "artifact": {
                "name": "libgnutls30",
                "version": "3.7.1-5",
            },
        },
        {
            "vulnerability": {
                "id": "CVE-2023-5678",
                "severity": "Low",
                "description": "OpenSSL low-risk issue",
            },
            "artifact": {
                "name": "openssl",
                "version": "3.0.11-1",
            },
        },
        {
            "vulnerability": {
                "id": "CVE-2024-1111",
                "severity": "Medium",
                "description": "Zlib buffer issue",
            },
            "artifact": {
                "name": "zlib1g",
                "version": "1.2.13-1",
            },
        },
    ],
}


class TestGrypeImageScanner:

    def test_category_is_container_scanning(self):
        scanner = GrypeImageScanner()
        with patch("subprocess.run") as mock_run, \
             patch("builtins.open", create=True) as mock_open:
            mock_run.return_value = MagicMock(returncode=0)
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            mock_open.return_value.read = MagicMock(return_value=json.dumps(SAMPLE_GRYPE_OUTPUT))

            with patch.object(scanner, "is_installed", return_value=True), \
                 patch("json.load", return_value=SAMPLE_GRYPE_OUTPUT), \
                 patch("os.unlink"):
                findings = scanner.scan("nginx:latest")

        assert len(findings) == 4
        for f in findings:
            assert f["category"] == "container_scanning"

    def test_severity_mapping(self):
        scanner = GrypeImageScanner()
        with patch("subprocess.run") as mock_run, \
             patch.object(scanner, "is_installed", return_value=True), \
             patch("json.load", return_value=SAMPLE_GRYPE_OUTPUT), \
             patch("builtins.open", create=True), \
             patch("os.unlink"):
            mock_run.return_value = MagicMock(returncode=0)
            findings = scanner.scan("nginx:latest")

        severities = {f["cve"]: f["severity"] for f in findings}
        assert severities["CVE-2023-44487"] == "high"
        assert severities["CVE-2024-0567"] == "critical"
        assert severities["CVE-2023-5678"] == "low"
        assert severities["CVE-2024-1111"] == "medium"

    def test_registry_auth_passed_to_env(self):
        scanner = GrypeImageScanner()
        captured_envs = []

        def capture_env(*args, **kwargs):
            if "env" in kwargs:
                captured_envs.append(kwargs["env"].copy())
            return MagicMock(returncode=0)

        with patch("subprocess.run", side_effect=capture_env), \
             patch.object(scanner, "is_installed", return_value=True), \
             patch("json.load", return_value={"matches": []}), \
             patch("builtins.open", create=True), \
             patch("os.unlink"):
            scanner.scan("registry.example.com/app:v1", registry_auth="myuser:mytoken")

        assert len(captured_envs) > 0
        last_env = captured_envs[-1]
        assert last_env["GRYPE_REGISTRY_AUTH_USERNAME"] == "myuser"
        assert last_env["GRYPE_REGISTRY_AUTH_PASSWORD"] == "mytoken"

    def test_missing_image_raises_error(self):
        scanner = GrypeImageScanner()
        with patch.object(scanner, "is_installed", return_value=True):
            with pytest.raises(ValueError, match="Image reference is required"):
                scanner.scan("")

    def test_grype_not_installed(self):
        scanner = GrypeImageScanner()
        with patch.object(scanner, "is_installed", return_value=False):
            findings = scanner.scan("nginx:latest")
        assert findings == []

    def test_invalid_registry_auth_format(self):
        scanner = GrypeImageScanner()
        with patch.object(scanner, "is_installed", return_value=True), \
             patch("subprocess.run", return_value=MagicMock(returncode=0)):
            with pytest.raises(ValueError, match="user:token format"):
                scanner.scan("nginx:latest", registry_auth="badformat")

    def test_finding_fields(self):
        scanner = GrypeImageScanner()
        with patch("subprocess.run") as mock_run, \
             patch.object(scanner, "is_installed", return_value=True), \
             patch("json.load", return_value=SAMPLE_GRYPE_OUTPUT), \
             patch("builtins.open", create=True), \
             patch("os.unlink"):
            mock_run.return_value = MagicMock(returncode=0)
            findings = scanner.scan("nginx:latest")

        f = findings[0]
        assert f["type"] == "Dependency"
        assert f["category"] == "container_scanning"
        assert f["scanner"] == "grype"
        assert f["cve"] == "CVE-2023-44487"
        assert "libnghttp2" in f["title"]
        assert f["file"] == "image: nginx:latest"

    def test_unknown_severity_defaults_to_medium(self):
        data = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2099-0001",
                        "severity": "Negligible",
                        "description": "Unknown sev",
                    },
                    "artifact": {"name": "foo", "version": "1.0"},
                },
            ],
        }
        scanner = GrypeImageScanner()
        with patch("subprocess.run", return_value=MagicMock(returncode=0)), \
             patch.object(scanner, "is_installed", return_value=True), \
             patch("json.load", return_value=data), \
             patch("builtins.open", create=True), \
             patch("os.unlink"):
            findings = scanner.scan("test:latest")

        assert findings[0]["severity"] == "medium"

    def test_empty_matches(self):
        scanner = GrypeImageScanner()
        with patch("subprocess.run", return_value=MagicMock(returncode=0)), \
             patch.object(scanner, "is_installed", return_value=True), \
             patch("json.load", return_value={"matches": []}), \
             patch("builtins.open", create=True), \
             patch("os.unlink"):
            findings = scanner.scan("alpine:latest")

        assert findings == []


class TestContainerScanCLI:

    def test_image_flag_triggers_container_scan(self):
        from click.testing import CliRunner
        from ez_appsec.cli import main

        runner = CliRunner()
        with patch("ez_appsec.cli.SecurityScanner") as MockScanner, \
             patch("ez_appsec.external_scanners.GrypeImageScanner") as MockImageScanner:
            mock_scanner_instance = MagicMock()
            mock_scanner_instance.scan.return_value = {
                "issues": [],
                "total": 0,
            }
            MockScanner.return_value = mock_scanner_instance

            mock_image_instance = MagicMock()
            mock_image_instance.scan.return_value = [
                {
                    "type": "Dependency",
                    "category": "container_scanning",
                    "title": "libfoo - CVE-2024-9999",
                    "description": "Test vuln",
                    "file": "image: nginx:1.25",
                    "severity": "high",
                    "scanner": "grype",
                    "cve": "CVE-2024-9999",
                },
            ]
            MockImageScanner.return_value = mock_image_instance

            with tempfile.TemporaryDirectory() as tmpdir:
                result = runner.invoke(main, ["scan", tmpdir, "--image", "nginx:1.25"])

            assert result.exit_code == 0
            mock_image_instance.scan.assert_called_once_with("nginx:1.25", registry_auth=None)
            assert "Container image scan" in result.output

    def test_registry_auth_flag_forwarded(self):
        from click.testing import CliRunner
        from ez_appsec.cli import main

        runner = CliRunner()
        with patch("ez_appsec.cli.SecurityScanner") as MockScanner, \
             patch("ez_appsec.external_scanners.GrypeImageScanner") as MockImageScanner:
            mock_scanner_instance = MagicMock()
            mock_scanner_instance.scan.return_value = {"issues": [], "total": 0}
            MockScanner.return_value = mock_scanner_instance

            mock_image_instance = MagicMock()
            mock_image_instance.scan.return_value = []
            MockImageScanner.return_value = mock_image_instance

            with tempfile.TemporaryDirectory() as tmpdir:
                result = runner.invoke(main, [
                    "scan", tmpdir,
                    "--image", "reg.example.com/app:v2",
                    "--registry-auth", "user:secret",
                ])

            assert result.exit_code == 0
            mock_image_instance.scan.assert_called_once_with(
                "reg.example.com/app:v2", registry_auth="user:secret"
            )
