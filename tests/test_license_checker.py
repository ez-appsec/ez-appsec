"""Tests for the license compliance checker (PLAN-11)"""

import os
import subprocess
import tempfile
import json
import pytest

from ez_appsec.license_checker import (
    LicensePolicy,
    PackageLicense,
    extract_licenses_from_syft,
    check_licenses,
    _matches_pattern,
    _matches_any,
    _normalize_license,
)
from ez_appsec.config import Config, LicensePolicyConfig


# --- Helpers ---


def _syft_artifact(name, version, licenses, pkg_type="npm"):
    """Build a syft artifact dict."""
    return {
        "name": name,
        "version": version,
        "type": pkg_type,
        "licenses": licenses,
    }


def _syft_output(artifacts):
    """Build a minimal syft JSON structure."""
    return {"artifacts": artifacts}


def _syft_output_v1(packages):
    """Build a syft >= 1.0 JSON structure using 'packages' key."""
    return {"packages": packages}


# --- LicensePolicy ---


class TestLicensePolicy:
    def test_empty_policy_allows_all(self):
        policy = LicensePolicy()
        assert policy.check("MIT") == "allowed"
        assert policy.check("GPL-3.0") == "allowed"

    def test_denied_license_exact(self):
        policy = LicensePolicy(denied_licenses=["GPL-3.0"])
        assert policy.check("GPL-3.0") == "denied"

    def test_denied_license_wildcard(self):
        policy = LicensePolicy(denied_licenses=["GPL*"])
        assert policy.check("GPL-2.0") == "denied"
        assert policy.check("GPL-3.0") == "denied"
        assert policy.check("GPL-3.0-only") == "denied"

    def test_agpl_wildcard(self):
        policy = LicensePolicy(denied_licenses=["AGPL*"])
        assert policy.check("AGPL-3.0") == "denied"
        assert policy.check("AGPL-3.0-only") == "denied"
        assert policy.check("MIT") != "denied"

    def test_allowed_license_exact(self):
        policy = LicensePolicy(allowed_licenses=["MIT", "Apache-2.0"])
        assert policy.check("MIT") == "allowed"
        assert policy.check("Apache-2.0") == "allowed"

    def test_not_in_allowed_is_unknown(self):
        policy = LicensePolicy(allowed_licenses=["MIT"])
        assert policy.check("BSD-3-Clause") == "unknown"

    def test_denied_takes_priority_over_allowed(self):
        policy = LicensePolicy(
            allowed_licenses=["GPL-3.0"],
            denied_licenses=["GPL*"],
        )
        assert policy.check("GPL-3.0") == "denied"

    def test_unknown_license_string(self):
        policy = LicensePolicy(allowed_licenses=["MIT"])
        assert policy.check("UNKNOWN") == "unknown"
        assert policy.check("unknown") == "unknown"
        assert policy.check("") == "unknown"
        assert policy.check("none") == "unknown"

    def test_case_insensitive_matching(self):
        policy = LicensePolicy(denied_licenses=["gpl*"])
        assert policy.check("GPL-3.0") == "denied"

    def test_no_allowed_no_denied_allows_all(self):
        policy = LicensePolicy(allowed_licenses=[], denied_licenses=[])
        assert policy.check("MIT") == "allowed"
        assert policy.check("GPL-3.0") == "allowed"

    def test_only_denied_allows_rest(self):
        policy = LicensePolicy(denied_licenses=["GPL*"])
        assert policy.check("MIT") == "allowed"
        assert policy.check("Apache-2.0") == "allowed"

    def test_bsd_wildcard(self):
        policy = LicensePolicy(allowed_licenses=["BSD*"])
        assert policy.check("BSD-2-Clause") == "allowed"
        assert policy.check("BSD-3-Clause") == "allowed"


# --- Pattern matching ---


class TestPatternMatching:
    def test_exact_match(self):
        assert _matches_pattern("MIT", "MIT") is True

    def test_wildcard_match(self):
        assert _matches_pattern("GPL-3.0", "GPL*") is True

    def test_no_match(self):
        assert _matches_pattern("MIT", "GPL*") is False

    def test_case_insensitive(self):
        assert _matches_pattern("mit", "MIT") is True
        assert _matches_pattern("MIT", "mit") is True

    def test_matches_any(self):
        assert _matches_any("MIT", ["MIT", "Apache-2.0"]) is True
        assert _matches_any("BSD-3-Clause", ["MIT", "Apache-2.0"]) is False

    def test_normalize_strips_whitespace(self):
        assert _normalize_license("  MIT  ") == "MIT"


# --- extract_licenses_from_syft ---


class TestExtractLicensesFromSyft:
    def test_string_licenses(self):
        data = _syft_output([
            _syft_artifact("express", "4.18.2", ["MIT"]),
        ])
        packages = extract_licenses_from_syft(data)
        assert len(packages) == 1
        assert packages[0].name == "express"
        assert packages[0].licenses == ["MIT"]

    def test_dict_licenses_spdx(self):
        data = _syft_output([
            _syft_artifact("lodash", "4.17.21", [
                {"spdxExpression": "MIT", "type": "declared"},
            ]),
        ])
        packages = extract_licenses_from_syft(data)
        assert packages[0].licenses == ["MIT"]

    def test_dict_licenses_value_fallback(self):
        data = _syft_output([
            _syft_artifact("some-pkg", "1.0.0", [
                {"value": "Apache-2.0"},
            ]),
        ])
        packages = extract_licenses_from_syft(data)
        assert packages[0].licenses == ["Apache-2.0"]

    def test_dict_licenses_name_fallback(self):
        data = _syft_output([
            _syft_artifact("some-pkg", "1.0.0", [
                {"name": "ISC"},
            ]),
        ])
        packages = extract_licenses_from_syft(data)
        assert packages[0].licenses == ["ISC"]

    def test_no_licenses_defaults_unknown(self):
        data = _syft_output([
            _syft_artifact("mystery", "0.1.0", []),
        ])
        packages = extract_licenses_from_syft(data)
        assert packages[0].licenses == ["UNKNOWN"]

    def test_null_licenses_defaults_unknown(self):
        data = _syft_output([
            {"name": "mystery", "version": "0.1.0", "licenses": None, "type": "npm"},
        ])
        packages = extract_licenses_from_syft(data)
        assert packages[0].licenses == ["UNKNOWN"]

    def test_multiple_licenses_per_package(self):
        data = _syft_output([
            _syft_artifact("dual-licensed", "2.0.0", ["MIT", "Apache-2.0"]),
        ])
        packages = extract_licenses_from_syft(data)
        assert set(packages[0].licenses) == {"MIT", "Apache-2.0"}

    def test_packages_key_syft_v1(self):
        data = _syft_output_v1([
            _syft_artifact("express", "4.18.2", ["MIT"]),
        ])
        packages = extract_licenses_from_syft(data)
        assert len(packages) == 1
        assert packages[0].name == "express"

    def test_empty_artifacts(self):
        data = _syft_output([])
        packages = extract_licenses_from_syft(data)
        assert packages == []

    def test_missing_both_keys(self):
        packages = extract_licenses_from_syft({})
        assert packages == []

    def test_package_type_preserved(self):
        data = _syft_output([
            _syft_artifact("flask", "2.3.0", ["BSD-3-Clause"], pkg_type="python"),
        ])
        packages = extract_licenses_from_syft(data)
        assert packages[0].pkg_type == "python"


# --- PackageLicense ---


class TestPackageLicense:
    def test_to_dict(self):
        pkg = PackageLicense("express", "4.18.2", ["MIT"], "npm")
        d = pkg.to_dict()
        assert d == {
            "name": "express",
            "version": "4.18.2",
            "licenses": ["MIT"],
            "type": "npm",
        }


# --- check_licenses ---


class TestCheckLicenses:
    def test_denied_license_produces_high_finding(self):
        policy = LicensePolicy(denied_licenses=["GPL*"])
        syft_data = _syft_output([
            _syft_artifact("evil-lib", "1.0.0", ["GPL-3.0"]),
        ])
        result = check_licenses(".", policy, syft_json=syft_data)
        assert len(result["findings"]) == 1
        f = result["findings"][0]
        assert f["severity"] == "high"
        assert f["category"] == "license_compliance"
        assert f["scanner"] == "license-checker"
        assert "GPL-3.0" in f["title"]
        assert "evil-lib" in f["title"]
        assert result["summary"]["denied"] == 1

    def test_allowed_license_no_finding(self):
        policy = LicensePolicy(allowed_licenses=["MIT", "Apache-2.0"])
        syft_data = _syft_output([
            _syft_artifact("good-lib", "1.0.0", ["MIT"]),
        ])
        result = check_licenses(".", policy, syft_json=syft_data)
        assert len(result["findings"]) == 0
        assert result["summary"]["allowed"] == 1
        assert result["summary"]["denied"] == 0

    def test_unknown_license_produces_medium_finding(self):
        policy = LicensePolicy(allowed_licenses=["MIT"])
        syft_data = _syft_output([
            _syft_artifact("weird-lib", "1.0.0", ["Artistic-2.0"]),
        ])
        result = check_licenses(".", policy, syft_json=syft_data)
        assert len(result["findings"]) == 1
        f = result["findings"][0]
        assert f["severity"] == "medium"
        assert "unknown" in f["title"].lower() or "Unknown" in f["title"]
        assert result["summary"]["unknown"] == 1

    def test_mixed_licenses(self):
        policy = LicensePolicy(
            allowed_licenses=["MIT", "Apache-2.0"],
            denied_licenses=["GPL*"],
        )
        syft_data = _syft_output([
            _syft_artifact("good", "1.0.0", ["MIT"]),
            _syft_artifact("bad", "2.0.0", ["GPL-3.0"]),
            _syft_artifact("meh", "3.0.0", ["Artistic-2.0"]),
        ])
        result = check_licenses(".", policy, syft_json=syft_data)
        assert result["summary"]["allowed"] == 1
        assert result["summary"]["denied"] == 1
        assert result["summary"]["unknown"] == 1
        assert len(result["findings"]) == 2

    def test_no_syft_data_returns_empty(self):
        policy = LicensePolicy(denied_licenses=["GPL*"])
        result = check_licenses(".", policy, syft_json=None)
        assert result["findings"] == []
        assert result["packages"] == []
        assert result["summary"]["total"] == 0

    def test_empty_packages(self):
        policy = LicensePolicy(denied_licenses=["GPL*"])
        syft_data = _syft_output([])
        result = check_licenses(".", policy, syft_json=syft_data)
        assert result["findings"] == []
        assert result["summary"]["total"] == 0

    def test_packages_returned(self):
        policy = LicensePolicy()
        syft_data = _syft_output([
            _syft_artifact("express", "4.18.2", ["MIT"]),
            _syft_artifact("lodash", "4.17.21", ["MIT"]),
        ])
        result = check_licenses(".", policy, syft_json=syft_data)
        assert len(result["packages"]) == 2
        assert result["packages"][0]["name"] == "express"

    def test_finding_fields_complete(self):
        policy = LicensePolicy(denied_licenses=["GPL*"])
        syft_data = _syft_output([
            _syft_artifact("gpl-thing", "1.2.3", ["GPL-2.0"]),
        ])
        result = check_licenses(".", policy, syft_json=syft_data)
        f = result["findings"][0]
        assert f["type"] == "license_compliance"
        assert f["category"] == "license_compliance"
        assert f["scanner"] == "license-checker"
        assert f["license"] == "GPL-2.0"
        assert f["package"] == "gpl-thing"
        assert f["package_version"] == "1.2.3"
        assert f["rule_id"] == "license-denied-GPL-2.0"
        assert f["file"] == "dependency: gpl-thing"

    def test_dual_licensed_package_one_denied(self):
        policy = LicensePolicy(
            allowed_licenses=["MIT"],
            denied_licenses=["GPL*"],
        )
        syft_data = _syft_output([
            _syft_artifact("dual", "1.0.0", ["MIT", "GPL-3.0"]),
        ])
        result = check_licenses(".", policy, syft_json=syft_data)
        assert result["summary"]["allowed"] == 1
        assert result["summary"]["denied"] == 1
        assert len(result["findings"]) == 1
        assert result["findings"][0]["license"] == "GPL-3.0"

    def test_wildcard_sspl(self):
        policy = LicensePolicy(denied_licenses=["SSPL*"])
        syft_data = _syft_output([
            _syft_artifact("mongo-lib", "1.0.0", ["SSPL-1.0"]),
        ])
        result = check_licenses(".", policy, syft_json=syft_data)
        assert result["summary"]["denied"] == 1

    def test_unknown_spdx_tag(self):
        policy = LicensePolicy(allowed_licenses=["MIT"])
        syft_data = _syft_output([
            _syft_artifact("no-license", "0.1.0", []),
        ])
        result = check_licenses(".", policy, syft_json=syft_data)
        assert result["summary"]["unknown"] == 1
        assert result["findings"][0]["license"] == "UNKNOWN"


# --- Config integration ---


class TestLicensePolicyConfig:
    def _write_config(self, content):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        f.write(content)
        f.close()
        return f.name

    def test_load_license_policy_from_yaml(self):
        path = self._write_config("""
severity: all
license_policy:
  allowed_licenses:
    - MIT
    - Apache-2.0
  denied_licenses:
    - GPL*
    - AGPL*
""")
        try:
            config = Config.from_file(path)
            assert config.license_policy is not None
            assert config.license_policy.allowed_licenses == ["MIT", "Apache-2.0"]
            assert config.license_policy.denied_licenses == ["GPL*", "AGPL*"]
        finally:
            os.unlink(path)

    def test_no_license_policy_section(self):
        path = self._write_config("severity: all\n")
        try:
            config = Config.from_file(path)
            assert config.license_policy is None
        finally:
            os.unlink(path)

    def test_license_policy_coexists_with_other_sections(self):
        path = self._write_config("""
severity: high
ignore:
  - rule_id: test.rule
    permanent: true
    reason: "test"
policy:
  - severity: critical
    action: fail
license_policy:
  denied_licenses:
    - GPL*
""")
        try:
            config = Config.from_file(path)
            assert len(config.ignore_rules) == 1
            assert len(config.policy_rules) == 1
            assert config.license_policy is not None
            assert config.license_policy.denied_licenses == ["GPL*"]
        finally:
            os.unlink(path)

    def test_to_policy_conversion(self):
        lpc = LicensePolicyConfig(
            allowed_licenses=["MIT"],
            denied_licenses=["GPL*"],
        )
        policy = lpc.to_policy()
        assert policy.check("MIT") == "allowed"
        assert policy.check("GPL-3.0") == "denied"

    def test_only_allowed_licenses(self):
        path = self._write_config("""
license_policy:
  allowed_licenses:
    - MIT
    - BSD-3-Clause
""")
        try:
            config = Config.from_file(path)
            assert config.license_policy.allowed_licenses == ["MIT", "BSD-3-Clause"]
            assert config.license_policy.denied_licenses == []
        finally:
            os.unlink(path)

    def test_only_denied_licenses(self):
        path = self._write_config("""
license_policy:
  denied_licenses:
    - GPL*
""")
        try:
            config = Config.from_file(path)
            assert config.license_policy.allowed_licenses == []
            assert config.license_policy.denied_licenses == ["GPL*"]
        finally:
            os.unlink(path)


# --- Scanner integration ---


class TestLicenseInScanOutput:
    def test_license_findings_in_scan_results(self):
        from unittest.mock import patch, MagicMock
        from ez_appsec.scanner import SecurityScanner

        config = Config(
            license_policy=LicensePolicyConfig(denied_licenses=["GPL*"]),
        )
        scanner = SecurityScanner(config, use_external_scanners=False, license_check=True)

        syft_data = _syft_output([
            _syft_artifact("bad-dep", "1.0.0", ["GPL-3.0"]),
            _syft_artifact("good-dep", "2.0.0", ["MIT"]),
        ])

        with patch.object(scanner.ai, "analyze", return_value={"enhanced_issues": []}):
            with patch("ez_appsec.scanner.check_licenses") as mock_check:
                mock_check.return_value = {
                    "findings": [
                        {
                            "type": "license_compliance",
                            "category": "license_compliance",
                            "title": "Denied license: GPL-3.0 in bad-dep@1.0.0",
                            "description": "denied",
                            "file": "dependency: bad-dep",
                            "line": 1,
                            "severity": "high",
                            "scanner": "license-checker",
                            "rule_id": "license-denied-GPL-3.0",
                            "license": "GPL-3.0",
                            "package": "bad-dep",
                            "package_version": "1.0.0",
                        }
                    ],
                    "packages": [
                        {"name": "bad-dep", "version": "1.0.0", "licenses": ["GPL-3.0"], "type": "npm"},
                        {"name": "good-dep", "version": "2.0.0", "licenses": ["MIT"], "type": "npm"},
                    ],
                    "summary": {"total": 2, "allowed": 1, "denied": 1, "unknown": 0},
                }
                results = scanner.scan(".")

        assert "license_summary" in results
        assert results["license_summary"]["denied"] == 1
        assert len(results["license_packages"]) == 2
        license_findings = [i for i in results["issues"] if i.get("category") == "license_compliance"]
        assert len(license_findings) == 1

    def test_no_license_check_no_key(self):
        from unittest.mock import patch
        from ez_appsec.scanner import SecurityScanner

        config = Config()
        scanner = SecurityScanner(config, use_external_scanners=False)

        with patch.object(scanner.ai, "analyze", return_value={"enhanced_issues": []}):
            results = scanner.scan(".")

        assert "license_summary" not in results

    def test_license_check_disabled_no_key(self):
        from unittest.mock import patch
        from ez_appsec.scanner import SecurityScanner

        config = Config(
            license_policy=LicensePolicyConfig(denied_licenses=["GPL*"]),
        )
        scanner = SecurityScanner(config, use_external_scanners=False, license_check=False)

        with patch.object(scanner.ai, "analyze", return_value={"enhanced_issues": []}):
            results = scanner.scan(".")

        assert "license_summary" not in results

    def test_license_findings_respect_ignore_rules(self):
        """License findings should be suppressible via ignore rules."""
        from unittest.mock import patch
        from ez_appsec.scanner import SecurityScanner
        from ez_appsec.config import IgnoreRule

        config = Config(
            license_policy=LicensePolicyConfig(denied_licenses=["GPL*"]),
            ignore_rules=[
                IgnoreRule(
                    rule_id="license-denied-GPL-3.0",
                    permanent=True,
                    reason="Accepted risk for this dependency",
                ),
            ],
        )
        scanner = SecurityScanner(config, use_external_scanners=False, license_check=True)

        with patch.object(scanner.ai, "analyze", return_value={"enhanced_issues": []}):
            with patch("ez_appsec.scanner.check_licenses") as mock_check:
                mock_check.return_value = {
                    "findings": [
                        {
                            "type": "license_compliance",
                            "category": "license_compliance",
                            "title": "Denied license: GPL-3.0 in bad-dep@1.0.0",
                            "description": "denied",
                            "file": "dependency: bad-dep",
                            "line": 1,
                            "severity": "high",
                            "scanner": "license-checker",
                            "rule_id": "license-denied-GPL-3.0",
                            "license": "GPL-3.0",
                            "package": "bad-dep",
                            "package_version": "1.0.0",
                        }
                    ],
                    "packages": [
                        {"name": "bad-dep", "version": "1.0.0", "licenses": ["GPL-3.0"], "type": "npm"},
                    ],
                    "summary": {"total": 1, "allowed": 0, "denied": 1, "unknown": 0},
                }
                results = scanner.scan(".")

        license_findings = [i for i in results["issues"] if i.get("category") == "license_compliance"]
        assert len(license_findings) == 0
        assert results["suppressed"] == 1


# --- Edge cases ---


class TestPolicyEdgeCases:
    def test_whitespace_only_license(self):
        policy = LicensePolicy(allowed_licenses=["MIT"])
        assert policy.check("   ") == "unknown"

    def test_none_input(self):
        policy = LicensePolicy(allowed_licenses=["MIT"])
        assert policy.check(None) == "unknown"

    def test_very_long_license_id(self):
        policy = LicensePolicy(allowed_licenses=["MIT"], denied_licenses=["GPL*"])
        long_id = "MIT-" + "x" * 1000
        assert policy.check(long_id) == "unknown"

    def test_special_characters_in_license(self):
        policy = LicensePolicy(allowed_licenses=["MIT"])
        assert policy.check("MIT (modified)") == "unknown"

    def test_summary_counts_are_per_license_not_per_package(self):
        """Verify that summary counts reflect individual license evaluations."""
        policy = LicensePolicy(
            allowed_licenses=["MIT"],
            denied_licenses=["GPL*"],
        )
        syft_data = _syft_output([
            _syft_artifact("dual", "1.0.0", ["MIT", "GPL-3.0"]),
        ])
        result = check_licenses(".", policy, syft_json=syft_data)
        assert result["summary"]["total"] == 1  # 1 package
        assert result["summary"]["allowed"] + result["summary"]["denied"] == 2  # 2 licenses


# --- run_syft unit tests ---


class TestRunSyft:
    def test_syft_not_installed(self):
        from unittest.mock import patch
        from ez_appsec.license_checker import run_syft

        with patch("ez_appsec.license_checker.subprocess.run", side_effect=FileNotFoundError):
            data, raw_path = run_syft(".")
        assert data is None
        assert raw_path == ""

    def test_syft_version_check_fails(self):
        from unittest.mock import patch, MagicMock
        from ez_appsec.license_checker import run_syft

        with patch("ez_appsec.license_checker.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "syft")
            data, raw_path = run_syft(".")
        assert data is None
        assert raw_path == ""

    def test_syft_nonzero_exit_code(self):
        from unittest.mock import patch, MagicMock, call
        from ez_appsec.license_checker import run_syft

        version_result = MagicMock(returncode=0)
        scan_result = MagicMock(returncode=1, stderr="error: bad path")

        with patch("ez_appsec.license_checker.subprocess.run", side_effect=[version_result, scan_result]):
            with patch("tempfile.NamedTemporaryFile") as mock_tmp:
                mock_tmp.return_value.__enter__ = lambda s: MagicMock(name="/tmp/test.json")
                mock_tmp.return_value.__exit__ = lambda s, *a: None
                data, raw_path = run_syft(".")

        assert data is None

    def test_syft_timeout(self):
        import subprocess as sp
        from unittest.mock import patch, MagicMock
        from ez_appsec.license_checker import run_syft

        version_result = MagicMock(returncode=0)

        with patch("ez_appsec.license_checker.subprocess.run") as mock_run:
            mock_run.side_effect = [version_result, sp.TimeoutExpired("syft", 300)]
            with patch("tempfile.NamedTemporaryFile") as mock_tmp:
                mock_file = MagicMock()
                mock_file.name = "/tmp/test.json"
                mock_tmp.return_value.__enter__ = lambda s: mock_file
                mock_tmp.return_value.__exit__ = lambda s, *a: None
                data, raw_path = run_syft(".")

        assert data is None
        assert raw_path == "/tmp/test.json"


# --- Diff parser tests ---


class TestUnifiedDiffParser:
    def test_parse_simple_addition(self):
        from ez_appsec.pr_commenter import PRDiffParser

        diff = (
            "diff --git a/foo.py b/foo.py\n"
            "--- a/foo.py\n"
            "+++ b/foo.py\n"
            "@@ -1,3 +1,4 @@\n"
            " line1\n"
            "+added_line\n"
            " line2\n"
            " line3\n"
        )
        result = PRDiffParser._parse_unified_diff(diff)
        assert "foo.py" in result
        assert 2 in result["foo.py"]

    def test_parse_deletion_only(self):
        from ez_appsec.pr_commenter import PRDiffParser

        diff = (
            "diff --git a/bar.py b/bar.py\n"
            "--- a/bar.py\n"
            "+++ b/bar.py\n"
            "@@ -1,4 +1,3 @@\n"
            " line1\n"
            "-removed_line\n"
            " line2\n"
            " line3\n"
        )
        result = PRDiffParser._parse_unified_diff(diff)
        assert result.get("bar.py", set()) == set()

    def test_parse_multiple_hunks(self):
        from ez_appsec.pr_commenter import PRDiffParser

        diff = (
            "diff --git a/multi.py b/multi.py\n"
            "--- a/multi.py\n"
            "+++ b/multi.py\n"
            "@@ -1,3 +1,4 @@\n"
            " line1\n"
            "+new_early\n"
            " line2\n"
            " line3\n"
            "@@ -10,3 +11,4 @@\n"
            " line10\n"
            "+new_late\n"
            " line11\n"
            " line12\n"
        )
        result = PRDiffParser._parse_unified_diff(diff)
        assert 2 in result["multi.py"]
        assert 12 in result["multi.py"]

    def test_parse_multiple_files(self):
        from ez_appsec.pr_commenter import PRDiffParser

        diff = (
            "diff --git a/a.py b/a.py\n"
            "--- a/a.py\n"
            "+++ b/a.py\n"
            "@@ -1,2 +1,3 @@\n"
            " x\n"
            "+y\n"
            " z\n"
            "diff --git a/b.py b/b.py\n"
            "--- a/b.py\n"
            "+++ b/b.py\n"
            "@@ -5,2 +5,3 @@\n"
            " m\n"
            "+n\n"
            " o\n"
        )
        result = PRDiffParser._parse_unified_diff(diff)
        assert 2 in result["a.py"]
        assert 6 in result["b.py"]

    def test_empty_diff(self):
        from ez_appsec.pr_commenter import PRDiffParser

        result = PRDiffParser._parse_unified_diff("")
        assert result == {}
