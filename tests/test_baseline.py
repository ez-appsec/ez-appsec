"""Tests for baseline diffing (PLAN-03)"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from ez_appsec.baseline import Baseline, load_baseline, diff_findings, _fingerprint

FIXTURES = Path(__file__).parent / "fixtures"


class TestFingerprint:
    def test_stable_across_calls(self):
        finding = {"rule_id": "xss", "file": "app.py", "line": 10}
        assert _fingerprint(finding) == _fingerprint(finding)

    def test_different_for_different_findings(self):
        a = {"rule_id": "xss", "file": "app.py", "line": 10}
        b = {"rule_id": "sqli", "file": "app.py", "line": 10}
        assert _fingerprint(a) != _fingerprint(b)

    def test_handles_gitlab_format(self):
        finding = {
            "id": "some-rule",
            "location": {"file": "src/main.py", "start_line": 5},
        }
        fp = _fingerprint(finding)
        assert isinstance(fp, str) and len(fp) == 64


class TestBaseline:
    def test_empty_baseline(self):
        bl = Baseline(findings=[])
        assert len(bl.fingerprints) == 0

    def test_fingerprints_populated(self):
        findings = [
            {"rule_id": "a", "file": "x.py", "line": 1},
            {"rule_id": "b", "file": "y.py", "line": 2},
        ]
        bl = Baseline(findings=findings)
        assert len(bl.fingerprints) == 2


class TestLoadBaseline:
    def test_load_from_file_issues_key(self):
        bl = load_baseline(str(FIXTURES / "baseline_v1.json"))
        assert len(bl.findings) == 3

    def test_load_from_file_vulnerabilities_key(self):
        data = {"vulnerabilities": [{"rule_id": "r1", "file": "f.py", "line": 1}]}
        tmp = FIXTURES / "_tmp_vuln_baseline.json"
        tmp.write_text(json.dumps(data))
        try:
            bl = load_baseline(str(tmp))
            assert len(bl.findings) == 1
        finally:
            tmp.unlink()

    def test_load_from_bare_list(self):
        data = [{"rule_id": "r1", "file": "f.py", "line": 1}]
        tmp = FIXTURES / "_tmp_list_baseline.json"
        tmp.write_text(json.dumps(data))
        try:
            bl = load_baseline(str(tmp))
            assert len(bl.findings) == 1
        finally:
            tmp.unlink()

    def test_load_from_url(self):
        payload = json.dumps({"issues": [{"rule_id": "r1", "file": "f.py", "line": 1}]}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = payload
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
            bl = load_baseline("https://dashboard.example.com/data/vulnerabilities.json")
            mock_open.assert_called_once()
            assert len(bl.findings) == 1


class TestDiffFindings:
    def test_identical_findings_all_suppressed(self):
        bl = load_baseline(str(FIXTURES / "baseline_v1.json"))
        current = bl.findings[:]
        new, existing = diff_findings(current, bl)
        assert len(new) == 0
        assert len(existing) == 3

    def test_new_file_all_new(self):
        bl = Baseline(findings=[])
        current = [
            {"rule_id": "xss", "file": "app.py", "line": 1},
            {"rule_id": "sqli", "file": "db.py", "line": 5},
        ]
        new, existing = diff_findings(current, bl)
        assert len(new) == 2
        assert len(existing) == 0

    def test_line_shift_matched_by_rule_and_file(self):
        bl = load_baseline(str(FIXTURES / "baseline_v1.json"))
        shifted = {
            "rule_id": "sql-injection",
            "file": "src/db.py",
            "line": 50,
            "severity": "high",
            "title": "SQL Injection",
        }
        new, existing = diff_findings([shifted], bl)
        assert len(existing) == 1
        assert len(new) == 0

    def test_empty_baseline_everything_new(self):
        bl = Baseline(findings=[])
        current = [{"rule_id": "a", "file": "f.py", "line": 1}]
        new, existing = diff_findings(current, bl)
        assert len(new) == 1
        assert len(existing) == 0

    def test_mixed_new_and_existing(self):
        bl = load_baseline(str(FIXTURES / "baseline_v1.json"))
        current = bl.findings[:] + [
            {"rule_id": "hardcoded-password", "file": "src/auth.py", "line": 22}
        ]
        new, existing = diff_findings(current, bl)
        assert len(existing) == 3
        assert len(new) == 1
        assert new[0]["rule_id"] == "hardcoded-password"


class TestIntegrationWithFixtures:
    def test_v1_to_v2_detects_new_finding(self):
        bl = load_baseline(str(FIXTURES / "baseline_v1.json"))
        v2 = load_baseline(str(FIXTURES / "baseline_v2.json"))
        new, existing = diff_findings(v2.findings, bl)
        assert len(new) == 1
        assert new[0]["rule_id"] == "hardcoded-password"
        assert len(existing) == 3
