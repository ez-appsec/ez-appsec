"""Tests for configuration"""

import os
import pytest
import tempfile
from datetime import datetime, timedelta

from ez_appsec.config import Config, IgnoreRule


# --- Existing tests ---


def test_default_config():
    config = Config()
    assert config.severity == "all"
    assert config.ai_model == "gpt-4"
    assert config.ai_temperature == 0.5


def test_config_with_languages():
    config = Config(languages=["python", "javascript"])
    assert config.languages == ["python", "javascript"]


def test_config_severity():
    config = Config(severity="high")
    assert config.severity == "high"


# --- IgnoreRule parsing tests ---


class TestIgnoreRuleParsing:
    def test_minimal_rule(self):
        rule = IgnoreRule(rule_id="test.rule", permanent=True, reason="test")
        assert rule.rule_id == "test.rule"
        assert rule.permanent is True
        assert rule.reason == "test"

    def test_all_fields(self):
        rule = IgnoreRule(
            rule_id="test.rule",
            file_path="tests/**",
            message="test credential",
            cve_id="CVE-2023-1234",
            permanent=False,
            until="2099-12-31",
            reason="test fixture",
        )
        assert rule.rule_id == "test.rule"
        assert rule.file_path == "tests/**"
        assert rule.message == "test credential"
        assert rule.cve_id == "CVE-2023-1234"
        assert rule.until == "2099-12-31"

    def test_invalid_until_date_rejected(self):
        with pytest.raises(ValueError, match="ISO format"):
            IgnoreRule(rule_id="x", until="not-a-date", reason="test")

    def test_valid_until_formats(self):
        rule = IgnoreRule(rule_id="x", until="2099-06-15", reason="test")
        assert rule.until == "2099-06-15"


# --- IgnoreRule.is_active tests ---


class TestIgnoreRuleIsActive:
    def test_permanent_always_active(self):
        rule = IgnoreRule(rule_id="x", permanent=True, reason="test")
        assert rule.is_active() is True

    def test_future_until_is_active(self):
        future = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
        rule = IgnoreRule(rule_id="x", until=future, reason="test")
        assert rule.is_active() is True

    def test_past_until_is_inactive(self):
        past = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        rule = IgnoreRule(rule_id="x", until=past, reason="test")
        assert rule.is_active() is False

    def test_no_permanent_no_until_is_inactive(self):
        rule = IgnoreRule(rule_id="x", reason="test")
        assert rule.is_active() is False


# --- IgnoreRule.matches tests ---


class TestIgnoreRuleMatches:
    def _finding(self, **overrides):
        base = {
            "rule_id": "python.sql-injection",
            "file": "src/app.py",
            "description": "SQL injection vulnerability",
            "severity": "high",
        }
        base.update(overrides)
        return base

    def test_match_by_rule_id(self):
        rule = IgnoreRule(rule_id="python.sql-injection", permanent=True, reason="test")
        assert rule.matches(self._finding()) is True

    def test_no_match_different_rule_id(self):
        rule = IgnoreRule(rule_id="python.xss", permanent=True, reason="test")
        assert rule.matches(self._finding()) is False

    def test_match_by_cve_id(self):
        rule = IgnoreRule(cve_id="CVE-2023-999", permanent=True, reason="test")
        assert rule.matches(self._finding(cve_id="CVE-2023-999")) is True

    def test_match_by_file_path_glob(self):
        rule = IgnoreRule(file_path="src/*.py", permanent=True, reason="test")
        assert rule.matches(self._finding(file="src/app.py")) is True

    def test_match_by_file_path_double_star(self):
        rule = IgnoreRule(file_path="tests/**", permanent=True, reason="test")
        assert rule.matches(self._finding(file="tests/unit/test_auth.py")) is True

    def test_no_match_file_path(self):
        rule = IgnoreRule(file_path="vendor/**", permanent=True, reason="test")
        assert rule.matches(self._finding(file="src/app.py")) is False

    def test_match_by_message_substring(self):
        rule = IgnoreRule(message="SQL injection", permanent=True, reason="test")
        assert rule.matches(self._finding()) is True

    def test_match_by_message_case_insensitive(self):
        rule = IgnoreRule(message="sql INJECTION", permanent=True, reason="test")
        assert rule.matches(self._finding()) is True

    def test_no_match_message(self):
        rule = IgnoreRule(message="buffer overflow", permanent=True, reason="test")
        assert rule.matches(self._finding()) is False

    def test_expired_rule_never_matches(self):
        past = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        rule = IgnoreRule(rule_id="python.sql-injection", until=past, reason="expired")
        assert rule.matches(self._finding()) is False

    def test_match_finding_with_id_field(self):
        rule = IgnoreRule(rule_id="generic-api-key", permanent=True, reason="test")
        assert rule.matches({"id": "generic-api-key", "file": "x"}) is True

    def test_match_finding_with_location_file(self):
        rule = IgnoreRule(file_path="lib/*.js", permanent=True, reason="test")
        finding = {"location": {"file": "lib/utils.js"}, "description": "x"}
        assert rule.matches(finding) is True


# --- Config YAML loading tests ---


class TestConfigFromFile:
    def _write_config(self, content):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        f.write(content)
        f.close()
        return f.name

    def test_load_with_ignore_rules(self):
        path = self._write_config(
            """
severity: high
ignore:
  - rule_id: python.sql-injection
    file_path: "tests/**"
    reason: "Test fixtures"
    permanent: true
  - cve_id: CVE-2023-1234
    reason: "Known false positive"
    until: "2099-06-01"
"""
        )
        try:
            config = Config.from_file(path)
            assert config.severity == "high"
            assert len(config.ignore_rules) == 2
            assert config.ignore_rules[0].rule_id == "python.sql-injection"
            assert config.ignore_rules[0].permanent is True
            assert config.ignore_rules[1].cve_id == "CVE-2023-1234"
            assert config.ignore_rules[1].until == "2099-06-01"
        finally:
            os.unlink(path)

    def test_load_no_ignore_section(self):
        path = self._write_config("severity: all\n")
        try:
            config = Config.from_file(path)
            assert config.ignore_rules == []
        finally:
            os.unlink(path)

    def test_load_nonexistent_file(self):
        config = Config.from_file("/tmp/does-not-exist-ez-appsec.yaml")
        assert config.severity == "all"
        assert config.ignore_rules == []

    def test_load_empty_file(self):
        path = self._write_config("")
        try:
            config = Config.from_file(path)
            assert config.severity == "all"
        finally:
            os.unlink(path)


# --- Config.get_matching_ignore_rule tests ---


class TestGetMatchingIgnoreRule:
    def test_returns_first_matching_rule(self):
        config = Config(
            ignore_rules=[
                IgnoreRule(rule_id="rule-a", permanent=True, reason="first"),
                IgnoreRule(rule_id="rule-b", permanent=True, reason="second"),
            ]
        )
        finding = {"rule_id": "rule-b", "file": "x.py", "description": "test"}
        match = config.get_matching_ignore_rule(finding)
        assert match is not None
        assert match.reason == "second"

    def test_returns_none_when_no_match(self):
        config = Config(
            ignore_rules=[
                IgnoreRule(rule_id="rule-a", permanent=True, reason="only"),
            ]
        )
        finding = {"rule_id": "rule-z", "file": "x.py", "description": "test"}
        assert config.get_matching_ignore_rule(finding) is None
