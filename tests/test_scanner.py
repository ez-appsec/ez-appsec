"""Tests for the security scanner"""

import pytest
from datetime import datetime, timedelta
from pathlib import Path
from ez_appsec.scanner import SecurityScanner
from ez_appsec.config import Config, IgnoreRule


@pytest.fixture
def test_config():
    return Config(severity="all")


@pytest.fixture
def scanner(test_config):
    return SecurityScanner(test_config)


def test_scanner_initialization(scanner):
    """Test scanner initializes correctly"""
    assert scanner is not None
    assert scanner.external is not None
    assert scanner.config is not None


# --- Ignore rule suppression tests ---


class TestApplyIgnoreRules:
    def _make_scanner(self, ignore_rules):
        config = Config(ignore_rules=ignore_rules)
        return SecurityScanner(config, use_external_scanners=False)

    def _issues(self):
        return [
            {"rule_id": "generic-api-key", "file": "tests/fixtures/creds.py", "description": "API key found", "severity": "critical"},
            {"rule_id": "python.sql-injection", "file": "src/db.py", "description": "SQL injection", "severity": "high"},
            {"rule_id": "kics.open-port", "file": "infra/main.tf", "description": "Port 22 open", "severity": "medium"},
        ]

    def test_no_rules_passes_all(self):
        scanner = self._make_scanner([])
        active, suppressed = scanner._apply_ignore_rules(self._issues())
        assert len(active) == 3
        assert suppressed == 0

    def test_suppress_by_rule_id(self):
        rules = [IgnoreRule(rule_id="generic-api-key", permanent=True, reason="test creds")]
        scanner = self._make_scanner(rules)
        active, suppressed = scanner._apply_ignore_rules(self._issues())
        assert len(active) == 2
        assert suppressed == 1
        assert all(i["rule_id"] != "generic-api-key" for i in active)

    def test_suppress_by_file_glob(self):
        rules = [IgnoreRule(file_path="tests/**", permanent=True, reason="test dir")]
        scanner = self._make_scanner(rules)
        active, suppressed = scanner._apply_ignore_rules(self._issues())
        assert len(active) == 2
        assert suppressed == 1

    def test_suppress_by_message(self):
        rules = [IgnoreRule(message="API key", permanent=True, reason="known FP")]
        scanner = self._make_scanner(rules)
        active, suppressed = scanner._apply_ignore_rules(self._issues())
        assert suppressed == 1

    def test_suppressed_finding_gets_metadata(self):
        rules = [IgnoreRule(rule_id="generic-api-key", permanent=True, reason="test creds")]
        scanner = self._make_scanner(rules)
        issues = self._issues()
        scanner._apply_ignore_rules(issues)
        suppressed_issue = next(i for i in issues if i.get("suppressed_by"))
        assert suppressed_issue["suppressed_by"]["reason"] == "test creds"
        assert suppressed_issue["suppressed_by"]["rule_id"] == "generic-api-key"
        assert suppressed_issue["suppressed_by"]["permanent"] is True

    def test_expired_rule_does_not_suppress(self):
        past = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        rules = [IgnoreRule(rule_id="generic-api-key", until=past, reason="expired")]
        scanner = self._make_scanner(rules)
        active, suppressed = scanner._apply_ignore_rules(self._issues())
        assert len(active) == 3
        assert suppressed == 0

    def test_future_until_suppresses(self):
        future = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
        rules = [IgnoreRule(rule_id="generic-api-key", until=future, reason="temp")]
        scanner = self._make_scanner(rules)
        active, suppressed = scanner._apply_ignore_rules(self._issues())
        assert len(active) == 2
        assert suppressed == 1

    def test_multiple_rules_suppress_multiple(self):
        rules = [
            IgnoreRule(rule_id="generic-api-key", permanent=True, reason="creds"),
            IgnoreRule(file_path="infra/*", permanent=True, reason="infra noise"),
        ]
        scanner = self._make_scanner(rules)
        active, suppressed = scanner._apply_ignore_rules(self._issues())
        assert len(active) == 1
        assert suppressed == 2
        assert active[0]["rule_id"] == "python.sql-injection"
