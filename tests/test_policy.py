"""Tests for the policy engine (PLAN-09)"""

import os
import tempfile
import pytest

from ez_appsec.policy import PolicyRule, PolicyEngine, VALID_SEVERITIES, VALID_CATEGORIES, VALID_ACTIONS
from ez_appsec.config import Config


# --- Test fixtures ---


def _finding(severity="high", category="sast", **overrides):
    base = {
        "rule_id": "python.sql-injection",
        "file": "src/app.py",
        "description": "SQL injection vulnerability",
        "severity": severity,
        "category": category,
        "title": "SQL Injection",
    }
    base.update(overrides)
    return base


def _findings(*specs):
    """Build a list of findings from (severity, category) tuples."""
    return [_finding(severity=s, category=c) for s, c in specs]


# --- PolicyRule validation ---


class TestPolicyRuleValidation:
    def test_valid_rule(self):
        rule = PolicyRule(severity="critical", category="secrets", max_count=0, action="fail")
        assert rule.severity == "critical"
        assert rule.category == "secrets"
        assert rule.action == "fail"

    def test_defaults(self):
        rule = PolicyRule()
        assert rule.severity is None
        assert rule.category is None
        assert rule.max_count == 0
        assert rule.action == "fail"

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValueError, match="Invalid severity"):
            PolicyRule(severity="super-critical")

    def test_invalid_category_rejected(self):
        with pytest.raises(ValueError, match="Invalid category"):
            PolicyRule(category="magic")

    def test_invalid_action_rejected(self):
        with pytest.raises(ValueError, match="Invalid action"):
            PolicyRule(action="explode")

    def test_all_valid_severities(self):
        for sev in VALID_SEVERITIES:
            rule = PolicyRule(severity=sev)
            assert rule.severity == sev

    def test_all_valid_categories(self):
        for cat in VALID_CATEGORIES:
            rule = PolicyRule(category=cat)
            assert rule.category == cat

    def test_all_valid_actions(self):
        for act in VALID_ACTIONS:
            rule = PolicyRule(action=act)
            assert rule.action == act

    def test_none_severity_means_all(self):
        rule = PolicyRule(severity=None, action="fail")
        assert rule.severity is None

    def test_none_category_means_all(self):
        rule = PolicyRule(category=None, action="warn")
        assert rule.category is None


# --- PolicyRule.matching_findings ---


class TestPolicyRuleMatching:
    def test_no_filter_matches_all(self):
        rule = PolicyRule()
        findings = _findings(("critical", "secrets"), ("high", "sast"), ("low", "iac"))
        assert len(rule.matching_findings(findings)) == 3

    def test_severity_filter(self):
        rule = PolicyRule(severity="critical")
        findings = _findings(("critical", "secrets"), ("high", "sast"), ("critical", "iac"))
        assert len(rule.matching_findings(findings)) == 2

    def test_category_filter(self):
        rule = PolicyRule(category="sast")
        findings = _findings(("critical", "sast"), ("high", "sast"), ("high", "secrets"))
        assert len(rule.matching_findings(findings)) == 2

    def test_severity_and_category_filter(self):
        rule = PolicyRule(severity="critical", category="secrets")
        findings = _findings(
            ("critical", "secrets"),
            ("critical", "sast"),
            ("high", "secrets"),
        )
        assert len(rule.matching_findings(findings)) == 1

    def test_empty_findings(self):
        rule = PolicyRule(severity="critical")
        assert rule.matching_findings([]) == []

    def test_category_from_type_field(self):
        rule = PolicyRule(category="secrets")
        finding = {"severity": "high", "type": "secrets", "file": "x"}
        assert len(rule.matching_findings([finding])) == 1

    def test_category_from_scanner_field(self):
        rule = PolicyRule(category="sast")
        finding = {"severity": "high", "scanner": "sast", "file": "x"}
        assert len(rule.matching_findings([finding])) == 1

    def test_case_insensitive_severity(self):
        rule = PolicyRule(severity="high")
        finding = {"severity": "High", "file": "x"}
        assert len(rule.matching_findings([finding])) == 1
        finding2 = {"severity": "high", "file": "x"}
        assert len(rule.matching_findings([finding2])) == 1


# --- PolicyRule.evaluate ---


class TestPolicyRuleEvaluate:
    def test_no_violation_when_under_threshold(self):
        rule = PolicyRule(severity="critical", max_count=5, action="fail")
        findings = _findings(("critical", "sast"), ("critical", "sast"))
        assert rule.evaluate(findings) is None

    def test_no_violation_when_at_threshold(self):
        rule = PolicyRule(severity="critical", max_count=2, action="fail")
        findings = _findings(("critical", "sast"), ("critical", "sast"))
        assert rule.evaluate(findings) is None

    def test_violation_when_over_threshold(self):
        rule = PolicyRule(severity="critical", max_count=0, action="fail")
        findings = _findings(("critical", "sast"),)
        result = rule.evaluate(findings)
        assert result is not None
        assert result["action"] == "fail"
        assert result["count"] == 1
        assert result["max_count"] == 0

    def test_violation_includes_description(self):
        rule = PolicyRule(severity="high", category="secrets", max_count=0, action="fail")
        findings = [_finding(severity="high", category="secrets")]
        result = rule.evaluate(findings)
        assert "severity=high" in result["description"]
        assert "category=secrets" in result["description"]

    def test_warn_violation(self):
        rule = PolicyRule(severity="high", max_count=1, action="warn")
        findings = _findings(("high", "sast"), ("high", "sast"))
        result = rule.evaluate(findings)
        assert result["action"] == "warn"

    def test_no_filter_violation_description(self):
        rule = PolicyRule(max_count=0, action="fail")
        findings = [_finding()]
        result = rule.evaluate(findings)
        assert "all findings" in result["description"]

    def test_rule_dict_in_violation(self):
        rule = PolicyRule(severity="critical", category="cve", max_count=3, action="fail")
        findings = _findings(*[("critical", "cve")] * 5)
        result = rule.evaluate(findings)
        assert result["rule"]["severity"] == "critical"
        assert result["rule"]["category"] == "cve"
        assert result["rule"]["max_count"] == 3
        assert result["rule"]["action"] == "fail"


# --- PolicyEngine ---


class TestPolicyEngine:
    def test_all_pass(self):
        engine = PolicyEngine([
            PolicyRule(severity="critical", max_count=0, action="fail"),
        ])
        findings = _findings(("high", "sast"), ("medium", "iac"))
        result = engine.evaluate(findings)
        assert result["failed"] is False
        assert result["violations"] == []
        assert "all policies passed" in result["summary"]

    def test_single_fail(self):
        engine = PolicyEngine([
            PolicyRule(severity="critical", max_count=0, action="fail"),
        ])
        findings = _findings(("critical", "secrets"),)
        result = engine.evaluate(findings)
        assert result["failed"] is True
        assert len(result["violations"]) == 1

    def test_warn_does_not_cause_failure(self):
        engine = PolicyEngine([
            PolicyRule(severity="high", max_count=0, action="warn"),
        ])
        findings = _findings(("high", "sast"), ("high", "sast"))
        result = engine.evaluate(findings)
        assert result["failed"] is False
        assert len(result["violations"]) == 1
        assert result["violations"][0]["action"] == "warn"

    def test_mixed_fail_and_warn(self):
        engine = PolicyEngine([
            PolicyRule(severity="critical", max_count=0, action="fail"),
            PolicyRule(severity="high", max_count=5, action="warn"),
        ])
        findings = _findings(
            ("critical", "sast"),
            *[("high", "sast")] * 10,
        )
        result = engine.evaluate(findings)
        assert result["failed"] is True
        assert len(result["violations"]) == 2
        actions = {v["action"] for v in result["violations"]}
        assert actions == {"fail", "warn"}

    def test_ignore_rules_skipped(self):
        engine = PolicyEngine([
            PolicyRule(severity="critical", max_count=0, action="ignore"),
        ])
        findings = _findings(("critical", "sast"),)
        result = engine.evaluate(findings)
        assert result["failed"] is False
        assert result["violations"] == []

    def test_multiple_fail_rules(self):
        engine = PolicyEngine([
            PolicyRule(severity="critical", max_count=0, action="fail"),
            PolicyRule(category="secrets", max_count=0, action="fail"),
        ])
        findings = [_finding(severity="critical", category="secrets")]
        result = engine.evaluate(findings)
        assert result["failed"] is True
        assert len(result["violations"]) == 2

    def test_category_filter_isolates(self):
        engine = PolicyEngine([
            PolicyRule(category="secrets", max_count=0, action="fail"),
        ])
        findings = _findings(("high", "sast"), ("high", "iac"))
        result = engine.evaluate(findings)
        assert result["failed"] is False

    def test_combined_severity_category_rule(self):
        engine = PolicyEngine([
            PolicyRule(severity="critical", category="cve", max_count=0, action="fail"),
        ])
        findings = _findings(
            ("critical", "sast"),
            ("high", "cve"),
            ("critical", "cve"),
        )
        result = engine.evaluate(findings)
        assert result["failed"] is True
        assert result["violations"][0]["count"] == 1

    def test_empty_findings_all_pass(self):
        engine = PolicyEngine([
            PolicyRule(severity="critical", max_count=0, action="fail"),
        ])
        result = engine.evaluate([])
        assert result["failed"] is False
        assert result["violations"] == []

    def test_empty_rules_all_pass(self):
        engine = PolicyEngine([])
        findings = _findings(("critical", "sast"),)
        result = engine.evaluate(findings)
        assert result["failed"] is False

    def test_summary_format_fail(self):
        engine = PolicyEngine([
            PolicyRule(severity="critical", max_count=0, action="fail"),
        ])
        findings = _findings(("critical", "sast"),)
        result = engine.evaluate(findings)
        assert "1 failed" in result["summary"]

    def test_summary_format_warn(self):
        engine = PolicyEngine([
            PolicyRule(severity="high", max_count=0, action="warn"),
        ])
        findings = _findings(("high", "sast"),)
        result = engine.evaluate(findings)
        assert "1 warning" in result["summary"]

    def test_max_count_boundary(self):
        engine = PolicyEngine([
            PolicyRule(severity="high", max_count=3, action="fail"),
        ])
        exactly_3 = _findings(*[("high", "sast")] * 3)
        assert engine.evaluate(exactly_3)["failed"] is False

        four = _findings(*[("high", "sast")] * 4)
        assert engine.evaluate(four)["failed"] is True


# --- Config integration ---


class TestPolicyConfigIntegration:
    def _write_config(self, content):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        f.write(content)
        f.close()
        return f.name

    def test_load_policy_from_yaml(self):
        path = self._write_config("""
severity: all
policy:
  - severity: critical
    action: fail
    max_count: 0
  - severity: high
    category: secrets
    action: warn
    max_count: 5
""")
        try:
            config = Config.from_file(path)
            assert len(config.policy_rules) == 2
            assert config.policy_rules[0].severity == "critical"
            assert config.policy_rules[0].action == "fail"
            assert config.policy_rules[0].max_count == 0
            assert config.policy_rules[1].severity == "high"
            assert config.policy_rules[1].category == "secrets"
            assert config.policy_rules[1].action == "warn"
            assert config.policy_rules[1].max_count == 5
        finally:
            os.unlink(path)

    def test_no_policy_section(self):
        path = self._write_config("severity: all\n")
        try:
            config = Config.from_file(path)
            assert config.policy_rules == []
        finally:
            os.unlink(path)

    def test_empty_policy_section(self):
        path = self._write_config("severity: all\npolicy: []\n")
        try:
            config = Config.from_file(path)
            assert config.policy_rules == []
        finally:
            os.unlink(path)

    def test_policy_with_ignore_rules(self):
        path = self._write_config("""
severity: high
ignore:
  - rule_id: test.rule
    permanent: true
    reason: "test"
policy:
  - severity: critical
    action: fail
""")
        try:
            config = Config.from_file(path)
            assert len(config.ignore_rules) == 1
            assert len(config.policy_rules) == 1
        finally:
            os.unlink(path)


# --- Policy result in scan output ---


class TestPolicyInScanOutput:
    """Test that policy violations appear in scan results."""

    def test_policy_violations_in_results(self):
        from unittest.mock import patch, MagicMock
        from ez_appsec.scanner import SecurityScanner

        config = Config(
            policy_rules=[
                PolicyRule(severity="critical", max_count=0, action="fail"),
            ]
        )
        scanner = SecurityScanner(config, use_external_scanners=False)

        mock_findings = [
            {"severity": "critical", "category": "sast", "title": "SQLi", "description": "test", "file": "x.py"},
        ]

        with patch.object(scanner.ai, "analyze", return_value={"enhanced_issues": mock_findings}):
            scanner.external = MagicMock()
            scanner.external.scan_all.return_value = mock_findings
            scanner.use_external = True
            results = scanner.scan(".")

        assert "policy_violations" in results
        assert results["policy_failed"] is True
        assert len(results["policy_violations"]) == 1

    def test_no_policy_rules_no_key(self):
        from unittest.mock import patch, MagicMock
        from ez_appsec.scanner import SecurityScanner

        config = Config()
        scanner = SecurityScanner(config, use_external_scanners=False)

        with patch.object(scanner.ai, "analyze", return_value={"enhanced_issues": []}):
            results = scanner.scan(".")

        assert "policy_violations" not in results

    def test_policy_pass_not_failed(self):
        from unittest.mock import patch, MagicMock
        from ez_appsec.scanner import SecurityScanner

        config = Config(
            policy_rules=[
                PolicyRule(severity="critical", max_count=0, action="fail"),
            ]
        )
        scanner = SecurityScanner(config, use_external_scanners=False)

        mock_findings = [
            {"severity": "high", "category": "sast", "title": "XSS", "description": "test", "file": "x.py"},
        ]

        with patch.object(scanner.ai, "analyze", return_value={"enhanced_issues": mock_findings}):
            scanner.external = MagicMock()
            scanner.external.scan_all.return_value = mock_findings
            scanner.use_external = True
            results = scanner.scan(".")

        assert results["policy_failed"] is False
        assert results["policy_violations"] == []
