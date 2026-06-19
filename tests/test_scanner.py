"""Tests for the security scanner"""

import json

import pytest
from datetime import datetime, timedelta, timezone
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

class _FakeExternalScanner:
    def __init__(self, issues):
        self.issues = issues

    def scan_all(self, path):
        return [dict(issue) for issue in self.issues]


class _PassthroughAI:
    def analyze(self, issues, base_path, custom_prompt=None):
        return {"enhanced_issues": issues}


class TestScanTracking:
    def _scanner_with_issues(self, tmp_path, issues):
        config = Config(severity="all")
        config.output_file = str(tmp_path / "vulnerabilities.json")
        scanner = SecurityScanner(config)
        scanner.external = _FakeExternalScanner(issues)
        scanner.ai = _PassthroughAI()
        return scanner

    def test_first_scan_populates_v2_temporal_fields_and_scan_record(self, tmp_path):
        issue = {
            "rule_id": "python.sql-injection",
            "title": "SQL injection",
            "description": "Unsafe query",
            "file": "app.py",
            "line": 12,
            "severity": "high",
        }
        scanner = self._scanner_with_issues(tmp_path, [issue])

        result = scanner.scan(str(tmp_path))

        finding = result["issues"][0]
        assert finding["schema_version"] == "2"
        assert finding["finding_id"]
        assert finding["scan_id"] == result["scan_record"]["scan_id"]
        assert finding["trend"] == "new"
        assert finding["first_seen"] == finding["last_seen"]
        assert finding["age_days"] == 0
        assert result["scan_record"]["finding_count"] == 1
        assert result["scan_record"]["new_count"] == 1
        assert result["scan_record"]["resolved_count"] == 0
        assert Path(result["scan_record_path"]).name == "scan_record.json"
        assert Path(result["scan_record_path"]).exists()

    def test_second_scan_inherits_first_seen_and_marks_unchanged(self, tmp_path):
        issue = {
            "rule_id": "python.sql-injection",
            "title": "SQL injection",
            "description": "Unsafe query",
            "file": "app.py",
            "line": 12,
            "severity": "high",
        }
        previous_first_seen = datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat()
        scanner = self._scanner_with_issues(tmp_path, [issue])
        first_result = scanner.scan(str(tmp_path))
        previous_payload = {
            "issues": [
                {
                    **first_result["issues"][0],
                    "first_seen": previous_first_seen,
                }
            ]
        }
        Path(scanner.config.output_file).write_text(json.dumps(previous_payload))

        result = scanner.scan(str(tmp_path))

        finding = result["issues"][0]
        assert finding["finding_id"] == first_result["issues"][0]["finding_id"]
        assert finding["first_seen"] == previous_first_seen
        assert finding["trend"] == "unchanged"
        assert finding["age_days"] >= 0
        assert result["scan_record"]["new_count"] == 0
        assert result["scan_record"]["resolved_count"] == 0

    def test_persisted_findings_retain_v2_fields_on_disk(self, tmp_path):
        """Regression: the on-disk vulnerabilities.json must keep v2 tracking fields.

        Previously the scanner persisted via finding_from_dict, which copied only the
        five v1 fields and dropped first_seen/trend/scan_id/category, so the written
        file always showed first_seen=null/trend=new regardless of the scan tracking.
        """
        issue = {
            "rule_id": "gitleaks.aws-key",
            "title": "AWS key",
            "description": "Hardcoded AWS access key",
            "file": "config.py",
            "line": 7,
            "severity": "critical",
            # Scanner-native category that is NOT a Category enum member; the
            # persistence boundary must normalize it rather than crash.
            "category": "hardcoded-secret",
        }
        scanner = self._scanner_with_issues(tmp_path, [issue])

        result = scanner.scan(str(tmp_path))

        persisted = json.loads(Path(scanner.config.output_file).read_text())
        written = persisted["vulnerabilities"][0]
        assert written["schema_version"] == "2"
        assert written["finding_id"] == result["issues"][0]["finding_id"]
        assert written["scan_id"] == result["scan_record"]["scan_id"]
        assert written["trend"] == "new"
        assert written["category"] == "secrets"  # alias normalized onto the enum
        # first_seen must survive to disk (the dropped-field bug left it null).
        # Pydantic JSON mode serializes the tz as 'Z' while the in-memory result
        # uses '+00:00', so compare the parsed instant rather than the raw string.
        assert written["first_seen"] is not None
        persisted_first_seen = datetime.fromisoformat(
            written["first_seen"].replace("Z", "+00:00")
        )
        result_first_seen = datetime.fromisoformat(result["issues"][0]["first_seen"])
        assert persisted_first_seen == result_first_seen

    def test_two_scan_sequence_round_trips_through_backend(self, tmp_path):
        """Second scan reads its OWN persisted file (not a hand-written payload).

        This exercises the real write -> read -> track path end to end: first_seen
        must be inherited from the persisted record and the finding marked unchanged.
        """
        issue = {
            "rule_id": "python.sql-injection",
            "title": "SQL injection",
            "description": "Unsafe query",
            "file": "app.py",
            "line": 12,
            "severity": "high",
        }
        scanner = self._scanner_with_issues(tmp_path, [issue])

        first_result = scanner.scan(str(tmp_path))
        first_seen = first_result["issues"][0]["first_seen"]
        assert first_seen is not None

        # Second scan loads previous findings from the file the first scan wrote.
        second_result = scanner.scan(str(tmp_path))

        finding = second_result["issues"][0]
        assert finding["finding_id"] == first_result["issues"][0]["finding_id"]
        assert finding["first_seen"] == first_seen
        assert finding["trend"] == "unchanged"
        assert second_result["scan_record"]["new_count"] == 0
        assert second_result["scan_record"]["resolved_count"] == 0

