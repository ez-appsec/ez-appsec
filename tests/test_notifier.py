"""Tests for ez_appsec.notifier (PLAN-07: Slack / Teams Notifications)."""

import json
from unittest.mock import patch, MagicMock

import pytest

from ez_appsec.notifier import (
    NotificationPayload,
    SlackNotifier,
    TeamsNotifier,
    build_payload,
    notify_on_new_findings,
    should_notify,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

CRITICAL_FINDING = {
    "severity": "critical",
    "title": "SQL Injection in login",
    "file": "app/auth.py",
    "line": 42,
    "rule_id": "sqli-001",
}

HIGH_FINDING = {
    "severity": "high",
    "title": "XSS in search",
    "file": "app/views.py",
    "line": 88,
    "rule_id": "xss-001",
}

MEDIUM_FINDING = {
    "severity": "medium",
    "title": "Missing CSRF token",
    "file": "app/forms.py",
    "line": 10,
    "rule_id": "csrf-001",
}

LOW_FINDING = {
    "severity": "low",
    "title": "Debug mode enabled",
    "file": "config.py",
    "line": 5,
    "rule_id": "debug-001",
}

MIXED_FINDINGS = [CRITICAL_FINDING, HIGH_FINDING, MEDIUM_FINDING, LOW_FINDING]


# ---------------------------------------------------------------------------
# should_notify
# ---------------------------------------------------------------------------

class TestShouldNotify:
    def test_true_for_critical(self):
        assert should_notify([CRITICAL_FINDING]) is True

    def test_true_for_high(self):
        assert should_notify([HIGH_FINDING]) is True

    def test_false_for_medium_only(self):
        assert should_notify([MEDIUM_FINDING]) is False

    def test_false_for_low_only(self):
        assert should_notify([LOW_FINDING]) is False

    def test_false_for_empty(self):
        assert should_notify([]) is False

    def test_true_for_mixed(self):
        assert should_notify(MIXED_FINDINGS) is True


# ---------------------------------------------------------------------------
# build_payload
# ---------------------------------------------------------------------------

class TestBuildPayload:
    def test_counts_by_severity(self):
        p = build_payload(MIXED_FINDINGS, project_name="test-proj")
        assert p.critical == 1
        assert p.high == 1
        assert p.medium == 1
        assert p.low == 1
        assert p.total_new == 4
        assert p.project_name == "test-proj"

    def test_top_findings_limited(self):
        findings = MIXED_FINDINGS * 5
        p = build_payload(findings, max_top=3)
        assert len(p.top_findings) == 3

    def test_top_findings_contain_title_and_file(self):
        p = build_payload([CRITICAL_FINDING])
        assert p.top_findings[0]["title"] == "SQL Injection in login"
        assert p.top_findings[0]["file"] == "app/auth.py"
        assert p.top_findings[0]["severity"] == "critical"

    def test_dashboard_url_passed_through(self):
        p = build_payload([CRITICAL_FINDING], dashboard_url="https://example.com/dash")
        assert p.dashboard_url == "https://example.com/dash"

    def test_empty_findings(self):
        p = build_payload([])
        assert p.total_new == 0
        assert p.critical == 0
        assert p.top_findings == []


# ---------------------------------------------------------------------------
# SlackNotifier
# ---------------------------------------------------------------------------

class TestSlackNotifier:
    def test_format_message_has_blocks(self):
        n = SlackNotifier("https://hooks.slack.com/test")
        payload = build_payload(MIXED_FINDINGS, project_name="my-app",
                                dashboard_url="https://dash.example.com")
        msg = n.format_message(payload)

        assert "blocks" in msg
        blocks = msg["blocks"]
        assert len(blocks) >= 2

        header = blocks[0]
        assert header["type"] == "header"
        assert "4 new finding" in header["text"]["text"]

    def test_format_message_includes_project_name(self):
        n = SlackNotifier("https://hooks.slack.com/test")
        payload = build_payload([CRITICAL_FINDING], project_name="acme-api")
        msg = n.format_message(payload)
        section_texts = [
            b["text"]["text"] for b in msg["blocks"] if b["type"] == "section"
        ]
        assert any("acme-api" in t for t in section_texts)

    def test_format_message_includes_dashboard_link(self):
        n = SlackNotifier("https://hooks.slack.com/test")
        payload = build_payload([HIGH_FINDING], dashboard_url="https://dash.io")
        msg = n.format_message(payload)
        flat = json.dumps(msg)
        assert "https://dash.io" in flat

    def test_format_message_omits_dashboard_when_empty(self):
        n = SlackNotifier("https://hooks.slack.com/test")
        payload = build_payload([HIGH_FINDING], dashboard_url="")
        msg = n.format_message(payload)
        flat = json.dumps(msg)
        assert "View Dashboard" not in flat

    @patch("ez_appsec.notifier._post_json")
    def test_send_calls_post_json(self, mock_post):
        mock_post.return_value = True
        n = SlackNotifier("https://hooks.slack.com/test")
        payload = build_payload([CRITICAL_FINDING], project_name="proj")
        result = n.send(payload)
        assert result is True
        mock_post.assert_called_once()
        url, body = mock_post.call_args[0]
        assert url == "https://hooks.slack.com/test"
        assert "blocks" in body


# ---------------------------------------------------------------------------
# TeamsNotifier
# ---------------------------------------------------------------------------

class TestTeamsNotifier:
    def test_format_message_is_adaptive_card(self):
        n = TeamsNotifier("https://outlook.office.com/webhook/test")
        payload = build_payload(MIXED_FINDINGS, project_name="my-app")
        msg = n.format_message(payload)

        assert msg["type"] == "message"
        assert len(msg["attachments"]) == 1
        card = msg["attachments"][0]
        assert card["contentType"] == "application/vnd.microsoft.card.adaptive"
        content = card["content"]
        assert content["type"] == "AdaptiveCard"
        assert content["version"] == "1.4"

    def test_format_message_includes_facts(self):
        n = TeamsNotifier("https://outlook.office.com/webhook/test")
        payload = build_payload([CRITICAL_FINDING], project_name="backend")
        msg = n.format_message(payload)
        content = msg["attachments"][0]["content"]
        fact_sets = [b for b in content["body"] if b.get("type") == "FactSet"]
        assert len(fact_sets) == 1
        facts = fact_sets[0]["facts"]
        assert any(f["value"] == "backend" for f in facts)

    def test_format_message_includes_dashboard_action(self):
        n = TeamsNotifier("https://outlook.office.com/webhook/test")
        payload = build_payload([HIGH_FINDING], dashboard_url="https://dash.io")
        msg = n.format_message(payload)
        content = msg["attachments"][0]["content"]
        assert "actions" in content
        assert content["actions"][0]["url"] == "https://dash.io"

    def test_format_message_omits_actions_when_no_url(self):
        n = TeamsNotifier("https://outlook.office.com/webhook/test")
        payload = build_payload([HIGH_FINDING], dashboard_url="")
        msg = n.format_message(payload)
        content = msg["attachments"][0]["content"]
        assert "actions" not in content

    @patch("ez_appsec.notifier._post_json")
    def test_send_calls_post_json(self, mock_post):
        mock_post.return_value = True
        n = TeamsNotifier("https://outlook.office.com/webhook/test")
        payload = build_payload([CRITICAL_FINDING], project_name="proj")
        result = n.send(payload)
        assert result is True
        mock_post.assert_called_once()
        url, body = mock_post.call_args[0]
        assert url == "https://outlook.office.com/webhook/test"
        assert body["type"] == "message"


# ---------------------------------------------------------------------------
# notify_on_new_findings (integration)
# ---------------------------------------------------------------------------

class TestNotifyOnNewFindings:
    @patch("ez_appsec.notifier._post_json", return_value=True)
    def test_sends_slack_on_critical(self, mock_post):
        result = notify_on_new_findings(
            [CRITICAL_FINDING],
            project_name="proj",
            slack_webhook="https://hooks.slack.com/test",
        )
        assert result["notified"] is True
        assert result["slack"] is True
        assert result["teams"] is None

    @patch("ez_appsec.notifier._post_json", return_value=True)
    def test_sends_teams_on_high(self, mock_post):
        result = notify_on_new_findings(
            [HIGH_FINDING],
            project_name="proj",
            teams_webhook="https://outlook.office.com/webhook/test",
        )
        assert result["notified"] is True
        assert result["teams"] is True
        assert result["slack"] is None

    @patch("ez_appsec.notifier._post_json", return_value=True)
    def test_sends_both_when_configured(self, mock_post):
        result = notify_on_new_findings(
            MIXED_FINDINGS,
            project_name="proj",
            slack_webhook="https://hooks.slack.com/test",
            teams_webhook="https://outlook.office.com/webhook/test",
        )
        assert result["notified"] is True
        assert result["slack"] is True
        assert result["teams"] is True
        assert mock_post.call_count == 2

    def test_no_notification_when_no_webhooks(self):
        result = notify_on_new_findings(MIXED_FINDINGS, project_name="proj")
        assert result["notified"] is False
        assert result["reason"] == "no webhook configured"

    @patch("ez_appsec.notifier._post_json", return_value=True)
    def test_no_notification_on_empty_findings(self, mock_post):
        result = notify_on_new_findings(
            [],
            project_name="proj",
            slack_webhook="https://hooks.slack.com/test",
        )
        assert result["notified"] is False
        assert result["reason"] == "no new findings"
        mock_post.assert_not_called()

    @patch("ez_appsec.notifier._post_json", return_value=True)
    def test_no_notification_on_medium_only(self, mock_post):
        result = notify_on_new_findings(
            [MEDIUM_FINDING],
            project_name="proj",
            slack_webhook="https://hooks.slack.com/test",
        )
        assert result["notified"] is False
        assert result["reason"] == "no critical/high findings"
        mock_post.assert_not_called()

    @patch("ez_appsec.notifier._post_json", return_value=True)
    def test_reads_env_vars(self, mock_post, monkeypatch):
        monkeypatch.setenv("EZ_APPSEC_SLACK_WEBHOOK", "https://hooks.slack.com/env")
        monkeypatch.setenv("EZ_APPSEC_PROJECT_NAME", "env-proj")
        monkeypatch.setenv("EZ_APPSEC_DASHBOARD_URL", "https://dash.env.io")
        result = notify_on_new_findings([CRITICAL_FINDING])
        assert result["notified"] is True
        url, body = mock_post.call_args[0]
        assert url == "https://hooks.slack.com/env"
        flat = json.dumps(body)
        assert "env-proj" in flat

    @patch("ez_appsec.notifier._post_json", return_value=False)
    def test_reports_send_failure(self, mock_post):
        result = notify_on_new_findings(
            [CRITICAL_FINDING],
            project_name="proj",
            slack_webhook="https://hooks.slack.com/test",
        )
        assert result["notified"] is False
        assert result["slack"] is False
