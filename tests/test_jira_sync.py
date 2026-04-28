"""Tests for ez_appsec.jira_sync (PLAN-08: Jira Integration)."""

import json
import os
import tempfile
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from ez_appsec.jira_sync import (
    JiraClient,
    JiraConfig,
    JiraIssueMap,
    _build_description,
    _build_resolved_comment,
    _build_summary,
    _fingerprint,
    _severity_to_priority,
    should_sync,
    sync_findings,
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
    "scanner": "semgrep",
    "description": "User input passed directly to SQL query",
    "remediation": "Use parameterized queries",
}

HIGH_FINDING = {
    "severity": "high",
    "title": "XSS in search",
    "file": "app/views.py",
    "line": 88,
    "rule_id": "xss-001",
    "scanner": "semgrep",
    "description": "Reflected XSS via search parameter",
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


@pytest.fixture
def jira_config():
    return JiraConfig(
        url="https://test.atlassian.net",
        email="bot@example.com",
        token="test-token",
        project_key="SEC",
    )


@pytest.fixture
def tmp_map(tmp_path):
    return str(tmp_path / "jira_map.json")


# ---------------------------------------------------------------------------
# JiraConfig
# ---------------------------------------------------------------------------


class TestJiraConfig:
    def test_from_env_complete(self):
        env = {
            "EZ_APPSEC_JIRA_URL": "https://my.atlassian.net",
            "EZ_APPSEC_JIRA_EMAIL": "bot@test.com",
            "EZ_APPSEC_JIRA_TOKEN": "tok-123",
            "EZ_APPSEC_JIRA_PROJECT": "SEC",
        }
        with patch.dict(os.environ, env, clear=False):
            cfg = JiraConfig.from_env()
        assert cfg is not None
        assert cfg.url == "https://my.atlassian.net"
        assert cfg.project_key == "SEC"
        assert cfg.issue_type == "Bug"

    def test_from_env_missing_returns_none(self):
        with patch.dict(os.environ, {}, clear=True):
            assert JiraConfig.from_env() is None

    def test_from_env_strips_trailing_slash(self):
        env = {
            "EZ_APPSEC_JIRA_URL": "https://my.atlassian.net/",
            "EZ_APPSEC_JIRA_EMAIL": "bot@test.com",
            "EZ_APPSEC_JIRA_TOKEN": "tok-123",
            "EZ_APPSEC_JIRA_PROJECT": "SEC",
        }
        with patch.dict(os.environ, env, clear=False):
            cfg = JiraConfig.from_env()
        assert cfg.url == "https://my.atlassian.net"

    def test_from_env_custom_issue_type(self):
        env = {
            "EZ_APPSEC_JIRA_URL": "https://my.atlassian.net",
            "EZ_APPSEC_JIRA_EMAIL": "bot@test.com",
            "EZ_APPSEC_JIRA_TOKEN": "tok-123",
            "EZ_APPSEC_JIRA_PROJECT": "SEC",
            "EZ_APPSEC_JIRA_ISSUE_TYPE": "Task",
        }
        with patch.dict(os.environ, env, clear=False):
            cfg = JiraConfig.from_env()
        assert cfg.issue_type == "Task"


# ---------------------------------------------------------------------------
# JiraIssueMap
# ---------------------------------------------------------------------------


class TestJiraIssueMap:
    def test_empty_map(self, tmp_map):
        m = JiraIssueMap(tmp_map)
        assert m.get("abc") is None
        assert m.all_fingerprints() == set()

    def test_set_and_get(self, tmp_map):
        m = JiraIssueMap(tmp_map)
        m.set("fp1", "SEC-1")
        assert m.get("fp1") == "SEC-1"

    def test_save_and_reload(self, tmp_map):
        m = JiraIssueMap(tmp_map)
        m.set("fp1", "SEC-1")
        m.set("fp2", "SEC-2")
        m.save()

        m2 = JiraIssueMap(tmp_map)
        assert m2.get("fp1") == "SEC-1"
        assert m2.get("fp2") == "SEC-2"

    def test_remove(self, tmp_map):
        m = JiraIssueMap(tmp_map)
        m.set("fp1", "SEC-1")
        m.remove("fp1")
        assert m.get("fp1") is None

    def test_remove_nonexistent(self, tmp_map):
        m = JiraIssueMap(tmp_map)
        m.remove("does-not-exist")  # should not raise

    def test_all_fingerprints(self, tmp_map):
        m = JiraIssueMap(tmp_map)
        m.set("a", "SEC-1")
        m.set("b", "SEC-2")
        assert m.all_fingerprints() == {"a", "b"}

    def test_corrupt_file(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not json!!!")
        m = JiraIssueMap(str(bad))
        assert m.get("anything") is None

    def test_creates_parent_dirs(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c" / "map.json"
        m = JiraIssueMap(str(deep))
        m.set("fp1", "SEC-1")
        m.save()
        assert deep.exists()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_fingerprint_deterministic(self):
        fp1 = _fingerprint(CRITICAL_FINDING)
        fp2 = _fingerprint(CRITICAL_FINDING)
        assert fp1 == fp2

    def test_fingerprint_different_findings(self):
        assert _fingerprint(CRITICAL_FINDING) != _fingerprint(HIGH_FINDING)

    def test_fingerprint_uses_rule_and_file(self):
        a = {"rule_id": "sqli-001", "file": "app/auth.py", "line": 42}
        b = {"rule_id": "sqli-001", "file": "app/auth.py", "line": 99}
        assert _fingerprint(a) == _fingerprint(b)

    def test_fingerprint_location_fallback(self):
        finding = {"id": "rule-1", "location": {"file": "foo.py"}}
        fp = _fingerprint(finding)
        assert isinstance(fp, str) and len(fp) == 64

    def test_severity_to_priority(self):
        assert _severity_to_priority("critical") == "Highest"
        assert _severity_to_priority("high") == "High"
        assert _severity_to_priority("medium") == "Medium"
        assert _severity_to_priority("low") == "Low"
        assert _severity_to_priority("unknown") == "Medium"

    def test_build_summary_with_file(self):
        s = _build_summary(CRITICAL_FINDING)
        assert "[CRITICAL]" in s
        assert "SQL Injection" in s
        assert "app/auth.py" in s

    def test_build_summary_without_file(self):
        finding = {"severity": "high", "title": "Open redirect"}
        s = _build_summary(finding)
        assert "[HIGH]" in s
        assert "Open redirect" in s
        assert "—" not in s

    def test_build_summary_fallback_name(self):
        finding = {"severity": "high", "name": "my-vuln"}
        s = _build_summary(finding)
        assert "my-vuln" in s

    def test_build_description_adf(self):
        desc = _build_description(CRITICAL_FINDING, dashboard_url="https://dash.example.com")
        assert desc["type"] == "doc"
        assert desc["version"] == 1
        text_content = json.dumps(desc)
        assert "critical" in text_content.lower()
        assert "semgrep" in text_content
        assert "sqli-001" in text_content
        assert "app/auth.py" in text_content
        assert "parameterized queries" in text_content
        assert "https://dash.example.com" in text_content

    def test_build_description_minimal(self):
        finding = {"severity": "high", "title": "Problem"}
        desc = _build_description(finding)
        assert desc["type"] == "doc"
        assert len(desc["content"]) >= 2

    def test_build_resolved_comment(self):
        comment = _build_resolved_comment()
        assert comment["type"] == "doc"
        text = json.dumps(comment)
        assert "no longer detected" in text

    def test_should_sync_critical(self):
        assert should_sync([CRITICAL_FINDING]) is True

    def test_should_sync_high(self):
        assert should_sync([HIGH_FINDING]) is True

    def test_should_sync_medium_only(self):
        assert should_sync([MEDIUM_FINDING]) is False

    def test_should_sync_empty(self):
        assert should_sync([]) is False

    def test_should_sync_mixed(self):
        assert should_sync([LOW_FINDING, HIGH_FINDING]) is True


# ---------------------------------------------------------------------------
# JiraClient
# ---------------------------------------------------------------------------


class TestJiraClient:
    def test_auth_header(self, jira_config):
        client = JiraClient(jira_config)
        assert client._auth_header.startswith("Basic ")

    @patch("ez_appsec.jira_sync.urllib.request.urlopen")
    def test_create_issue_success(self, mock_urlopen, jira_config):
        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = json.dumps({"key": "SEC-42", "id": "12345"}).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = JiraClient(jira_config)
        ok, data = client.create_issue(
            summary="Test issue",
            description={"version": 1, "type": "doc", "content": []},
        )
        assert ok is True
        assert data["key"] == "SEC-42"

    @patch("ez_appsec.jira_sync.urllib.request.urlopen")
    def test_create_issue_with_labels_and_priority(self, mock_urlopen, jira_config):
        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = json.dumps({"key": "SEC-43"}).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = JiraClient(jira_config)
        ok, data = client.create_issue(
            summary="Test",
            description={"version": 1, "type": "doc", "content": []},
            labels=["security"],
            priority="High",
        )
        assert ok is True

        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        body = json.loads(req.data.decode())
        assert body["fields"]["labels"] == ["security"]
        assert body["fields"]["priority"]["name"] == "High"

    @patch("ez_appsec.jira_sync.urllib.request.urlopen")
    def test_create_issue_failure(self, mock_urlopen, jira_config):
        error = urllib.error.HTTPError(
            url="https://test.atlassian.net/rest/api/3/issue",
            code=400,
            msg="Bad Request",
            hdrs={},
            fp=MagicMock(read=MagicMock(return_value=b'{"errorMessages":["oops"]}')),
        )
        mock_urlopen.side_effect = error

        client = JiraClient(jira_config)
        ok, data = client.create_issue(
            summary="Test", description={"version": 1, "type": "doc", "content": []}
        )
        assert ok is False

    @patch("ez_appsec.jira_sync.urllib.request.urlopen")
    def test_transition_issue_success(self, mock_urlopen, jira_config):
        transitions_resp = MagicMock()
        transitions_resp.status = 200
        transitions_resp.read.return_value = json.dumps(
            {"transitions": [{"id": "31", "name": "Done"}, {"id": "21", "name": "In Progress"}]}
        ).encode()
        transitions_resp.__enter__ = MagicMock(return_value=transitions_resp)
        transitions_resp.__exit__ = MagicMock(return_value=False)

        transition_resp = MagicMock()
        transition_resp.status = 204
        transition_resp.read.return_value = b""
        transition_resp.__enter__ = MagicMock(return_value=transition_resp)
        transition_resp.__exit__ = MagicMock(return_value=False)

        mock_urlopen.side_effect = [transitions_resp, transition_resp]

        client = JiraClient(jira_config)
        ok, data = client.transition_issue("SEC-1", "Done")
        assert ok is True

    @patch("ez_appsec.jira_sync.urllib.request.urlopen")
    def test_transition_not_found(self, mock_urlopen, jira_config):
        transitions_resp = MagicMock()
        transitions_resp.status = 200
        transitions_resp.read.return_value = json.dumps(
            {"transitions": [{"id": "21", "name": "In Progress"}]}
        ).encode()
        transitions_resp.__enter__ = MagicMock(return_value=transitions_resp)
        transitions_resp.__exit__ = MagicMock(return_value=False)

        mock_urlopen.return_value = transitions_resp

        client = JiraClient(jira_config)
        ok, data = client.transition_issue("SEC-1", "Done")
        assert ok is False
        assert "not found" in data["error"].lower()

    @patch("ez_appsec.jira_sync.urllib.request.urlopen")
    def test_get_issue(self, mock_urlopen, jira_config):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({"key": "SEC-1", "fields": {}}).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = JiraClient(jira_config)
        ok, data = client.get_issue("SEC-1")
        assert ok is True
        assert data["key"] == "SEC-1"

    @patch("ez_appsec.jira_sync.urllib.request.urlopen")
    def test_add_comment(self, mock_urlopen, jira_config):
        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = json.dumps({"id": "10001"}).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = JiraClient(jira_config)
        ok, data = client.add_comment("SEC-1", _build_resolved_comment())
        assert ok is True

    @patch("ez_appsec.jira_sync.urllib.request.urlopen")
    def test_network_error(self, mock_urlopen, jira_config):
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        client = JiraClient(jira_config)
        ok, data = client.create_issue(
            summary="Test", description={"version": 1, "type": "doc", "content": []}
        )
        assert ok is False
        assert "error" in data


# ---------------------------------------------------------------------------
# sync_findings
# ---------------------------------------------------------------------------


class TestSyncFindings:
    def _mock_client(self, mock_urlopen, create_keys=None, transition_ok=True):
        """Set up urlopen to respond to create/transitions/comment calls."""
        create_keys = create_keys or ["SEC-1", "SEC-2", "SEC-3"]
        call_count = {"n": 0}

        def side_effect(req, timeout=30):
            url = req.get_full_url() if hasattr(req, "get_full_url") else req.full_url
            method = req.get_method()
            resp = MagicMock()
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=False)

            if method == "POST" and "/issue" in url and "/transitions" not in url and "/comment" not in url:
                idx = min(call_count["n"], len(create_keys) - 1)
                key = create_keys[idx]
                call_count["n"] += 1
                resp.status = 201
                resp.read.return_value = json.dumps({"key": key}).encode()
            elif "transitions" in url and method == "GET":
                resp.status = 200
                resp.read.return_value = json.dumps(
                    {"transitions": [{"id": "31", "name": "Done"}]}
                ).encode()
            elif "transitions" in url and method == "POST":
                resp.status = 204 if transition_ok else 400
                resp.read.return_value = b""
            elif "comment" in url:
                resp.status = 201
                resp.read.return_value = json.dumps({"id": "10001"}).encode()
            else:
                resp.status = 200
                resp.read.return_value = b"{}"
            return resp

        mock_urlopen.side_effect = side_effect

    @patch("ez_appsec.jira_sync.urllib.request.urlopen")
    def test_creates_issues_for_crit_high(self, mock_urlopen, jira_config, tmp_map):
        self._mock_client(mock_urlopen, create_keys=["SEC-1", "SEC-2"])

        findings = [CRITICAL_FINDING, HIGH_FINDING, MEDIUM_FINDING, LOW_FINDING]
        result = sync_findings(findings, jira_config, tmp_map)

        assert len(result["created"]) == 2
        assert "SEC-1" in result["created"]
        assert "SEC-2" in result["created"]
        assert result["errors"] == []

    @patch("ez_appsec.jira_sync.urllib.request.urlopen")
    def test_skips_duplicates(self, mock_urlopen, jira_config, tmp_map):
        self._mock_client(mock_urlopen, create_keys=["SEC-1"])

        findings = [CRITICAL_FINDING]
        result1 = sync_findings(findings, jira_config, tmp_map)
        assert len(result1["created"]) == 1

        self._mock_client(mock_urlopen, create_keys=["SEC-99"])
        result2 = sync_findings(findings, jira_config, tmp_map)
        assert len(result2["created"]) == 0
        assert len(result2["skipped_existing"]) == 1
        assert "SEC-1" in result2["skipped_existing"]

    @patch("ez_appsec.jira_sync.urllib.request.urlopen")
    def test_closes_resolved_findings(self, mock_urlopen, jira_config, tmp_map):
        self._mock_client(mock_urlopen, create_keys=["SEC-1"])
        sync_findings([CRITICAL_FINDING], jira_config, tmp_map)

        self._mock_client(mock_urlopen)
        result = sync_findings([], jira_config, tmp_map, close_resolved=True)
        assert "SEC-1" in result["closed"]

    @patch("ez_appsec.jira_sync.urllib.request.urlopen")
    def test_close_resolved_disabled(self, mock_urlopen, jira_config, tmp_map):
        self._mock_client(mock_urlopen, create_keys=["SEC-1"])
        sync_findings([CRITICAL_FINDING], jira_config, tmp_map)

        self._mock_client(mock_urlopen)
        result = sync_findings([], jira_config, tmp_map, close_resolved=False)
        assert result["closed"] == []

    @patch("ez_appsec.jira_sync.urllib.request.urlopen")
    def test_persists_map(self, mock_urlopen, jira_config, tmp_map):
        self._mock_client(mock_urlopen, create_keys=["SEC-1"])
        sync_findings([CRITICAL_FINDING], jira_config, tmp_map)

        m = JiraIssueMap(tmp_map)
        fp = _fingerprint(CRITICAL_FINDING)
        assert m.get(fp) == "SEC-1"

    @patch("ez_appsec.jira_sync.urllib.request.urlopen")
    def test_dashboard_url_in_description(self, mock_urlopen, jira_config, tmp_map):
        self._mock_client(mock_urlopen, create_keys=["SEC-1"])
        sync_findings(
            [CRITICAL_FINDING], jira_config, tmp_map,
            dashboard_url="https://dash.example.com",
        )

        call_args_list = mock_urlopen.call_args_list
        for call in call_args_list:
            req = call[0][0]
            if req.get_method() == "POST" and "/issue" in req.get_full_url():
                body = json.loads(req.data.decode())
                desc_text = json.dumps(body["fields"]["description"])
                assert "https://dash.example.com" in desc_text
                break

    @patch("ez_appsec.jira_sync.urllib.request.urlopen")
    def test_empty_findings(self, mock_urlopen, jira_config, tmp_map):
        result = sync_findings([], jira_config, tmp_map)
        assert result["created"] == []
        assert result["errors"] == []
        mock_urlopen.assert_not_called()
