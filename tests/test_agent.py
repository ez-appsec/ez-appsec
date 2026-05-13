"""Tests for security agent core (PLAN-21)"""

import json
import os
import pytest
from unittest.mock import patch, MagicMock, PropertyMock
from dataclasses import dataclass

from ez_appsec.agent import (
    SecurityAgent,
    AgentResult,
    ToolRegistry,
    agent_tool_registry,
    redact_secrets,
    _validate_path,
    MAX_TASK_LENGTH,
)


class TestToolRegistry:
    def test_register_and_get(self):
        reg = ToolRegistry()
        fn = lambda: "ok"
        reg.register("my_tool", fn, {"description": "test"})
        entry = reg.get("my_tool")
        assert entry is not None
        assert entry["fn"]() == "ok"

    def test_names(self):
        reg = ToolRegistry()
        reg.register("a", lambda: None, {})
        reg.register("b", lambda: None, {})
        assert sorted(reg.names()) == ["a", "b"]

    def test_to_anthropic_tools(self):
        reg = ToolRegistry()
        reg.register("scan", lambda: None, {
            "description": "Scan stuff",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        })
        tools = reg.to_anthropic_tools()
        assert len(tools) == 1
        assert tools[0]["name"] == "scan"
        assert tools[0]["input_schema"]["properties"]["path"]["type"] == "string"

    def test_get_unknown_returns_none(self):
        reg = ToolRegistry()
        assert reg.get("nonexistent") is None


class TestSecurityAgent:
    def test_register_tool_adds_to_registry(self):
        agent = SecurityAgent()
        agent.register_tool("custom", lambda: "custom_result", {"description": "custom"})
        assert "custom" in agent.registry.names()

    def test_builtin_tools_registered(self):
        agent = SecurityAgent()
        expected = {"scan_directory", "read_findings", "search_findings",
                    "explain_finding", "suggest_fix", "check_status"}
        assert expected.issubset(set(agent.registry.names()))

    def test_empty_task_raises(self):
        agent = SecurityAgent()
        with pytest.raises(ValueError, match="cannot be empty"):
            agent.run("")

    def test_whitespace_task_raises(self):
        agent = SecurityAgent()
        with pytest.raises(ValueError, match="cannot be empty"):
            agent.run("   ")

    def test_task_too_long_raises(self):
        agent = SecurityAgent()
        with pytest.raises(ValueError, match="maximum length"):
            agent.run("x" * (MAX_TASK_LENGTH + 1))

    def test_missing_anthropic_sdk(self):
        agent = SecurityAgent()
        with patch.dict("sys.modules", {"anthropic": None}):
            with patch("builtins.__import__", side_effect=ImportError("No module named 'anthropic'")):
                result = agent.run("scan /tmp")
        assert "not installed" in result.summary

    def test_missing_api_key(self):
        agent = SecurityAgent()
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}, clear=False):
            with patch("builtins.__import__", return_value=MagicMock()):
                result = agent.run("scan something")
        assert "ANTHROPIC_API_KEY" in result.summary

    def test_run_tool_use_loop(self):
        mock_anthropic = MagicMock()
        mock_client = MagicMock()

        tool_use_block = MagicMock()
        tool_use_block.type = "tool_use"
        tool_use_block.name = "check_status"
        tool_use_block.input = {}
        tool_use_block.id = "tool_1"

        tool_response = MagicMock()
        tool_response.stop_reason = "tool_use"
        tool_response.content = [tool_use_block]

        text_block = MagicMock()
        text_block.type = "text"
        text_block.text = "Scan complete. No issues found."

        final_response = MagicMock()
        final_response.stop_reason = "end_turn"
        final_response.content = [text_block]

        mock_client.messages.create.side_effect = [tool_response, final_response]
        mock_anthropic.Anthropic.return_value = mock_client

        import sys
        agent = SecurityAgent()

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            with patch.dict(sys.modules, {"anthropic": mock_anthropic}):
                result = agent.run("check scanner status")

        assert "check_status" in result.actions_taken[0]
        assert result.summary == "Scan complete. No issues found."

    def test_scan_and_triage_delegates_to_run(self):
        agent = SecurityAgent()
        with patch.object(agent, "run", return_value=AgentResult(summary="triaged")) as mock_run:
            result = agent.scan_and_triage(".")
            mock_run.assert_called_once()
            assert "triaged" in result.summary


class TestBuiltinTools:
    def test_check_status(self):
        agent = SecurityAgent()
        with patch("ez_appsec.external_scanners.ExternalScannerManager") as mock_mgr_cls:
            mock_mgr = MagicMock()
            mock_mgr.get_installed.return_value = {"gitleaks": True, "semgrep": False}
            mock_mgr_cls.return_value = mock_mgr

            result = agent._tool_check_status()
            assert result["gitleaks"] is True

    def test_search_findings_by_severity(self):
        agent = SecurityAgent()
        agent._last_findings = [
            {"title": "XSS", "severity": "high", "description": ""},
            {"title": "Info leak", "severity": "low", "description": ""},
        ]
        result = agent._tool_search_findings(severity="high")
        assert result["total"] == 1
        assert result["findings"][0]["title"] == "XSS"

    def test_search_findings_by_query(self):
        agent = SecurityAgent()
        agent._last_findings = [
            {"title": "SQL Injection", "severity": "critical", "description": "user input"},
            {"title": "Missing header", "severity": "low", "description": ""},
        ]
        result = agent._tool_search_findings(query="SQL")
        assert result["total"] == 1

    def test_explain_finding_redacts_secrets(self):
        agent = SecurityAgent()
        result = agent._tool_explain_finding(
            title="Exposed AKIAIOSFODNN7EXAMPLE",
            description="Found AWS key",
            severity="critical",
        )
        assert "AKIAIOSFODNN7EXAMPLE" not in result["explanation"]
        assert "[REDACTED]" in result["explanation"]

    def test_read_findings(self, tmp_path):
        findings_file = tmp_path / "vulnerabilities.json"
        findings_file.write_text(json.dumps({
            "vulnerabilities": [
                {"title": "XSS", "severity": "high"},
            ]
        }))
        agent = SecurityAgent(allowed_root=str(tmp_path))
        result = agent._tool_read_findings(str(findings_file))
        assert result["total"] == 1


class TestAgentResult:
    def test_default_values(self):
        r = AgentResult()
        assert r.findings == []
        assert r.actions_taken == []
        assert r.summary == ""
        assert r.raw_messages == []

    def test_fields_set(self):
        r = AgentResult(
            findings=[{"title": "XSS"}],
            actions_taken=["scan_directory(...)"],
            summary="Found 1 issue",
        )
        assert len(r.findings) == 1
        assert r.summary == "Found 1 issue"


class TestCLIAgentCommand:
    @patch("ez_appsec.agent.SecurityAgent")
    def test_agent_command_basic(self, mock_agent_cls):
        from click.testing import CliRunner
        from ez_appsec.cli import main

        mock_agent = MagicMock()
        mock_agent.run.return_value = AgentResult(
            summary="No issues found",
            actions_taken=["check_status({})"],
        )
        mock_agent_cls.return_value = mock_agent

        runner = CliRunner()
        with runner.isolated_filesystem():
            os.makedirs("src", exist_ok=True)
            result = runner.invoke(main, ["agent", "check scanner status"])

        assert result.exit_code == 0
        assert "No issues found" in result.output
