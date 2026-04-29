"""Tests for multi-tenant organization management (PLAN-18)"""

import base64
import json
import os
import pytest
from unittest.mock import patch, MagicMock, call

from ez_appsec.org_manager import OrgManager, _build_scan_workflow


SAMPLE_REPOS = [
    {"full_name": "myorg/app-api", "archived": False, "fork": False},
    {"full_name": "myorg/web-frontend", "archived": False, "fork": False},
    {"full_name": "myorg/legacy-tool", "archived": True, "fork": False},
    {"full_name": "myorg/forked-lib", "archived": False, "fork": True},
]

ORG_CONFIG_YAML = """\
severity: high
languages:
  - python
  - javascript
policy:
  - severity: critical
    action: fail
    max_count: 0
"""

REPO_CONFIG_YAML = """\
severity: medium
languages:
  - python
  - go
"""


def _make_content_response(content_str: str) -> dict:
    """Build a GitHub API content response with base64 encoding."""
    return {
        "content": base64.b64encode(content_str.encode()).decode(),
        "encoding": "base64",
    }


class TestDiscoverRepos:
    @patch.object(OrgManager, "_github_get_paginated")
    def test_returns_non_archived_non_fork_repos(self, mock_get):
        mock_get.return_value = SAMPLE_REPOS
        mgr = OrgManager("myorg", "fake-token")
        repos = mgr.discover_repos()
        assert repos == ["myorg/app-api", "myorg/web-frontend"]

    @patch.object(OrgManager, "_github_get_paginated")
    def test_empty_org_returns_empty_list(self, mock_get):
        mock_get.return_value = []
        mgr = OrgManager("emptyorg", "fake-token")
        assert mgr.discover_repos() == []

    @patch.object(OrgManager, "_github_get_paginated")
    def test_all_archived_returns_empty(self, mock_get):
        mock_get.return_value = [
            {"full_name": "org/a", "archived": True, "fork": False},
        ]
        mgr = OrgManager("org", "fake-token")
        assert mgr.discover_repos() == []


class TestMergeConfigs:
    def test_repo_key_overrides_org_key(self):
        org = {"severity": "high", "languages": ["python"]}
        repo = {"severity": "medium"}
        merged = OrgManager.merge_configs(org, repo)
        assert merged["severity"] == "medium"

    def test_missing_repo_key_inherits_from_org(self):
        org = {"severity": "high", "policy": [{"action": "fail"}]}
        repo = {"severity": "medium"}
        merged = OrgManager.merge_configs(org, repo)
        assert merged["policy"] == [{"action": "fail"}]
        assert merged["severity"] == "medium"

    def test_repo_only_keys_preserved(self):
        org = {"severity": "high"}
        repo = {"custom_setting": True}
        merged = OrgManager.merge_configs(org, repo)
        assert merged["severity"] == "high"
        assert merged["custom_setting"] is True

    def test_empty_org_config(self):
        org = {}
        repo = {"severity": "low"}
        merged = OrgManager.merge_configs(org, repo)
        assert merged == {"severity": "low"}

    def test_empty_repo_config(self):
        org = {"severity": "high", "languages": ["python"]}
        repo = {}
        merged = OrgManager.merge_configs(org, repo)
        assert merged == {"severity": "high", "languages": ["python"]}

    def test_both_empty(self):
        assert OrgManager.merge_configs({}, {}) == {}

    def test_does_not_mutate_inputs(self):
        org = {"severity": "high", "nested": {"a": 1}}
        repo = {"severity": "low"}
        org_copy = json.loads(json.dumps(org))
        OrgManager.merge_configs(org, repo)
        assert org == org_copy


class TestDryRun:
    @patch.object(OrgManager, "get_repo_config", return_value={})
    @patch.object(OrgManager, "get_org_config", return_value={"severity": "high"})
    @patch.object(OrgManager, "discover_repos", return_value=["myorg/app-api", "myorg/web-frontend"])
    def test_dry_run_makes_no_api_write_calls(self, mock_discover, mock_org_cfg, mock_repo_cfg):
        mgr = OrgManager("myorg", "fake-token")

        with patch.object(mgr, "_github_put") as mock_put:
            results = mgr.dry_run()
            mock_put.assert_not_called()

        assert len(results) == 2
        for r in results:
            assert r["dry_run"] is True
            assert any("would" in a for a in r["actions"])

    @patch.object(OrgManager, "get_repo_config", return_value={})
    @patch.object(OrgManager, "get_org_config", return_value={})
    @patch.object(OrgManager, "discover_repos", return_value=[])
    def test_dry_run_empty_org(self, mock_discover, mock_org_cfg, mock_repo_cfg):
        mgr = OrgManager("emptyorg", "fake-token")
        results = mgr.dry_run()
        assert results == []


class TestInstallRepo:
    @patch.object(OrgManager, "get_repo_config", return_value={})
    @patch.object(OrgManager, "get_org_config", return_value={"severity": "high"})
    def test_dry_run_returns_plan(self, mock_org, mock_repo):
        mgr = OrgManager("myorg", "fake-token")
        result = mgr.install_repo("myorg/app-api", dry_run=True)
        assert result["dry_run"] is True
        assert result["repo"] == "myorg/app-api"
        assert len(result["actions"]) > 0

    @patch.object(OrgManager, "_github_put")
    @patch.object(OrgManager, "_github_get")
    @patch.object(OrgManager, "get_repo_config", return_value={})
    @patch.object(OrgManager, "get_org_config", return_value={"severity": "high"})
    def test_install_creates_workflow(self, mock_org, mock_repo, mock_get, mock_put):
        from urllib.error import HTTPError
        mock_get.side_effect = HTTPError(
            url="", code=404, msg="Not Found", hdrs=None, fp=None
        )
        mock_put.return_value = {"content": {"sha": "abc123"}}

        mgr = OrgManager("myorg", "fake-token")
        result = mgr.install_repo("myorg/app-api")

        assert result["dry_run"] is False
        mock_put.assert_called_once()
        put_url = mock_put.call_args[0][0]
        assert "ez-appsec-scan.yml" in put_url


class TestSyncAll:
    @patch.object(OrgManager, "install_repo")
    @patch.object(OrgManager, "discover_repos", return_value=["myorg/a", "myorg/b"])
    def test_sync_all_dry_run(self, mock_discover, mock_install):
        mock_install.return_value = {"repo": "myorg/a", "actions": ["would update"], "dry_run": True}
        mgr = OrgManager("myorg", "fake-token")
        results = mgr.sync_all(dry_run=True)
        assert len(results) == 2
        mock_install.assert_called_with("myorg/b", dry_run=True)

    @patch.object(OrgManager, "install_repo")
    @patch.object(OrgManager, "discover_repos", return_value=["myorg/a"])
    def test_sync_all_handles_errors(self, mock_discover, mock_install):
        mock_install.side_effect = RuntimeError("API rate limited")
        mgr = OrgManager("myorg", "fake-token")
        results = mgr.sync_all()
        assert len(results) == 1
        assert "error" in results[0]


class TestBuildScanWorkflow:
    def test_default_severity(self):
        wf = _build_scan_workflow({})
        assert "--severity medium" in wf

    def test_custom_severity(self):
        wf = _build_scan_workflow({"severity": "high"})
        assert "--severity high" in wf

    def test_workflow_structure(self):
        wf = _build_scan_workflow({"severity": "critical"})
        assert "name: ez-appsec Security Scan" in wf
        assert "actions/checkout@v4" in wf
        assert "upload-sarif" in wf
        assert "cron:" in wf


class TestCLIOrgSync:
    @patch("ez_appsec.org_manager.OrgManager.sync_all")
    @patch("ez_appsec.org_manager.OrgManager.discover_repos")
    def test_org_sync_dry_run(self, mock_discover, mock_sync):
        from click.testing import CliRunner
        from ez_appsec.cli import main

        mock_sync.return_value = [
            {"repo": "myorg/app", "actions": ["would update workflow"], "dry_run": True},
        ]

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["org-sync", "--org", "myorg", "--dry-run"],
            env={"GITHUB_TOKEN": "fake-token"},
        )

        assert result.exit_code == 0
        assert "would update workflow" in result.output

    def test_org_sync_no_token(self):
        from click.testing import CliRunner
        from ez_appsec.cli import main

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["org-sync", "--org", "myorg"],
            env={"GITHUB_TOKEN": "", "GH_TOKEN": ""},
        )

        assert result.exit_code == 1
        assert "GITHUB_TOKEN" in result.output

    @patch("ez_appsec.org_manager.OrgManager.sync_all")
    def test_org_sync_no_repos(self, mock_sync):
        from click.testing import CliRunner
        from ez_appsec.cli import main

        mock_sync.return_value = []

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["org-sync", "--org", "emptyorg"],
            env={"GITHUB_TOKEN": "fake-token"},
        )

        assert result.exit_code == 0
        assert "No repositories found" in result.output
