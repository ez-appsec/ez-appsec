"""Tests for the ez-appsec REST API (PLAN-14)."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _set_api_key(monkeypatch):
    monkeypatch.setenv("EZ_APPSEC_API_KEY", "test-key-123")


@pytest.fixture()
def client():
    from api.main import app

    return TestClient(app)


AUTH = {"X-API-Key": "test-key-123"}


class TestAuthMiddleware:
    def test_missing_key_returns_401(self, client):
        resp = client.get("/projects")
        assert resp.status_code == 401

    def test_wrong_key_returns_401(self, client):
        resp = client.get("/projects", headers={"X-API-Key": "wrong"})
        assert resp.status_code == 401

    def test_valid_key_passes(self, client):
        with patch("api.main.get_index", return_value={"projects": []}):
            resp = client.get("/projects", headers=AUTH)
            assert resp.status_code == 200

    def test_unconfigured_key_returns_500(self, client, monkeypatch):
        monkeypatch.delenv("EZ_APPSEC_API_KEY")
        resp = client.get("/projects", headers={"X-API-Key": "anything"})
        assert resp.status_code == 500


class TestPostScan:
    def test_scan_returns_202_with_job_id(self, client):
        resp = client.post("/scan", json={"path": "/tmp/repo"}, headers=AUTH)
        assert resp.status_code == 202
        body = resp.json()
        assert "job_id" in body
        assert body["status"] == "queued"

    def test_scan_requires_path(self, client):
        resp = client.post("/scan", json={}, headers=AUTH)
        assert resp.status_code == 422


class TestScanStatus:
    def test_unknown_job_returns_404(self, client):
        resp = client.get("/scan/nonexistent", headers=AUTH)
        assert resp.status_code == 404

    def test_known_job_returns_status(self, client):
        post_resp = client.post("/scan", json={"path": "/tmp/repo"}, headers=AUTH)
        job_id = post_resp.json()["job_id"]
        resp = client.get(f"/scan/{job_id}", headers=AUTH)
        assert resp.status_code == 200
        assert resp.json()["job_id"] == job_id


class TestScannerClient:
    def test_run_loads_vulnerabilities_json_from_output_dir(self, monkeypatch):
        from api import scanner_client

        calls = []

        def fake_run(cmd, capture_output, text, timeout):
            calls.append(cmd)
            output_dir = cmd[cmd.index("--output") + 1]
            os.makedirs(output_dir, exist_ok=True)
            with open(os.path.join(output_dir, "vulnerabilities.json"), "w", encoding="utf-8") as fh:
                fh.write('{"vulnerabilities": [{"id": "finding-1"}], "summary": {"total": 1}}')

            class Proc:
                returncode = 0
                stdout = "human readable summary"
                stderr = ""

            return Proc()

        monkeypatch.setattr(scanner_client.subprocess, "run", fake_run)
        job = scanner_client._Job(job_id="job-1", path="/tmp/repo", severity="high")

        scanner_client._run(job)

        assert job.status == "complete"
        assert job.result == {"vulnerabilities": [{"id": "finding-1"}], "summary": {"total": 1}}
        assert calls[0][:4] == ["ez-appsec", "scan", "/tmp/repo", "--output"]
        assert calls[0][-2:] == ["--severity", "high"]

    def test_run_fails_when_results_file_missing(self, monkeypatch):
        from api import scanner_client

        def fake_run(cmd, capture_output, text, timeout):
            class Proc:
                returncode = 0
                stdout = "human readable summary"
                stderr = ""

            return Proc()

        monkeypatch.setattr(scanner_client.subprocess, "run", fake_run)
        job = scanner_client._Job(job_id="job-1", path="/tmp/repo")

        scanner_client._run(job)

        assert job.status == "failed"
        assert "results could not be read" in job.error


    def test_run_clones_git_url_before_scanning(self, monkeypatch):
        from api import scanner_client

        calls = []

        def fake_run(cmd, capture_output, text, timeout):
            calls.append(cmd)
            if cmd[0] == "git":
                os.makedirs(cmd[-1], exist_ok=True)
            else:
                output_dir = cmd[cmd.index("--output") + 1]
                os.makedirs(output_dir, exist_ok=True)
                with open(os.path.join(output_dir, "vulnerabilities.json"), "w", encoding="utf-8") as fh:
                    fh.write('{"vulnerabilities": []}')

            class Proc:
                returncode = 0
                stdout = ""
                stderr = ""

            return Proc()

        monkeypatch.setattr(scanner_client.subprocess, "run", fake_run)
        job = scanner_client._Job(job_id="job-1", path="https://github.com/example/repo.git")

        scanner_client._run(job)

        assert job.status == "complete"
        assert calls[0][:4] == ["git", "clone", "--depth", "1"]
        assert calls[0][4] == "https://github.com/example/repo.git"
        assert calls[1][0:2] == ["ez-appsec", "scan"]
        assert calls[1][2].endswith("/repo")

    def test_run_reports_git_clone_failure(self, monkeypatch):
        from api import scanner_client

        def fake_run(cmd, capture_output, text, timeout):
            class Proc:
                returncode = 1
                stdout = ""
                stderr = "repository not found"

            return Proc()

        monkeypatch.setattr(scanner_client.subprocess, "run", fake_run)
        job = scanner_client._Job(job_id="job-1", path="https://github.com/example/missing.git")

        scanner_client._run(job)

        assert job.status == "failed"
        assert "repository not found" in job.error


class TestGetProjects:
    def test_returns_project_list(self, client):
        mock_index = {
            "projects": [
                {
                    "slug": "myapp",
                    "name": "myapp",
                    "project_path": "org/myapp",
                    "github_url": "https://github.com/org/myapp",
                    "last_updated": "2026-01-01T00:00:00Z",
                    "summary": {"total": 5, "critical": 1, "high": 2, "medium": 1, "low": 1},
                }
            ]
        }
        with patch("api.main.get_index", return_value=mock_index):
            resp = client.get("/projects", headers=AUTH)
            assert resp.status_code == 200
            projects = resp.json()
            assert len(projects) == 1
            assert projects[0]["slug"] == "myapp"

    def test_dashboard_error_returns_502(self, client):
        with patch("api.main.get_index", side_effect=Exception("network error")):
            resp = client.get("/projects", headers=AUTH)
            assert resp.status_code == 502


class TestGetFindings:
    def test_returns_vulnerabilities(self, client):
        mock_data = {
            "version": "15.0.0",
            "vulnerabilities": [
                {
                    "id": "abc-123",
                    "category": "sast",
                    "name": "SQL Injection",
                    "message": "Possible SQL injection",
                    "description": "User input flows into query",
                    "cve": "CVE-2024-1234",
                    "severity": "high",
                    "confidence": "high",
                    "solution": "Use parameterized queries",
                    "scanner": {"id": "semgrep", "name": "Semgrep"},
                    "location": {
                        "file": {"file_name": "app.py", "line": 42},
                        "start_line": 42,
                        "end_line": 42,
                    },
                    "identifiers": [{"type": "cve", "name": "CVE-2024-1234", "value": "CVE-2024-1234"}],
                    "links": [],
                }
            ],
        }
        with patch("api.main.get_vulnerabilities", return_value=mock_data):
            resp = client.get("/projects/myapp/findings", headers=AUTH)
            assert resp.status_code == 200
            vulns = resp.json()
            assert len(vulns) == 1
            assert vulns[0]["severity"] == "high"

    def test_dashboard_error_returns_502(self, client):
        with patch("api.main.get_vulnerabilities", side_effect=Exception("not found")):
            resp = client.get("/projects/bad/findings", headers=AUTH)
            assert resp.status_code == 502


    def test_findings_accept_dashboard_fixture_shape(self, client):
        fixture = json.loads(Path("web/data/vulnerabilities.json").read_text())
        with patch("api.main.get_vulnerabilities", return_value=fixture):
            resp = client.get("/projects/juice-shop/findings", headers=AUTH)

        assert resp.status_code == 200
        findings = resp.json()
        assert findings
        assert findings[0]["scanner"] == "gitleaks"
        assert findings[0]["file_name"] == "config/awsConfig.js"

    def test_findings_filter_by_severity_category_scanner_and_file(self, client):
        mock_data = {
            "vulnerabilities": [
                {
                    "id": "1",
                    "severity": "critical",
                    "category": "secrets",
                    "scanner": "gitleaks",
                    "file_name": "config/awsConfig.js",
                },
                {
                    "id": "2",
                    "severity": "high",
                    "category": "sast",
                    "scanner": {"id": "semgrep", "name": "semgrep"},
                    "file_name": "src/app.py",
                },
            ]
        }
        with patch("api.main.get_vulnerabilities", return_value=mock_data):
            resp = client.get(
                "/projects/myapp/findings?severity=critical&category=secrets&scanner=gitleaks&file=aws",
                headers=AUTH,
            )

        assert resp.status_code == 200
        assert [finding["id"] for finding in resp.json()] == ["1"]


class TestGetHistory:
    def test_returns_history_entries(self, client):
        mock_data = [
            {"date": "2026-01-01T00:00:00Z", "total": 10, "critical": 1, "high": 2, "medium": 5, "low": 2},
            {"date": "2026-01-02T00:00:00Z", "total": 8, "critical": 0, "high": 2, "medium": 4, "low": 2},
        ]
        with patch("api.main.get_history", return_value=mock_data):
            resp = client.get("/projects/myapp/history", headers=AUTH)
            assert resp.status_code == 200
            entries = resp.json()
            assert len(entries) == 2
            assert entries[0]["total"] == 10

    def test_dashboard_error_returns_502(self, client):
        with patch("api.main.get_history", side_effect=Exception("timeout")):
            resp = client.get("/projects/myapp/history", headers=AUTH)
            assert resp.status_code == 502


class TestOpenAPISpec:
    def test_openapi_endpoint_exists(self, client):
        resp = client.get("/openapi.json", headers=AUTH)
        assert resp.status_code == 200
        spec = resp.json()
        assert spec["info"]["title"] == "ez-appsec API"
        assert "/scan" in spec["paths"]
        assert "/projects" in spec["paths"]
