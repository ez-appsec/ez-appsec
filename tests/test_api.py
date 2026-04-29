"""Tests for the ez-appsec REST API (PLAN-14)."""

import os
from unittest.mock import patch

import pytest
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
