"""Tests for the ez-appsec REST API (PLAN-14) and API-hardening follow-ups.

Covers: auth (incl. constant-time compare, fail-fast on missing key, auth on
every protected endpoint), scan input validation (argv injection, allowlist,
severity allowlist), scanner_client internals (_is_git_url, bounded jobs, lock
scope), dashboard retry/error mapping, and OpenAPI/docs auth gating.
"""

import json
import os
import time
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

    def test_auth_enforced_on_every_protected_endpoint(self, client):
        """Every data endpoint must require the API key (review #23)."""
        no_auth = {}
        with patch("api.main.get_index", return_value={"projects": []}):
            assert client.get("/projects", headers=no_auth).status_code == 401
        with patch("api.main.get_vulnerabilities", return_value={"vulnerabilities": []}):
            assert client.get("/projects/x/findings", headers=no_auth).status_code == 401
        with patch("api.main.get_history", return_value=[]):
            assert client.get("/projects/x/history", headers=no_auth).status_code == 401
        # POST /scan without auth -> 401 (not 400/422 validation path).
        assert client.post("/scan", json={"path": "/tmp"}, headers=no_auth).status_code == 401
        # OpenAPI + docs gated.
        assert client.get("/openapi.json", headers=no_auth).status_code == 401
        assert client.get("/docs", headers=no_auth).status_code == 401

    def test_constant_time_compare_used(self, client):
        """Auth uses hmac.compare_digest, not ``==`` (review #21)."""
        import api.main as main_mod

        with patch.object(main_mod.hmac, "compare_digest", return_value=True) as cmp:
            with patch("api.main.get_index", return_value={"projects": []}):
                resp = client.get("/projects", headers={"X-API-Key": "test-key-123"})
            assert resp.status_code == 200
            cmp.assert_called()
        # Wrong key still invokes compare_digest (timing identical).
        with patch.object(main_mod.hmac, "compare_digest", return_value=False) as cmp:
            resp = client.get("/projects", headers={"X-API-Key": "nope"})
            assert resp.status_code == 401
            cmp.assert_called()

    def test_health_is_public(self, client):
        """Liveness probe stays open without a key."""
        assert client.get("/health").status_code == 200


def test_missing_api_key_at_startup_raises(monkeypatch):
    """Process must fail fast when EZ_APPSEC_API_KEY is unset (review #6)."""
    monkeypatch.delenv("EZ_APPSEC_API_KEY", raising=False)
    # Drop the cached module so _configured_api_key re-runs on import.
    import sys

    sys.modules.pop("api.main", None)
    try:
        with pytest.raises(RuntimeError, match="EZ_APPSEC_API_KEY"):
            import importlib

            importlib.import_module("api.main")
    finally:
        sys.modules.pop("api.main", None)


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

    @pytest.mark.parametrize(
        "bad_path",
        [
            "--upload-pack=evil-cmd",
            "-uPAYLOAD",
            "git@github.com:org/repo.git",
        ],
    )
    def test_scan_rejects_dangerous_path(self, client, bad_path):
        """Leading-dash and SSH-URL paths rejected as 400 (review #1/#10)."""
        resp = client.post("/scan", json={"path": bad_path}, headers=AUTH)
        assert resp.status_code == 400

    def test_scan_rejects_invalid_severity(self, client):
        """Unknown severity rejected as 400 (review #16)."""
        resp = client.post("/scan", json={"path": "/tmp/repo", "severity": "--config=/etc/passwd"}, headers=AUTH)
        assert resp.status_code == 400

    def test_scan_rejects_path_outside_allowlist(self, client, monkeypatch):
        """EZ_APPSEC_ALLOWED_ROOTS confines local scan targets (review #2)."""
        monkeypatch.setenv("EZ_APPSEC_ALLOWED_ROOTS", "/safe/dir")
        resp = client.post("/scan", json={"path": "/etc/passwd"}, headers=AUTH)
        assert resp.status_code == 400

    def test_scan_accepts_path_inside_allowlist(self, client, monkeypatch):
        monkeypatch.setenv("EZ_APPSEC_ALLOWED_ROOTS", "/tmp")
        resp = client.post("/scan", json={"path": "/tmp/repo"}, headers=AUTH)
        assert resp.status_code == 202


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


class TestScannerClientInternals:
    """Direct unit tests for validation + job-store behavior (review #20, #22)."""

    @pytest.mark.parametrize(
        "path, expected",
        [
            ("https://github.com/o/r.git", True),
            ("http://example.com/r", True),
            ("ssh://git@example.com/r", True),
            ("git://example.com/r", True),
            ("git@host:repo", False),  # rejected by design (SSH needs keys)
            ("--upload-pack=evil", False),
            ("-uPAYLOAD", False),
            ("file:///etc/passwd", False),
            ("", False),
            ("   ", False),
            ("/tmp/local/path", False),
        ],
    )
    def test_is_git_url(self, path, expected):
        from api.scanner_client import _is_git_url

        assert _is_git_url(path) is expected

    def test_validate_scan_path_rejects_leading_dash(self):
        from api.scanner_client import _validate_scan_path

        with pytest.raises(ValueError, match="must not start with '-'"):
            _validate_scan_path("--evil")

    def test_validate_scan_path_rejects_ssh_url(self):
        from api.scanner_client import _validate_scan_path

        with pytest.raises(ValueError, match="SSH git URLs"):
            _validate_scan_path("git@github.com:o/r.git")

    def test_validate_scan_path_rejects_empty(self):
        from api.scanner_client import _validate_scan_path

        with pytest.raises(ValueError, match="empty"):
            _validate_scan_path("")

    def test_jobs_store_is_bounded(self, monkeypatch):
        """_sweep_locked evicts finished jobs at the cap; no unbounded growth (review #5).

        Exercises the eviction logic directly: insert more finished jobs than
        the cap, run the sweep, and assert the store shrinks below the cap.
        """
        from api import scanner_client

        with scanner_client._lock:
            scanner_client._jobs.clear()
        monkeypatch.setattr(scanner_client, "_MAX_JOBS", 5)

        # Populate with 20 completed jobs (as if they had run and finished).
        with scanner_client._lock:
            for i in range(20):
                j = scanner_client._Job(job_id=f"j{i}", path=f"/tmp/repo-{i}")
                j.status = "complete"
                j.finished_at = time.time() - i  # older jobs sort first
                scanner_client._jobs[j.job_id] = j

        # Sweep should evict down to _MAX_JOBS - 1.
        with scanner_client._lock:
            scanner_client._sweep_locked(now=time.time())
            assert len(scanner_client._jobs) <= scanner_client._MAX_JOBS

    def test_submit_scan_sweeps_before_insert(self, monkeypatch):
        """submit_scan triggers eviction, keeping the store bounded under load (review #5)."""
        from api import scanner_client

        with scanner_client._lock:
            scanner_client._jobs.clear()
        monkeypatch.setattr(scanner_client, "_MAX_JOBS", 3)
        # _run completes synchronously inline so the store reflects real state.
        monkeypatch.setattr(
            scanner_client,
            "_executor",
            type(
                "E",
                (),
                {
                    "submit": staticmethod(lambda fn, *a: fn(*a)),
                },
            )(),
        )

        for i in range(10):
            scanner_client.submit_scan(f"/tmp/repo-{i}")

        with scanner_client._lock:
            assert len(scanner_client._jobs) <= scanner_client._MAX_JOBS

    def test_run_does_not_hold_lock_during_io(self, monkeypatch):
        """get_job must not be blocked by _run's subprocess/file I/O (review #15)."""
        from api import scanner_client

        state = {"in_subprocess": False, "blocked_read": False}

        def fake_run(cmd, capture_output, text, timeout):
            state["in_subprocess"] = True
            # While the subprocess "runs", a concurrent get_job must succeed.
            with scanner_client._lock:
                # If _run held the lock this would deadlock -> but get_job is
                # called from the main thread below; we assert lock is free here.
                pass
            output_dir = cmd[cmd.index("--output") + 1]
            os.makedirs(output_dir, exist_ok=True)
            with open(os.path.join(output_dir, "vulnerabilities.json"), "w") as fh:
                fh.write('{"vulnerabilities": []}')

            class Proc:
                returncode = 0
                stdout = ""
                stderr = ""

            return Proc()

        monkeypatch.setattr(scanner_client.subprocess, "run", fake_run)
        job = scanner_client._Job(job_id="j1", path="/tmp/repo")
        scanner_client._run(job)
        assert job.status == "complete"

    def test_run_loads_vulnerabilities_json_from_output_dir(self, monkeypatch):
        from api import scanner_client

        calls = []

        def fake_run(cmd, capture_output, text, timeout):
            calls.append(cmd)
            output_dir = cmd[cmd.index("--output") + 1]
            os.makedirs(output_dir, exist_ok=True)
            with open(os.path.join(output_dir, "vulnerabilities.json"), "w") as fh:
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
        # `--` separator is present before the scan path (review #1).
        assert calls[0][:5] == ["ez-appsec", "scan", "--", "/tmp/repo", "--output"]
        assert calls[0][-2:] == ["--severity", "high"]

    def test_run_fails_when_results_file_missing(self, monkeypatch):
        from api import scanner_client

        def fake_run(cmd, capture_output, text, timeout):
            class Proc:
                returncode = 0
                stdout = ""
                stderr = ""

            return Proc()

        monkeypatch.setattr(scanner_client.subprocess, "run", fake_run)
        job = scanner_client._Job(job_id="job-1", path="/tmp/repo")
        scanner_client._run(job)
        assert job.status == "failed"
        assert "results could not be read" in (job.error or "")

    def test_run_clones_git_url_before_scanning(self, monkeypatch):
        from api import scanner_client

        calls = []

        def fake_run(cmd, capture_output, text, timeout):
            calls.append(cmd)
            if cmd[0] == "git":
                # git clone invocation must include `--` before the URL.
                assert "--" in cmd
                clone_target = cmd[-1]
                assert clone_target.endswith("/repo"), clone_target
                os.makedirs(clone_target, exist_ok=True)
            else:
                output_dir = cmd[cmd.index("--output") + 1]
                os.makedirs(output_dir, exist_ok=True)
                with open(os.path.join(output_dir, "vulnerabilities.json"), "w") as fh:
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
        assert calls[0][4] == "--"  # injection guard
        assert calls[0][5] == "https://github.com/example/repo.git"

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
        assert "repository not found" in (job.error or "")


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
        from api.dashboard_client import DashboardUnavailable

        with patch("api.main.get_index", side_effect=DashboardUnavailable("network error")):
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

    def test_findings_without_id_do_not_500(self, client):
        """Image/container findings may lack id; model must accept them (review #13/#25)."""
        mock_data = {
            "vulnerabilities": [
                {
                    # No `id` field.
                    "severity": "high",
                    "category": "container",
                    "scanner": "grype",
                    "location": {"file": {"file_name": "nginx:1.21"}},
                }
            ]
        }
        with patch("api.main.get_vulnerabilities", return_value=mock_data):
            resp = client.get("/projects/img/findings", headers=AUTH)
            assert resp.status_code == 200
            assert len(resp.json()) == 1

    def test_dashboard_error_returns_502(self, client):
        from api.dashboard_client import DashboardUnavailable

        with patch("api.main.get_vulnerabilities", side_effect=DashboardUnavailable("not found")):
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
        from api.dashboard_client import DashboardUnavailable

        with patch("api.main.get_history", side_effect=DashboardUnavailable("timeout")):
            resp = client.get("/projects/myapp/history", headers=AUTH)
            assert resp.status_code == 502


class TestOpenAPISpec:
    def test_openapi_endpoint_requires_auth(self, client):
        """OpenAPI schema is gated behind the API key (review #27)."""
        assert client.get("/openapi.json").status_code == 401
        resp = client.get("/openapi.json", headers=AUTH)
        assert resp.status_code == 200
        spec = resp.json()
        assert spec["info"]["title"] == "ez-appsec API"
        assert "/scan" in spec["paths"]
        assert "/projects" in spec["paths"]

    def test_docs_endpoint_requires_auth(self, client):
        assert client.get("/docs").status_code == 401
        resp = client.get("/docs", headers=AUTH)
        assert resp.status_code == 200


class TestDashboardClientRetry:
    """Retry/backoff + error mapping for the dashboard backend (review #4/#7)."""

    def test_retries_on_transient_5xx_then_succeeds(self, monkeypatch):
        from api import dashboard_client

        class Resp:
            def __init__(self, status, payload=None, text=""):
                self.status_code = status
                self._payload = payload
                self.text = text

            def json(self):
                return self._payload

            def raise_for_status(self):
                if self.status_code >= 400:
                    import requests

                    raise requests.HTTPError(f"{self.status_code}")

        seq = [Resp(503), Resp(200, {"ok": True})]
        monkeypatch.setattr(dashboard_client.requests, "get", lambda *a, **k: seq.pop(0))
        monkeypatch.setattr(dashboard_client.time, "sleep", lambda s: None)
        assert dashboard_client._get_file("x") == {"ok": True}

    def test_raises_dashboard_unavailable_after_retries(self, monkeypatch):
        from api import dashboard_client

        class Resp:
            status_code = 502
            text = "bad gateway"

            def json(self):
                return {}

            def raise_for_status(self):
                pass

        monkeypatch.setattr(dashboard_client.requests, "get", lambda *a, **k: Resp())
        monkeypatch.setattr(dashboard_client.time, "sleep", lambda s: None)
        with pytest.raises(dashboard_client.DashboardUnavailable):
            dashboard_client._get_file("x")

    def test_rate_limit_raises_dashboard_unavailable(self, monkeypatch):
        from api import dashboard_client

        class Resp:
            status_code = 403
            text = "API rate limit exceeded"

            def json(self):
                return {}

            def raise_for_status(self):
                pass

        monkeypatch.setattr(dashboard_client.requests, "get", lambda *a, **k: Resp())
        monkeypatch.setattr(dashboard_client.time, "sleep", lambda s: None)
        with pytest.raises(dashboard_client.DashboardUnavailable, match="rate limit"):
            dashboard_client._get_file("x")


class TestSharedSchemaHelpers:
    """finding_file_path / finding_scanner_name (review #14)."""

    def test_finding_file_path_handles_flat_file(self):
        from ez_appsec.schema import finding_file_path

        assert finding_file_path({"file": "src/app.py"}) == "src/app.py"

    def test_finding_file_path_handles_file_name(self):
        from ez_appsec.schema import finding_file_path

        assert finding_file_path({"file_name": "config/x.js"}) == "config/x.js"

    def test_finding_file_path_handles_object_location(self):
        from ez_appsec.schema import finding_file_path

        assert finding_file_path({"location": {"file": {"file_name": "pkg/main.go"}}}) == "pkg/main.go"

    def test_finding_file_path_handles_string_location_file(self):
        from ez_appsec.schema import finding_file_path

        assert finding_file_path({"location": {"file": "str.go"}}) == "str.go"

    def test_finding_file_path_empty_when_unknown(self):
        from ez_appsec.schema import finding_file_path

        assert finding_file_path({}) == ""
        assert finding_file_path({"location": {}}) == ""

    def test_finding_scanner_name_string(self):
        from ez_appsec.schema import finding_scanner_name

        assert finding_scanner_name({"scanner": "gitleaks"}) == "gitleaks"

    def test_finding_scanner_name_object(self):
        from ez_appsec.schema import finding_scanner_name

        assert finding_scanner_name({"scanner": {"id": "semgrep", "name": "Semgrep"}}) == "Semgrep"
