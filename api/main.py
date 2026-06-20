"""FastAPI application — ez-appsec REST API."""

from __future__ import annotations

import hmac
import json
import os
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Security
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.security import APIKeyHeader

from api.dashboard_client import DashboardUnavailable, get_history, get_index, get_vulnerabilities
from api.models import HistoryEntry, Project, ScanJob, ScanRequest, Vulnerability
from api.scanner_client import get_job, submit_scan
from ez_appsec.schema import finding_file_path, finding_scanner_name


def _configured_api_key() -> str:
    """Return the configured API key or fail fast.

    Failing at startup means misconfiguration surfaces in container logs
    immediately rather than as a 500 on the first authenticated request.
    """
    expected = os.environ.get("EZ_APPSEC_API_KEY", "")
    if not expected:
        raise RuntimeError("EZ_APPSEC_API_KEY must be set before starting the API")
    return expected


# Eager validation: if the key is unset the process should not serve traffic.
_API_KEY = _configured_api_key()

# Disable FastAPI's default unauthenticated /openapi.json and /docs routes; we
# re-register them below behind the same API key so the schema is not exposed.
app = FastAPI(
    title="ez-appsec API",
    description="REST API for querying security findings and triggering scans.",
    version="0.1.0",
    openapi_url=None,
    docs_url=None,
    redoc_url=None,
)

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _verify_api_key(key: str | None = Security(_api_key_header)) -> str:
    # Constant-time comparison avoids timing-based key enumeration. The
    # compare_digest call always runs so timing is identical on pass/fail.
    provided = key or ""
    if not hmac.compare_digest(provided, _API_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return key or ""


def _matches_filters(
    finding: dict[str, Any],
    severity: str | None,
    category: str | None,
    scanner: str | None,
    file: str | None,
) -> bool:
    if severity and str(finding.get("severity", "")).lower() != severity.lower():
        return False
    if category and str(finding.get("category", "")).lower() != category.lower():
        return False
    if scanner and finding_scanner_name(finding).lower() != scanner.lower():
        return False
    # Case-insensitive substring match on the finding's file path (see `file`).
    if file and file.lower() not in finding_file_path(finding).lower():
        return False
    return True


def _wrap_dashboard(call: Any, *, action: str) -> Any:
    """Run a dashboard call, mapping only expected errors to 502."""
    try:
        return call()
    except DashboardUnavailable as exc:
        raise HTTPException(status_code=502, detail=f"Dashboard unavailable: {exc}") from exc
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=502, detail=f"Dashboard returned invalid data: {exc}") from exc


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", status_code=202, response_model=ScanJob)
def start_scan(
    body: ScanRequest,
    _key: str = Depends(_verify_api_key),
) -> ScanJob:
    try:
        job_id = submit_scan(body.path, body.severity)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ScanJob(job_id=job_id, status="queued", message="Scan job accepted")


@app.get("/scan/{job_id}")
def scan_status(
    job_id: str,
    _key: str = Depends(_verify_api_key),
) -> dict[str, Any]:
    job = get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.get("/projects", response_model=list[Project])
def list_projects(
    _key: str = Depends(_verify_api_key),
) -> list[Project]:
    index = _wrap_dashboard(get_index, action="index")
    return [Project(**p) for p in index.get("projects", [])]


@app.get("/projects/{slug}/findings", response_model=list[Vulnerability])
def project_findings(
    slug: str,
    severity: str | None = Query(None, description="Filter by severity, e.g. critical, high, medium, low"),
    category: str | None = Query(None, description="Filter by finding category, e.g. secrets, sast, iac"),
    scanner: str | None = Query(None, description="Filter by scanner name, e.g. gitleaks, semgrep"),
    file: str | None = Query(
        None,
        description="Case-insensitive substring filter on the finding's file path",
    ),
    _key: str = Depends(_verify_api_key),
) -> list[Vulnerability]:
    data = _wrap_dashboard(lambda: get_vulnerabilities(slug), action="vulnerabilities")
    findings = [
        v
        for v in data.get("vulnerabilities", [])
        if _matches_filters(v, severity=severity, category=category, scanner=scanner, file=file)
    ]
    return [Vulnerability(**v) for v in findings]


@app.get("/projects/{slug}/history", response_model=list[HistoryEntry])
def project_history(
    slug: str,
    _key: str = Depends(_verify_api_key),
) -> list[HistoryEntry]:
    data = _wrap_dashboard(lambda: get_history(slug), action="history")
    return [HistoryEntry(**e) for e in data]


# OpenAPI spec and interactive docs leak the full request/response schema.
# Gate them behind the same API key so an unauthenticated client cannot
# enumerate the API surface. /health stays open for liveness probes.
@app.get("/openapi.json")
def get_openapi(_key: str = Depends(_verify_api_key)) -> dict[str, Any]:
    return app.openapi()


@app.get("/docs", include_in_schema=False)
def custom_docs(_key: str = Depends(_verify_api_key)):
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="ez-appsec API - Swagger UI",
    )
