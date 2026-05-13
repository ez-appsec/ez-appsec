"""FastAPI application — ez-appsec REST API."""

from __future__ import annotations

import hmac
import os
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Security
from fastapi.security import APIKeyHeader

from api.dashboard_client import get_history, get_index, get_vulnerabilities
from api.models import HistoryEntry, Project, ScanJob, ScanRequest, Vulnerability
from api.scanner_client import get_job, submit_scan

app = FastAPI(
    title="ez-appsec API",
    description="REST API for querying security findings and triggering scans.",
    version="0.1.0",
)

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _verify_api_key(key: str | None = Security(_api_key_header)) -> str:
    expected = os.environ.get("EZ_APPSEC_API_KEY", "")
    if not expected:
        raise HTTPException(status_code=500, detail="EZ_APPSEC_API_KEY not configured")
    if not key or not hmac.compare_digest(key, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return key


def _scanner_name(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("name") or value.get("id") or "")
    return str(value or "")


def _finding_file(value: dict[str, Any]) -> str:
    if value.get("file"):
        return str(value["file"])
    if value.get("file_name"):
        return str(value["file_name"])
    location = value.get("location")
    if isinstance(location, dict):
        file_info = location.get("file")
        if isinstance(file_info, dict):
            return str(file_info.get("file_name") or "")
    return ""


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
    if scanner and _scanner_name(finding.get("scanner")).lower() != scanner.lower():
        return False
    if file and file.lower() not in _finding_file(finding).lower():
        return False
    return True


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", status_code=202, response_model=ScanJob)
def start_scan(
    body: ScanRequest,
    _key: str = Depends(_verify_api_key),
) -> ScanJob:
    job_id = submit_scan(body.path, body.severity)
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
    try:
        index = get_index()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Dashboard unavailable: {exc}") from exc
    return [Project(**p) for p in index.get("projects", [])]


@app.get("/projects/{slug}/findings", response_model=list[Vulnerability])
def project_findings(
    slug: str,
    severity: str | None = Query(None, description="Filter by severity, e.g. critical, high, medium, low"),
    category: str | None = Query(None, description="Filter by finding category, e.g. secrets, sast, iac"),
    scanner: str | None = Query(None, description="Filter by scanner name, e.g. gitleaks, semgrep"),
    file: str | None = Query(None, description="Case-insensitive file path substring filter"),
    _key: str = Depends(_verify_api_key),
) -> list[Vulnerability]:
    try:
        data = get_vulnerabilities(slug)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Dashboard unavailable: {exc}") from exc
    findings = [
        v for v in data.get("vulnerabilities", [])
        if _matches_filters(v, severity=severity, category=category, scanner=scanner, file=file)
    ]
    return [Vulnerability(**v) for v in findings]


@app.get("/projects/{slug}/history", response_model=list[HistoryEntry])
def project_history(
    slug: str,
    _key: str = Depends(_verify_api_key),
) -> list[HistoryEntry]:
    try:
        data = get_history(slug)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Dashboard unavailable: {exc}") from exc
    return [HistoryEntry(**e) for e in data]
