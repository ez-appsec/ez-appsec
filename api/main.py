"""FastAPI application — ez-appsec REST API."""

from __future__ import annotations

import os
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Security
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
    if not key or key != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return key


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
    _key: str = Depends(_verify_api_key),
) -> list[Vulnerability]:
    try:
        data = get_vulnerabilities(slug)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Dashboard unavailable: {exc}") from exc
    return [Vulnerability(**v) for v in data.get("vulnerabilities", [])]


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
