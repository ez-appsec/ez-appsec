"""Pydantic response models matching the dashboard vulnerabilities.json schema."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ScannerInfo(BaseModel):
    id: str
    name: str


class FileLocation(BaseModel):
    file_name: str = ""
    similarity_id: str = ""
    line: int = 0
    issue_type: str = ""
    search_key: str = ""
    search_line: int = -1
    search_value: str = ""
    expected_value: str = ""
    actual_value: str = ""


class VulnerabilityLocation(BaseModel):
    file: FileLocation | None = None
    start_line: int = 0
    end_line: int = 0
    class_: str = Field("", alias="class")
    method: str = ""

    model_config = {"populate_by_name": True}


class Identifier(BaseModel):
    type: str
    name: str
    value: str


class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    category: str = "sast"
    name: str = ""
    message: str = ""
    description: str = ""
    cve: str = ""
    severity: str = "medium"
    confidence: str = "medium"
    solution: str = ""
    scanner: ScannerInfo | str | None = None
    location: VulnerabilityLocation | None = None
    identifiers: list[Identifier] = []
    links: list[Any] = []


class VulnerabilityReport(BaseModel):
    version: str = "15.0.0"
    vulnerabilities: list[Vulnerability] = []


class ProjectSummary(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class Project(BaseModel):
    slug: str
    name: str
    project_path: str = ""
    github_url: str = ""
    last_updated: str = ""
    summary: ProjectSummary = ProjectSummary()


class ProjectIndex(BaseModel):
    last_updated: str = ""
    projects: list[Project] = []


class HistoryEntry(BaseModel):
    date: str
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class ScanRequest(BaseModel):
    path: str = Field(..., description="Filesystem path or Git clone URL to scan")
    severity: str = Field("all", description="Minimum severity filter: all, low, medium, high, critical")


class ScanJob(BaseModel):
    job_id: str
    status: str = "queued"
    message: str = "Scan job accepted"
