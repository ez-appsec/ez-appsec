"""Schema v2 models for ez-appsec findings and scan records."""

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field


class Trend(str, Enum):
    new = "new"
    unchanged = "unchanged"
    resolved = "resolved"


class Category(str, Enum):
    secrets = "secrets"
    sast = "sast"
    iac = "iac"
    dependency = "dependency"
    license = "license"
    unknown = "unknown"


def normalize_path(p: str) -> str:
    """Normalize a file path: forward slashes, strip leading ./ and /src/."""
    if not p:
        return ""
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    if p.startswith("/src/"):
        p = p[5:]
    return p


def compute_finding_id(rule_id: str, file_path: str, start_line: int) -> str:
    """Compute a stable finding_id from rule, normalized path, and line number."""
    normalized = normalize_path(file_path)
    raw = f"{rule_id}:{normalized}:{start_line}"
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_scan_id() -> str:
    """Generate a unique scan ID."""
    return str(uuid.uuid4())


class FindingV2(BaseModel):
    model_config = ConfigDict(extra="allow")

    # v1 fields (preserved for backwards compat — consumers may set these via extra="allow")
    rule_id: str = ""
    file: str = ""
    line: int = 0
    severity: str = ""
    message: str = ""

    # v2 fields
    finding_id: str = ""
    scan_id: str = ""
    scan_timestamp: Optional[datetime] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    age_days: int = 0
    sla_deadline: Optional[datetime] = None
    trend: Trend = Trend.new
    category: Category = Category.unknown
    schema_version: str = "2"

    def compute_id(self) -> str:
        """Compute and set finding_id from this finding's fields."""
        self.finding_id = compute_finding_id(self.rule_id, self.file, self.line)
        return self.finding_id


class ScanRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    scan_id: str = Field(default_factory=generate_scan_id)
    scan_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    project: str = ""
    scanner_versions: Dict[str, str] = Field(default_factory=dict)
    finding_count: int = 0
    new_count: int = 0
    resolved_count: int = 0
    duration_seconds: float = 0.0
    schema_version: str = "2"


def finding_from_dict(d: Dict[str, Any]) -> FindingV2:
    """Create a FindingV2 from a v1-style finding dict, computing finding_id."""
    rule_id = d.get("rule_id", d.get("ruleId", d.get("id", "")))
    file_path = d.get("file", d.get("location", {}).get("file", ""))
    start_line = d.get("line", d.get("location", {}).get("start_line", 0))
    try:
        start_line = int(start_line)
    except (TypeError, ValueError):
        start_line = 0

    finding = FindingV2(
        rule_id=rule_id,
        file=file_path,
        line=start_line,
        severity=d.get("severity", ""),
        message=d.get("message", ""),
        finding_id=compute_finding_id(rule_id, file_path, start_line),
    )
    return finding
