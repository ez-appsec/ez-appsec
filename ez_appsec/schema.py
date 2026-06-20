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


# Scanner-native category strings that don't match a Category member verbatim.
# Scanners and converters emit these (e.g. gitleaks tags findings "hardcoded-secret"),
# so the persistence boundary must map them onto the canonical enum.
_CATEGORY_ALIASES = {
    "hardcoded-secret": Category.secrets,
    "secret": Category.secrets,
    "secret_detection": Category.secrets,
    "secret-detection": Category.secrets,
    "dependency_scanning": Category.dependency,
    "container_scanning": Category.dependency,
}


def normalize_category(value: Any) -> Category:
    """Map a scanner-native category string onto the canonical Category enum.

    Returns Category.unknown for empty or unrecognized values so that a finding
    with an off-enum category never breaks model validation at persistence time.
    """
    if isinstance(value, Category):
        return value
    if value is None:
        return Category.unknown
    key = str(value).strip().lower()
    if not key:
        return Category.unknown
    try:
        return Category(key)
    except ValueError:
        return _CATEGORY_ALIASES.get(key, Category.unknown)


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


def finding_file_path(value: Dict[str, Any]) -> str:
    """Extract a normalized file path from a finding dict across known shapes.

    Shared by the REST API and the dashboard so both surfaces render the same
    path for the same finding. Handles v1 flat findings (``file`` / ``file_name``),
    object-shaped ``location.file`` (e.g. KICS, grype image findings), and the
    dashboard-fixture shape. Returns "" when no path can be derived.
    """
    if not isinstance(value, dict):
        return ""
    if value.get("file"):
        return normalize_path(str(value["file"]))
    if value.get("file_name"):
        return normalize_path(str(value["file_name"]))
    location = value.get("location")
    if isinstance(location, dict):
        file_info = location.get("file")
        if isinstance(file_info, dict):
            name = file_info.get("file_name") or file_info.get("path") or file_info.get("name")
            if name:
                return normalize_path(str(name))
        elif isinstance(file_info, str) and file_info:
            return normalize_path(file_info)
        path = location.get("path")
        if isinstance(path, str) and path:
            return normalize_path(path)
    return ""


def finding_scanner_name(value: Dict[str, Any]) -> str:
    """Extract a scanner display name from a finding dict.

    Handles string scanner fields ("gitleaks") and object-shaped scanner fields
    ({"id": "semgrep", "name": "Semgrep"}). Shared with the dashboard so the
    API and dashboard agree on the scanner label.
    """
    if not isinstance(value, dict):
        return ""
    scanner = value.get("scanner")
    if isinstance(scanner, dict):
        return str(scanner.get("name") or scanner.get("id") or "")
    if scanner is None:
        return ""
    return str(scanner)


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

    # OpenTelemetry attributes: optional, populated when opentelemetry-sdk is installed.
    otel_attributes: Optional[Dict[str, Any]] = None

    # AI remediation attributes: optional, populated where scanner has signal.
    fix_type: Optional[str] = None
    fix_complexity: Optional[str] = None
    effort_mins: Optional[int] = None
    affected_symbol: Optional[str] = None
    ai_context: Optional[Dict[str, Any]] = None

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


def finding_from_issue(issue: Dict[str, Any]) -> FindingV2:
    """Validate a scanner issue dict into a FindingV2 without losing v2 fields.

    Unlike finding_from_dict (which copies only the five v1 fields), this preserves
    every field the scanner and scan-tracking populated — first_seen, trend, scan_id,
    age_days, otel_attributes, AI remediation, etc. — and tolerates extras via the
    model's extra="allow" config. The category is normalized onto the Category enum
    first, since scanners emit off-enum strings like "hardcoded-secret".
    """
    data = dict(issue)
    if "category" in data:
        data["category"] = normalize_category(data["category"]).value
    return FindingV2.model_validate(data)
