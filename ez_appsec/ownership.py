"""Finding ownership and SLA tracking for ez-appsec dashboards."""

import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

from ez_appsec.baseline import _fingerprint


@dataclass
class OwnershipRecord:
    finding_fingerprint: str
    owner: str
    assigned_date: str  # ISO 8601
    sla_days: int


DEFAULT_SLA = {"critical": 7, "high": 30, "medium": 90, "low": 180}


def fingerprint_finding(finding: Dict[str, Any]) -> str:
    return _fingerprint(finding)


def load_ownership(slug: str, dashboard_repo: str = ".") -> Dict[str, OwnershipRecord]:
    path = Path(dashboard_repo) / "data" / "projects" / slug / "ownership.json"
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    records: Dict[str, OwnershipRecord] = {}
    for fp, entry in raw.items():
        records[fp] = OwnershipRecord(
            finding_fingerprint=fp,
            owner=entry.get("owner", ""),
            assigned_date=entry.get("assigned_date", ""),
            sla_days=entry.get("sla_days", 0),
        )
    return records


def save_ownership(
    slug: str,
    records: Dict[str, OwnershipRecord],
    dashboard_repo: str = ".",
) -> Path:
    path = Path(dashboard_repo) / "data" / "projects" / slug / "ownership.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {}
    for fp, rec in records.items():
        data[fp] = {
            "owner": rec.owner,
            "assigned_date": rec.assigned_date,
            "sla_days": rec.sla_days,
        }
    path.write_text(json.dumps(data, indent=2) + "\n")
    return path


def is_overdue(record: OwnershipRecord, now: Optional[datetime] = None) -> bool:
    if now is None:
        now = datetime.now(timezone.utc)
    try:
        assigned = datetime.fromisoformat(record.assigned_date.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return False
    elapsed_days = (now - assigned).total_seconds() / 86400
    return elapsed_days > record.sla_days


def load_sla_config(dashboard_repo: str = ".") -> Dict[str, int]:
    path = Path(dashboard_repo) / "data" / "config.json"
    if not path.exists():
        return dict(DEFAULT_SLA)
    try:
        data = json.loads(path.read_text())
        sla = data.get("sla", {})
        result = dict(DEFAULT_SLA)
        result.update(sla)
        return result
    except (json.JSONDecodeError, OSError):
        return dict(DEFAULT_SLA)


def assign_owner(
    slug: str,
    finding: Dict[str, Any],
    owner: str,
    dashboard_repo: str = ".",
    sla_days: Optional[int] = None,
) -> OwnershipRecord:
    records = load_ownership(slug, dashboard_repo)
    fp = fingerprint_finding(finding)

    if sla_days is None:
        sla_config = load_sla_config(dashboard_repo)
        severity = (finding.get("severity") or "medium").lower()
        sla_days = sla_config.get(severity, 90)

    record = OwnershipRecord(
        finding_fingerprint=fp,
        owner=owner,
        assigned_date=datetime.now(timezone.utc).isoformat(),
        sla_days=sla_days,
    )
    records[fp] = record
    save_ownership(slug, records, dashboard_repo)
    return record
