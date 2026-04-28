"""Scan history tracking for ez-appsec dashboards (PLAN-05).

Each scan appends a timestamped entry to history.json per project.
The dashboard uses this data for sparkline charts and trend indicators.
"""

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class HistoryEntry:
    date: str
    total: int
    critical: int
    high: int
    medium: int
    low: int


def make_entry(total: int, critical: int, high: int, medium: int, low: int,
               date: str | None = None) -> HistoryEntry:
    if date is None:
        date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return HistoryEntry(
        date=date, total=total, critical=critical,
        high=high, medium=medium, low=low,
    )


def append_history(slug: str, entry: HistoryEntry, dashboard_dir: Path,
                   max_entries: int = 90,
                   history_file: Path | None = None) -> Path:
    """Append a history entry for a project and trim to max_entries.

    If history_file is provided, writes there directly.
    Otherwise derives from dashboard_dir / public/data/projects/<slug>/history.json.

    Returns the path to the history.json file.
    """
    if history_file is None:
        projects_dir = dashboard_dir / "public" / "data" / "projects"
        history_file = projects_dir / slug / "history.json"
    history_file.parent.mkdir(parents=True, exist_ok=True)

    entries = load_history(history_file)
    entries.append(asdict(entry))
    entries = trim_history(entries, max_entries)

    history_file.write_text(json.dumps(entries, indent=2))
    return history_file


def load_history(history_file: Path) -> list[dict]:
    if history_file.exists():
        try:
            data = json.loads(history_file.read_text())
            if isinstance(data, list):
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return []


def trim_history(entries: list[dict], max_entries: int = 90) -> list[dict]:
    """Keep only the most recent max_entries entries."""
    if len(entries) > max_entries:
        return entries[-max_entries:]
    return entries


def compute_trend(entries: list[dict]) -> str:
    """Compare latest entry to previous: '↑' worse, '↓' better, '→' stable."""
    if len(entries) < 2:
        return "→"
    prev_total = entries[-2].get("total", 0)
    curr_total = entries[-1].get("total", 0)
    if curr_total > prev_total:
        return "↑"
    elif curr_total < prev_total:
        return "↓"
    return "→"
