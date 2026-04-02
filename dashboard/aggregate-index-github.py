#!/usr/bin/env python3
"""
GitHub Pages Dashboard Aggregation Script

Aggregates vulnerability data across all GitHub projects in the dashboard.
Updates data/index.json with project summaries and statistics.
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime
from collections import Counter


def load_meta(project_path: Path) -> dict:
    """Load project meta.json if exists"""
    meta_file = project_path / "meta.json"
    if not meta_file.exists():
        return {}
    try:
        with open(meta_file, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def load_vulnerabilities(project_path: Path) -> tuple:
    """Load and parse vulnerabilities from a project directory

    Returns: (vulnerabilities list, scan_date string, findings_count int)
    """
    vuln_file = project_path / "vulnerabilities.json"
    if not vuln_file.exists():
        return [], None, 0

    try:
        with open(vuln_file, 'r') as f:
            data = json.load(f)

        # Parse different formats
        if isinstance(data, list):
            vulns = data
            scan_date = None
        elif "vulnerabilities" in data:
            vulns = data["vulnerabilities"]
            scan_date = data.get("scan_date") or data.get("generated_at")
        elif "runs" in data and len(data["runs"]) > 0:
            # SARIF format
            sarif_results = data["runs"][0].get("results", [])
            # Map SARIF level to severity
            level_to_severity = {"error": "critical", "warning": "medium", "note": "low"}
            vulns = []
            for result in sarif_results:
                level = result.get("level", "warning")
                severity = level_to_severity.get(level, "medium")
                locations = result.get("locations", [])
                if locations:
                    physical_loc = locations[0].get("physicalLocation", {})
                    artifact = physical_loc.get("artifactLocation", {})
                    region = physical_loc.get("region", {})
                    file_path = artifact.get("uri", "unknown")
                    line = region.get("startLine", 1)
                else:
                    file_path = "unknown"
                    line = 1

                vulns.append({
                    "name": result.get("ruleId", "unknown"),
                    "message": result.get("message", {}).get("text", ""),
                    "severity": severity,
                    "category": "sast",
                    "file": file_path,
                    "line": line,
                    "scanner": "sarif",
                    "confidence": "medium"
                })
            scan_date = data.get("scan_date") or data.get("generated_at")
        elif "issues" in data:
            vulns = data["issues"]
            scan_date = data.get("scan_date") or data.get("generated_at")
        else:
            vulns = []
            scan_date = None

        return vulns, scan_date, len(vulns)

    except (json.JSONDecodeError, IOError) as e:
        print(f"Warning: Could not load {vuln_file}: {e}", file=sys.stderr)
        return [], None, 0


def aggregate_project(project_path: Path) -> dict:
    """Aggregate data for a single project

    Returns: Project summary dict
    """
    vulns, scan_date, findings_count = load_vulnerabilities(project_path)
    meta = load_meta(project_path)

    # Calculate severity breakdown
    severity_counter = Counter(v.get("severity", "medium") for v in vulns)

    # Get project info
    slug = project_path.name
    project_name = meta.get("project_name", slug)
    project_path_full = meta.get("project_path", f"org/{slug}")

    # Determine last updated time
    if scan_date:
        last_updated = scan_date
    elif meta.get("scan_date"):
        last_updated = meta["scan_date"]
    else:
        # Use filesystem modification time as fallback
        try:
            last_updated = datetime.fromtimestamp(project_path.stat().st_mtime).isoformat()
        except:
            last_updated = None

    return {
        "slug": slug,
        "name": project_name,
        "project_path": project_path_full,
        "github_url": f"https://github.com/{project_path_full}",
        "last_updated": last_updated,
        "summary": {
            "total": findings_count,
            "critical": severity_counter.get("critical", 0),
            "high": severity_counter.get("high", 0),
            "medium": severity_counter.get("medium", 0),
            "low": severity_counter.get("low", 0)
        }
    }


def main():
    """Main aggregation function"""
    data_dir = Path("public/data")
    projects_dir = data_dir / "projects"

    if not projects_dir.exists():
        print("No projects directory found")
        return

    # Load existing index
    index_file = data_dir / "index.json"
    if index_file.exists():
        with open(index_file, 'r') as f:
            index = json.load(f)
    else:
        index = {"last_updated": None, "projects": []}

    # Aggregate all projects
    projects = []
    for project_path in sorted(projects_dir.iterdir()):
        if not project_path.is_dir():
            continue

        print(f"Aggregating: {project_path.name}")

        try:
            project_summary = aggregate_project(project_path)
            projects.append(project_summary)
        except Exception as e:
            print(f"Error aggregating {project_path.name}: {e}", file=sys.stderr)
            continue

    # Calculate totals
    total_findings = sum(p["summary"]["total"] for p in projects)
    total_critical = sum(p["summary"]["critical"] for p in projects)
    total_high = sum(p["summary"]["high"] for p in projects)
    total_medium = sum(p["summary"]["medium"] for p in projects)
    total_low = sum(p["summary"]["low"] for p in projects)

    # Update index
    index["projects"] = projects
    index["last_updated"] = datetime.utcnow().isoformat() + "Z"
    index["totals"] = {
        "projects": len(projects),
        "findings": total_findings,
        "critical": total_critical,
        "high": total_high,
        "medium": total_medium,
        "low": total_low
    }

    # Write updated index
    with open(index_file, 'w') as f:
        json.dump(index, f, indent=2)

    print(f"\n✓ Aggregated {len(projects)} projects")
    print(f"  Total findings: {total_findings}")
    print(f"  Critical: {total_critical}")
    print(f"  High: {total_high}")
    print(f"  Medium: {total_medium}")
    print(f"  Low: {total_low}")
    print(f"  Index updated: {index_file}")


if __name__ == "__main__":
    main()
