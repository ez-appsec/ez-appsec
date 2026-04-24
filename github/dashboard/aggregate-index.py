#!/usr/bin/env python3
"""
GitHub Pages Dashboard Aggregation Script

Scans data/vulnerabilities/**/*.json and regenerates data/index.json.

File layout:
  data/vulnerabilities/juice-shop.json          → slug "juice-shop"
  data/vulnerabilities/test/juice-shop.json     → slug "test/juice-shop"

Metadata (project_name, project_path, scan_date) is read from fields embedded
in each vulnerabilities file by ez-appsec web-report.
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from collections import Counter


def load_vulnerabilities(vuln_file: Path) -> tuple:
    """Load and parse a vulnerabilities file.

    Returns: (vulnerabilities list, metadata dict, scan_date string)
    """
    try:
        with open(vuln_file) as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"Warning: Could not load {vuln_file}: {e}", file=sys.stderr)
        return [], {}, None

    # Extract top-level metadata fields
    meta = {
        "project_name": data.get("project_name"),
        "project_path": data.get("project_path"),
        "github_url":   data.get("github_url"),
        "scan_date":    data.get("scan_date") or data.get("generated_at"),
    }

    # Parse vulnerability list in various formats
    if isinstance(data, list):
        vulns = data
    elif "vulnerabilities" in data:
        vulns = data["vulnerabilities"]
    elif "runs" in data and data["runs"]:
        # SARIF format
        level_map = {"error": "critical", "warning": "medium", "note": "low"}
        vulns = []
        for result in data["runs"][0].get("results", []):
            level = result.get("level", "warning")
            locs = result.get("locations", [])
            if locs:
                pl = locs[0].get("physicalLocation", {})
                file_path = pl.get("artifactLocation", {}).get("uri", "unknown")
                line = pl.get("region", {}).get("startLine", 1)
            else:
                file_path, line = "unknown", 1
            vulns.append({
                "name": result.get("ruleId", "unknown"),
                "message": result.get("message", {}).get("text", ""),
                "severity": level_map.get(level, "medium"),
                "file": file_path, "line": line,
                "scanner": "sarif",
            })
    elif "issues" in data:
        vulns = data["issues"]
    else:
        vulns = []

    return vulns, meta, meta["scan_date"]


def aggregate_file(vuln_file: Path, vulns_dir: Path) -> dict:
    """Build a project summary entry for index.json."""
    vulns, meta, scan_date = load_vulnerabilities(vuln_file)

    # Slug = path relative to data/vulnerabilities/ without extension
    rel = vuln_file.relative_to(vulns_dir)
    slug = str(rel.with_suffix(""))                    # e.g. "test/juice-shop"
    repo_name = rel.stem                               # e.g. "juice-shop"

    project_name = meta.get("project_name") or repo_name
    project_path = meta.get("project_path") or slug
    github_url   = meta.get("github_url") or f"https://github.com/{project_path}"

    # Determine last updated
    if scan_date:
        last_updated = scan_date
    else:
        try:
            last_updated = datetime.fromtimestamp(vuln_file.stat().st_mtime).isoformat()
        except Exception:
            last_updated = None

    severity_counter = Counter(v.get("severity", "medium") for v in vulns)

    return {
        "slug":         slug,
        "name":         project_name,
        "path":         f"vulnerabilities/{rel}",      # relative to data/
        "project_path": project_path,
        "github_url":   github_url,
        "last_updated": last_updated,
        "summary": {
            "total":    len(vulns),
            "critical": severity_counter.get("critical", 0),
            "high":     severity_counter.get("high", 0),
            "medium":   severity_counter.get("medium", 0),
            "low":      severity_counter.get("low", 0),
        },
    }


def main():
    data_dir  = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("public/data")
    vulns_dir = data_dir / "vulnerabilities"

    if not vulns_dir.exists():
        print("No data/vulnerabilities/ directory found — nothing to aggregate.")
        return

    projects = []
    for vuln_file in sorted(vulns_dir.rglob("*.json")):
        rel = vuln_file.relative_to(vulns_dir)
        print(f"Aggregating: {rel}")
        try:
            projects.append(aggregate_file(vuln_file, vulns_dir))
        except Exception as e:
            print(f"Error aggregating {rel}: {e}", file=sys.stderr)

    totals = {
        "projects": len(projects),
        "findings": sum(p["summary"]["total"]    for p in projects),
        "critical": sum(p["summary"]["critical"] for p in projects),
        "high":     sum(p["summary"]["high"]     for p in projects),
        "medium":   sum(p["summary"]["medium"]   for p in projects),
        "low":      sum(p["summary"]["low"]      for p in projects),
    }

    index = {
        "last_updated": datetime.utcnow().isoformat() + "Z",
        "projects":     projects,
        "totals":       totals,
    }

    index_file = data_dir / "index.json"
    with open(index_file, "w") as f:
        json.dump(index, f, indent=2)

    print(f"\n✓ Aggregated {len(projects)} projects → {index_file}")
    print(f"  Findings: {totals['findings']}  "
          f"(critical={totals['critical']} high={totals['high']} "
          f"medium={totals['medium']} low={totals['low']})")


if __name__ == "__main__":
    main()
