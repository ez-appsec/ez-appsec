#!/usr/bin/env python3
"""
Rebuild public/data/index.json from all public/data/projects/*/vulnerabilities.json files.
Run from the dashboard repo root before GitLab Pages deploy.
"""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECTS_DIR = Path("public/data/projects")
INDEX_FILE   = Path("public/data/index.json")

if not PROJECTS_DIR.exists():
    print("No projects directory found — writing empty index.")
    INDEX_FILE.parent.mkdir(parents=True, exist_ok=True)
    INDEX_FILE.write_text(json.dumps({"last_updated": None, "projects": []}, indent=2))
    sys.exit(0)

projects = []
for vuln_file in sorted(PROJECTS_DIR.glob("*/vulnerabilities.json")):
    slug = vuln_file.parent.name
    meta_file = vuln_file.parent / "meta.json"

    try:
        data = json.loads(vuln_file.read_text())
        v    = data.get("vulnerabilities", [])
    except Exception as e:
        print(f"  SKIP {slug}: could not parse vulnerabilities.json — {e}")
        continue

    meta = {}
    if meta_file.exists():
        try:
            meta = json.loads(meta_file.read_text())
        except Exception:
            pass

    name = meta.get("project_name") or slug
    path = meta.get("project_path") or slug

    # Use the file mtime as last_updated if not available in meta
    last_updated = meta.get("last_updated") or datetime.fromtimestamp(
        vuln_file.stat().st_mtime, tz=timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    summary = {
        "total":    len(v),
        "critical": sum(1 for x in v if x.get("severity") == "critical"),
        "high":     sum(1 for x in v if x.get("severity") == "high"),
        "medium":   sum(1 for x in v if x.get("severity") == "medium"),
        "low":      sum(1 for x in v if x.get("severity") == "low"),
    }

    projects.append({
        "slug":         slug,
        "name":         name,
        "path":         path,
        "last_updated": last_updated,
        "summary":      summary,
    })

    print(f"  {slug}: {summary['total']} findings "
          f"({summary['critical']}C {summary['high']}H {summary['medium']}M {summary['low']}L)")

now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
index = {"last_updated": now, "projects": projects}
INDEX_FILE.write_text(json.dumps(index, indent=2))
print(f"\nWrote {INDEX_FILE} with {len(projects)} project(s).")
