"""
CI helper: upsert a project entry into public/data/index.json.

Reads:
  EZ_APPSEC_REPORT        - path to the scan vulnerabilities.json artifact
  CI_PROJECT_PATH_SLUG    - gitlab project slug  (e.g. my-project)
  CI_PROJECT_NAME         - human-readable project name
  CI_PROJECT_PATH         - full project path    (e.g. group/my-project)

Writes:
  public/data/index.json  - creates or updates in place
"""

import json
import os
from datetime import datetime, timezone

report_path = os.environ["EZ_APPSEC_REPORT"]
slug        = os.environ["CI_PROJECT_PATH_SLUG"]
name        = os.environ["CI_PROJECT_NAME"]
path        = os.environ["CI_PROJECT_PATH"]
index_path  = "public/data/index.json"

with open(report_path) as f:
    data = json.load(f)

vulns = data.get("vulnerabilities", [])
summary = {
    "total":    len(vulns),
    "critical": sum(1 for v in vulns if v.get("severity") == "critical"),
    "high":     sum(1 for v in vulns if v.get("severity") == "high"),
    "medium":   sum(1 for v in vulns if v.get("severity") == "medium"),
    "low":      sum(1 for v in vulns if v.get("severity") == "low"),
}

entry = {
    "slug":         slug,
    "name":         name,
    "path":         path,
    "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "summary":      summary,
}

if os.path.exists(index_path):
    with open(index_path) as f:
        index = json.load(f)
else:
    index = {"projects": []}

# upsert: remove existing entry for this slug, then append updated one
index["projects"] = [
    p for p in index.get("projects", []) if p.get("slug") != slug
] + [entry]
index["last_updated"] = entry["last_updated"]

with open(index_path, "w") as f:
    json.dump(index, f, indent=2)

print(f"index.json updated: {slug}  total={summary['total']}  "
      f"critical={summary['critical']}  high={summary['high']}")
