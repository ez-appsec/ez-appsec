"""Compliance report generation mapping findings to control frameworks."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader

SUPPORTED_FRAMEWORKS = {"soc2", "pci-dss", "hipaa"}

_DATA_DIR = Path(__file__).parent / "data" / "frameworks"
_TEMPLATE_DIR = Path(__file__).parent / "templates"


def load_framework(framework: str) -> List[Dict[str, Any]]:
    """Load control mapping for a compliance framework.

    Args:
        framework: One of ``soc2``, ``pci-dss``, ``hipaa``.

    Returns:
        List of control dicts with ``control_id``, ``title``, ``description``, ``categories``.

    Raises:
        ValueError: If *framework* is not a supported identifier.
        FileNotFoundError: If the framework data file is missing.
    """
    if framework not in SUPPORTED_FRAMEWORKS:
        raise ValueError(
            f"Unsupported framework '{framework}'. "
            f"Supported: {', '.join(sorted(SUPPORTED_FRAMEWORKS))}"
        )

    path = _DATA_DIR / f"{framework}.json"
    if not path.exists():
        raise FileNotFoundError(f"Framework data file not found: {path}")

    with open(path) as f:
        return json.load(f)


def _map_findings_to_controls(
    findings: List[Dict[str, Any]],
    controls: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Map findings to controls by matching ``category`` to ``categories``."""
    enriched = []
    for ctrl in controls:
        mapped = []
        for finding in findings:
            cat = finding.get("category", "")
            if cat in ctrl["categories"]:
                mapped.append(finding)
        enriched.append({**ctrl, "findings": mapped})
    return enriched


def _severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low")
        if sev in counts:
            counts[sev] += 1
    return counts


class ComplianceReporter:
    """Generate an HTML compliance report mapping findings to a control framework.

    Usage::

        reporter = ComplianceReporter("soc2")
        reporter.generate(findings, "report.html")
    """

    FRAMEWORK_DISPLAY_NAMES = {
        "soc2": "SOC 2 Type II",
        "pci-dss": "PCI DSS 4.0",
        "hipaa": "HIPAA §164.312",
    }

    def __init__(self, framework: str) -> None:
        self.framework = framework
        self.controls = load_framework(framework)

    def generate(self, findings: List[Dict[str, Any]], output_path: str) -> str:
        """Render the compliance report HTML to *output_path*.

        Args:
            findings: List of finding dicts (from ``vulnerabilities.json`` or scan results).
            output_path: Destination file path for the HTML report.

        Returns:
            The absolute path of the written report file.
        """
        enriched_controls = _map_findings_to_controls(findings, self.controls)
        sev = _severity_counts(findings)
        total = len(findings)
        controls_total = len(enriched_controls)
        controls_clean = sum(1 for c in enriched_controls if not c["findings"])

        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=True,
        )
        template = env.get_template("compliance_report.html.j2")

        html = template.render(
            framework_name=self.FRAMEWORK_DISPLAY_NAMES.get(self.framework, self.framework),
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            total_findings=total,
            severity_counts=sev,
            controls=enriched_controls,
            controls_total=controls_total,
            controls_clean=controls_clean,
        )

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(html)
        return str(out.resolve())


def load_findings_from_file(path: str) -> List[Dict[str, Any]]:
    """Load findings from a vulnerabilities.json file.

    Supports both ez-appsec internal format (``issues`` key) and GitLab format
    (``vulnerabilities`` key).

    Raises:
        FileNotFoundError: If *path* does not exist.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Findings file not found: {path}")

    with open(p) as f:
        data = json.load(f)

    if "issues" in data:
        return data["issues"]
    if "vulnerabilities" in data:
        vulns = data["vulnerabilities"]
        return [
            {
                "title": v.get("name", v.get("title", "")),
                "description": v.get("description", ""),
                "severity": v.get("severity", "medium").lower(),
                "category": v.get("category", ""),
                "file": v.get("location", {}).get("file", ""),
            }
            for v in vulns
        ]
    return data if isinstance(data, list) else []
