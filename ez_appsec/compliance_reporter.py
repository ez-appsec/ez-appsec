"""Compliance report generation mapping findings to control frameworks."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from jinja2 import Environment, FileSystemLoader

SUPPORTED_FRAMEWORKS = {"soc2", "pci-dss", "hipaa"}

_DATA_DIR = Path(__file__).parent / "data" / "frameworks"
_TEMPLATE_DIR = Path(__file__).parent / "templates"

_CATEGORY_ALIASES: Dict[str, str] = {
    "secret_detection": "secrets",
    "secrets": "secrets",
    "sast": "sast",
    "dast": "dast",
    "dependency_scanning": "dependency_scanning",
    "container_scanning": "dependency_scanning",
    "cve": "cve",
    "iac": "iac",
    "infrastructure as code": "iac",
    "license_compliance": "license_compliance",
}

_TYPE_TO_CATEGORY: Dict[str, str] = {
    "dependency": "dependency_scanning",
}


def normalize_category(finding: Dict[str, Any]) -> str:
    """Resolve a finding's category from ``category`` or ``type`` fields.

    Applies alias mapping so scanner-specific values (e.g. ``secret_detection``,
    ``Secrets``) resolve to the canonical names used in framework JSON files.
    """
    raw = finding.get("category", "").strip()
    if not raw:
        raw = finding.get("type", "").strip()
    key = raw.lower()
    return _CATEGORY_ALIASES.get(key, _TYPE_TO_CATEGORY.get(key, key))


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
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Map findings to controls by matching normalized category to ``categories``.

    Returns:
        Tuple of (enriched_controls, unmapped_findings).
    """
    cats = [normalize_category(f) for f in findings]
    mapped_set: Set[int] = set()
    enriched = []
    for ctrl in controls:
        ctrl_cats = ctrl["categories"]
        matched = []
        for idx, cat in enumerate(cats):
            if cat in ctrl_cats:
                matched.append(findings[idx])
                mapped_set.add(idx)
        enriched.append({**ctrl, "findings": matched})

    unmapped = [f for idx, f in enumerate(findings) if idx not in mapped_set]
    return enriched, unmapped


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
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=True,
        )

    def generate(self, findings: List[Dict[str, Any]], output_path: str) -> Dict[str, Any]:
        """Render the compliance report HTML to *output_path*.

        Args:
            findings: List of finding dicts (from ``vulnerabilities.json`` or scan results).
            output_path: Destination file path for the HTML report.

        Returns:
            Dict with ``path`` (absolute file path), ``total``, ``mapped``, ``unmapped``,
            ``controls_total``, and ``controls_clean``.
        """
        enriched_controls, unmapped = _map_findings_to_controls(findings, self.controls)
        sev = _severity_counts(findings)
        total = len(findings)
        mapped_count = total - len(unmapped)
        controls_total = len(enriched_controls)
        controls_clean = sum(1 for c in enriched_controls if not c["findings"])

        template = self._env.get_template("compliance_report.html.j2")

        html = template.render(
            framework_name=self.FRAMEWORK_DISPLAY_NAMES.get(self.framework, self.framework),
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            total_findings=total,
            mapped_count=mapped_count,
            severity_counts=sev,
            controls=enriched_controls,
            controls_total=controls_total,
            controls_clean=controls_clean,
            unmapped_findings=unmapped,
        )

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(html)
        return {
            "path": str(out.resolve()),
            "total": total,
            "mapped": mapped_count,
            "unmapped": len(unmapped),
            "controls_total": controls_total,
            "controls_clean": controls_clean,
        }


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
        issues = data["issues"]
        for item in issues:
            if "category" not in item and "type" in item:
                item["category"] = item["type"]
        return issues
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
