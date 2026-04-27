"""Baseline diffing for new-findings-only alerting"""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Tuple


def _fingerprint(finding: Dict[str, Any]) -> str:
    rule_id = finding.get("rule_id", finding.get("ruleId", finding.get("id", "")))
    file_path = _normalize_path(finding.get("file", finding.get("location", {}).get("file", "")))
    start_line = str(finding.get("line", finding.get("location", {}).get("start_line", "")))
    raw = f"{rule_id}:{file_path}:{start_line}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _fingerprint_no_line(finding: Dict[str, Any]) -> str:
    rule_id = finding.get("rule_id", finding.get("ruleId", finding.get("id", "")))
    file_path = _normalize_path(finding.get("file", finding.get("location", {}).get("file", "")))
    raw = f"{rule_id}:{file_path}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _normalize_path(p: str) -> str:
    return str(Path(p)) if p else ""


@dataclass
class Baseline:
    findings: List[Dict[str, Any]] = field(default_factory=list)
    fingerprints: set = field(default_factory=set, init=False, repr=False)
    fingerprints_no_line: set = field(default_factory=set, init=False, repr=False)

    def __post_init__(self):
        self.fingerprints = {_fingerprint(f) for f in self.findings}
        self.fingerprints_no_line = {_fingerprint_no_line(f) for f in self.findings}


def load_baseline(path_or_url: str) -> Baseline:
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        import urllib.request
        with urllib.request.urlopen(path_or_url) as resp:
            data = json.loads(resp.read().decode())
    else:
        with open(path_or_url) as f:
            data = json.load(f)

    if isinstance(data, list):
        findings = data
    elif isinstance(data, dict):
        findings = data.get("issues", data.get("vulnerabilities", []))
    else:
        findings = []

    return Baseline(findings=findings)


def diff_findings(
    current: List[Dict[str, Any]],
    baseline: Baseline,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    new_findings = []
    existing_findings = []

    for finding in current:
        fp = _fingerprint(finding)
        fp_no_line = _fingerprint_no_line(finding)
        if fp in baseline.fingerprints or fp_no_line in baseline.fingerprints_no_line:
            existing_findings.append(finding)
        else:
            new_findings.append(finding)

    return new_findings, existing_findings
