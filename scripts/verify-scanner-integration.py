#!/usr/bin/env python3
"""Verify scanner binary availability and wrapper parsing paths.

This CI check is deterministic: it requires scanner binaries to be present in the
standard image, then feeds representative scanner JSON through the real wrapper
parsing code by patching subprocess.run at the wrapper boundary. That catches
wrapper command/parsing/normalization regressions without depending on live
vulnerability DB updates or external rule registry behavior.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Tuple
from unittest.mock import patch

from ez_appsec.external_scanners import GitleaksScanner, GrypeScanner, KicsScanner, SemgrepScanner

FIXTURES_ROOT = Path("tests/fixtures/scanners")


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _has_any(findings: Iterable[Dict[str, Any]], predicate: Callable[[Dict[str, Any]], bool]) -> bool:
    return any(predicate(finding) for finding in findings)


def _require_binary(binary: str, allow_missing: bool) -> bool:
    if shutil.which(binary):
        return True
    message = f"{binary} is not installed"
    if allow_missing:
        print(f"SKIP {binary}: {message}")
        return False
    raise RuntimeError(message)


def _assert_common_shape(scanner: str, findings: List[Dict[str, Any]]) -> None:
    _assert(findings, f"{scanner} produced no findings")
    for finding in findings:
        _assert(finding.get("scanner"), f"{scanner} finding missing scanner: {finding}")
        _assert(finding.get("severity"), f"{scanner} finding missing severity: {finding}")
        _assert(finding.get("finding_id"), f"{scanner} finding missing finding_id: {finding}")
        _assert(finding.get("schema_version") == "2", f"{scanner} finding missing schema v2 marker: {finding}")


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _write_json(path: str | Path, data: Any) -> None:
    Path(path).write_text(json.dumps(data))


def check_gitleaks(allow_missing: bool) -> str:
    if not _require_binary("gitleaks", allow_missing):
        return "skipped"

    def fake_run(args: List[str], **_: Any) -> subprocess.CompletedProcess:
        if args[:2] == ["gitleaks", "version"]:
            return _completed(stdout="8.18.0")
        if args[:2] == ["gitleaks", "detect"]:
            out = args[args.index("--report-path") + 1]
            _write_json(out, [{
                "RuleID": "aws-access-token",
                "Match": "AKIAIOSFODNN7EXAMPLE",
                "File": "tests/fixtures/scanners/secrets/app.py",
                "StartLine": 2,
            }])
            return _completed(returncode=1)
        return _completed()

    with patch("ez_appsec.external_scanners.subprocess.run", side_effect=fake_run):
        findings = GitleaksScanner().scan(str(FIXTURES_ROOT / "secrets"))
    _assert_common_shape("gitleaks", findings)
    _assert(_has_any(findings, lambda f: f.get("category") in {"secret", "hardcoded-secret"} and f.get("rule_id") == "aws-access-token"),
            f"gitleaks parser did not return expected secret fixture: {findings}")
    return f"passed ({len(findings)} findings)"


def check_kics(allow_missing: bool) -> str:
    if not _require_binary("kics", allow_missing):
        return "skipped"

    def fake_run(args: List[str], **_: Any) -> subprocess.CompletedProcess:
        if args[:2] == ["kics", "version"]:
            return _completed(stdout="v2.1.20")
        if args and args[0] == "kics" and "scan" in args:
            out_dir = Path(args[args.index("-o") + 1])
            out_dir.mkdir(parents=True, exist_ok=True)
            _write_json(out_dir / "results.json", {
                "queries": [{
                    "queryName": "Security Group Allows unrestricted ingress",
                    "description": "Security group permits SSH from the public internet",
                    "severity": "HIGH",
                    "results": [{
                        "file": "tests/fixtures/scanners/iac/main.tf",
                        "line": 5,
                        "resource_type": "aws_security_group",
                        "issue_type": "IncorrectValue",
                        "expected_value": "restricted ingress",
                        "actual_value": "0.0.0.0/0",
                    }],
                }]
            })
            return _completed()
        return _completed()

    with patch("ez_appsec.external_scanners.subprocess.run", side_effect=fake_run):
        findings = KicsScanner().scan(str(FIXTURES_ROOT / "iac"))
    _assert_common_shape("kics", findings)
    _assert(_has_any(findings, lambda f: f.get("category") == "iac" and f.get("scanner") == "kics"),
            f"kics parser did not return expected IaC fixture: {findings}")
    return f"passed ({len(findings)} findings)"


def check_grype(allow_missing: bool) -> str:
    if not _require_binary("grype", allow_missing):
        return "skipped"

    def fake_run(args: List[str], **_: Any) -> subprocess.CompletedProcess:
        if args[:2] == ["grype", "--version"] or args[:3] == ["grype", "db", "check"]:
            return _completed(stdout="grype 0.74.0")
        if args and args[0] == "grype" and "--file" in args:
            out = args[args.index("--file") + 1]
            _write_json(out, {
                "matches": [{
                    "vulnerability": {"id": "GHSA-whpj-8f3w-67p5", "severity": "Critical", "description": "vm2 sandbox escape"},
                    "artifact": {"name": "vm2", "version": "3.9.17", "type": "npm"},
                }]
            })
            return _completed()
        return _completed()

    with tempfile.TemporaryDirectory() as tmpdir, patch("ez_appsec.external_scanners.subprocess.run", side_effect=fake_run):
        findings = GrypeScanner().scan(tmpdir)
    _assert_common_shape("grype", findings)
    _assert(_has_any(findings, lambda f: f.get("category") == "dependency" and "vm2" in str(f)),
            f"grype parser did not return expected dependency fixture: {findings}")
    return f"passed ({len(findings)} findings)"


def check_semgrep(allow_missing: bool) -> str:
    if not _require_binary("semgrep", allow_missing):
        return "skipped"

    def fake_run(args: List[str], **_: Any) -> subprocess.CompletedProcess:
        if args[:2] == ["semgrep", "--version"]:
            return _completed(stdout="1.99.0")
        if args and args[0] == "semgrep" and "--output" in args:
            out = args[args.index("--output") + 1]
            _write_json(out, {
                "results": [{
                    "check_id": "ez-django-idor-get-parameter",
                    "path": "tests/fixtures/scanners/semgrep/app.py",
                    "start": {"line": 9},
                    "extra": {"severity": "ERROR", "message": "IDOR via direct object lookup", "metadata": {"category": "security"}},
                }]
            })
            return _completed()
        return _completed()

    with patch("ez_appsec.external_scanners.subprocess.run", side_effect=fake_run):
        findings = SemgrepScanner(extra_rules_dirs=["rules/python"]).scan(str(FIXTURES_ROOT / "semgrep"))
    _assert_common_shape("semgrep", findings)
    _assert(_has_any(findings, lambda f: f.get("scanner") == "semgrep" and f.get("category") == "sast"),
            f"semgrep parser did not return expected SAST fixture: {findings}")
    return f"passed ({len(findings)} findings)"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-missing-scanners",
        action="store_true",
        help="Skip scanners whose binaries are missing. Use only for local development; CI should fail on missing binaries.",
    )
    args = parser.parse_args()

    checks = {
        "gitleaks": check_gitleaks,
        "kics": check_kics,
        "grype": check_grype,
        "semgrep": check_semgrep,
    }
    failures: List[str] = []
    for name, check in checks.items():
        try:
            result = check(args.allow_missing_scanners)
            print(f"{name}: {result}")
        except Exception as exc:  # noqa: BLE001 - CLI summary should include all failed scanner checks
            failures.append(f"{name}: {exc}")
            print(f"{name}: FAILED: {exc}", file=sys.stderr)

    if failures:
        print("\nScanner integration failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
