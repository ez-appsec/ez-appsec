#!/usr/bin/env python3
"""Verify custom semgrep rule packs against their TP/TN fixtures.

This script is intentionally dependency-light enough to run inside ez-appsec
Docker images after they are built. It verifies every rule file under rules/*:
  - rule YAML is parseable by semgrep
  - its true-positive fixture produces at least one finding
  - its true-negative fixture produces zero findings

Fixture mapping is discovered from inline comments:
  # ruleid: <rule-id>
  # ok: <rule-id>
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

RULES_ROOT = Path("rules")
LANGUAGES = ["python", "ruby", "java", "javascript", "php"]
RULEREF_RE = re.compile(r"ruleid:\s*([\w.-]+)|ok:\s*([\w.-]+)")


def run_semgrep(rule_yaml: Path, target: Path) -> tuple[int, list[str]]:
    proc = subprocess.run(
        ["semgrep", "--config", str(rule_yaml), str(target), "--json", "--quiet"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return -1, [f"semgrep produced non-JSON output (rc={proc.returncode}): {proc.stderr[:200]}"]
    findings = len(data.get("results", []))
    errors = [
        str(e.get("message", e))[:200]
        for e in data.get("errors", [])
        if e.get("code") != "TargetParseError"
    ]
    return findings, errors


def load_rule_id(rule_yaml: Path) -> str:
    data = yaml.safe_load(rule_yaml.read_text())
    rules = data.get("rules", [])
    if not rules or not rules[0].get("id"):
        raise ValueError(f"{rule_yaml}: missing rules[0].id")
    return str(rules[0]["id"])


def fixtures_for_rule(rule_yaml: Path, language: str) -> tuple[Path | None, Path | None]:
    rule_id = load_rule_id(rule_yaml)
    tests_dir = RULES_ROOT / language / "tests"
    tp = tn = None
    for fixture in tests_dir.iterdir():
        if not fixture.is_file():
            continue
        refs = {m.group(1) or m.group(2) for m in RULEREF_RE.finditer(fixture.read_text())}
        if rule_id not in refs:
            continue
        if "_tp" in fixture.name.lower():
            tp = fixture
        elif "_tn" in fixture.name.lower():
            tn = fixture
    return tp, tn


def all_rules() -> list[tuple[str, Path]]:
    cases: list[tuple[str, Path]] = []
    for language in LANGUAGES:
        lang_dir = RULES_ROOT / language
        if not lang_dir.is_dir():
            continue
        for rule_yaml in sorted(lang_dir.glob("*.yaml")):
            cases.append((language, rule_yaml))
    return cases


def validate_rule(rule_yaml: Path) -> list[str]:
    empty_target = Path(tempfile.gettempdir()) / "ez_appsec_empty_target"
    empty_target.mkdir(exist_ok=True)
    _, errors = run_semgrep(rule_yaml, empty_target)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-missing-semgrep",
        action="store_true",
        help="Exit 0 when semgrep is missing (for images intentionally built without semgrep).",
    )
    args = parser.parse_args()

    if shutil.which("semgrep") is None:
        msg = "semgrep is not installed; cannot verify rule fixtures"
        if args.allow_missing_semgrep:
            print(f"SKIP: {msg}")
            return 0
        print(f"ERROR: {msg}", file=sys.stderr)
        return 2

    failures: list[str] = []
    passed = 0
    for language, rule_yaml in all_rules():
        rule_id = load_rule_id(rule_yaml)
        errors = validate_rule(rule_yaml)
        if errors:
            failures.append(f"{rule_yaml}: invalid rule config: {errors[:2]}")
            continue

        tp, tn = fixtures_for_rule(rule_yaml, language)
        if tp is None:
            failures.append(f"{rule_yaml}: no true-positive fixture references {rule_id}")
            continue
        if tn is None:
            failures.append(f"{rule_yaml}: no true-negative fixture references {rule_id}")
            continue

        tp_count, tp_errors = run_semgrep(rule_yaml, tp)
        tn_count, tn_errors = run_semgrep(rule_yaml, tn)
        if tp_errors:
            failures.append(f"{rule_yaml} -> {tp}: semgrep errors: {tp_errors[:2]}")
            continue
        if tn_errors:
            failures.append(f"{rule_yaml} -> {tn}: semgrep errors: {tn_errors[:2]}")
            continue
        if tp_count < 1:
            failures.append(f"{rule_yaml} -> {tp}: TRUE POSITIVE produced 0 findings")
            continue
        if tn_count != 0:
            failures.append(f"{rule_yaml} -> {tn}: TRUE NEGATIVE produced {tn_count} findings")
            continue
        passed += 1
        print(f"OK {language}/{rule_yaml.name}: tp={tp_count} tn={tn_count}")

    if failures:
        print("\nRule fixture verification failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(f"\nRule fixture verification passed: {passed} rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
