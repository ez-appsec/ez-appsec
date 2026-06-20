"""Functional tests for custom SAST rule packs (PLAN-16).

These tests run semgrep against every rule's own TP/TN fixture pair and assert:
  - the true-positive fixture produces >= 1 finding (catches FALSE_NEGATIVE rules)
  - the true-negative fixture produces 0 findings (catches FALSE_POSITIVE rules)
  - the rule YAML validates without parse errors

This is the verification the schema tests in test_custom_rules.py do NOT provide:
they check structure but never prove a rule actually matches vulnerable code or
correctly excludes safe code. These tests would have caught all 4 of the broken
IDOR rules shipped in the initial PLAN-16 PR.

Fixtures are auto-discovered: a fixture file belongs to a rule if it contains a
``# ruleid: <rule_id>`` or ``# ok: <rule_id>`` comment referencing that rule.
This avoids maintaining a brittle filename<->rule mapping.

Skipped automatically when semgrep is not installed (honors the project
convention of keeping CI light and not bundling semgrep as a hard dependency).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

RULES_ROOT = Path(__file__).parent.parent / "rules"
LANGUAGES = ["python", "ruby", "java", "javascript", "php"]

# Shared empty target dir used by the validate test. Semgrep's `--validate` flag
# does not reliably emit JSON in all versions; instead we scan an empty dir and
# inspect the errors array for rule parse failures.
_EMPTY_TARGET = Path(tempfile.gettempdir()) / "ez_appsec_empty_target"
_EMPTY_TARGET.mkdir(exist_ok=True)

# Match `# ruleid: <id>` or `# ok: <id>` (leading comment char varies by language).
RULEREF_RE = re.compile(r"ruleid:\s*([\w.-]+)|ok:\s*([\w.-]+)")


def _semgrep_available() -> bool:
    """True if a usable semgrep binary is on PATH."""
    return shutil.which("semgrep") is not None


# Skip the entire module when semgrep is not installed. This keeps the test
# suite green in minimal CI environments while still running in any environment
# that has semgrep (developer machines, the rule-quality CI job, etc.).
pytestmark = pytest.mark.skipif(
    not _semgrep_available(),
    reason="semgrep not installed on PATH — install with `pip install semgrep` to run rule fixture tests",
)


def _run_semgrep(rule_yaml: Path, target: Path) -> tuple[int, list[str]]:
    """Run semgrep with one rule against one file. Returns (finding_count, error_messages).

    Only *rule* parse errors are surfaced as failures; file-target parse errors
    (e.g. a fixture that uses framework imports semgrep cannot resolve) are
    filtered out since fixtures are intentionally minimal snippets.
    """
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
    all_errors = data.get("errors", [])
    # Distinguish rule-level parse errors (always fail) from target-level parse
    # errors (expected for minimal fixtures — filter out).
    rule_errors = [
        e.get("message", str(e))[:200]
        for e in all_errors
        if e.get("code") != "TargetParseError"
        and "Parse error" not in str(e.get("message", ""))
    ]
    return findings, rule_errors


def _load_rule_id(rule_yaml: Path) -> str | None:
    """Extract the first rule id from a rule YAML file."""
    data = yaml.safe_load(rule_yaml.read_text())
    rules = data.get("rules", [])
    return rules[0].get("id") if rules else None


def _fixtures_for_rule(rule_yaml: Path, language: str) -> tuple[Path | None, Path | None]:
    """Find the TP and TN fixtures whose `# ruleid:`/`# ok:` comments reference this rule.

    Returns (tp_path, tn_path) - either may be None if no fixture references the rule.
    """
    rule_id = _load_rule_id(rule_yaml)
    if not rule_id:
        return None, None
    tests_dir = RULES_ROOT / language / "tests"
    if not tests_dir.is_dir():
        return None, None
    tp = tn = None
    for fixture in tests_dir.iterdir():
        if not fixture.is_file():
            continue
        text = fixture.read_text()
        refs = {m.group(1) or m.group(2) for m in RULEREF_RE.finditer(text)}
        if rule_id not in refs:
            continue
        name = fixture.name.lower()
        if "_tp" in name:
            tp = fixture
        elif "_tn" in name:
            tn = fixture
    return tp, tn


def _all_rules():
    """Return (language, rule_yaml_path) for every rule file across all language packs."""
    cases = []
    for language in LANGUAGES:
        lang_dir = RULES_ROOT / language
        if not lang_dir.is_dir():
            continue
        for rule_yaml in sorted(lang_dir.glob("*.yaml")):
            cases.append((language, rule_yaml))
    return cases


@pytest.mark.parametrize("language, rule_yaml", _all_rules())
def test_rule_yaml_validates(language, rule_yaml):
    """Rule YAML must be syntactically valid semgrep config (catches PatternParseError).

    Uses an empty-target scan rather than `semgrep --validate --json` because the
    latter does not reliably emit parseable JSON across semgrep versions. Any
    rule-level parse error (malformed pattern, invalid metavariable usage) shows
    up in the scan's errors array regardless of the target scanned.
    """
    proc = subprocess.run(
        ["semgrep", "--config", str(rule_yaml), str(_EMPTY_TARGET), "--json", "--quiet"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        pytest.fail(
            f"{rule_yaml.name}: semgrep scan produced non-JSON output (rc={proc.returncode}): "
            f"{proc.stderr[:300]}"
        )
    rule_errors = [
        e for e in data.get("errors", [])
        if e.get("code") != "TargetParseError"
    ]
    if rule_errors:
        msgs = "; ".join(str(e.get("message", e))[:200] for e in rule_errors)
        pytest.fail(f"{rule_yaml.name}: invalid semgrep rule - {msgs}")


@pytest.mark.parametrize("language, rule_yaml", _all_rules())
def test_rule_true_positive_fires(language, rule_yaml):
    """The rule's true-positive fixture must produce at least one finding.

    A zero here means the rule does not match the vulnerable code it claims to
    catch (FALSE_NEGATIVE) - usually a malformed pattern or an over-broad
    pattern-not exclusion.
    """
    tp, _ = _fixtures_for_rule(rule_yaml, language)
    if tp is None:
        pytest.skip(f"no true-positive fixture references {rule_yaml.name}")
    count, errors = _run_semgrep(rule_yaml, tp)
    if errors:
        pytest.fail(f"{rule_yaml.name} -> {tp.name}: semgrep errors: {errors[:2]}")
    assert count >= 1, (
        f"{rule_yaml.name} -> {tp.name}: TRUE POSITIVE produced 0 findings "
        f"(rule does not match its own vulnerable fixture - FALSE NEGATIVE)"
    )


@pytest.mark.parametrize("language, rule_yaml", _all_rules())
def test_rule_true_negative_clean(language, rule_yaml):
    """The rule's true-negative fixture must produce zero findings.

    A non-zero here means the rule flags safe code (FALSE POSITIVE) - usually a
    missing pattern-not exclusion for the scoped/safe variant.
    """
    _, tn = _fixtures_for_rule(rule_yaml, language)
    if tn is None:
        pytest.skip(f"no true-negative fixture references {rule_yaml.name}")
    count, errors = _run_semgrep(rule_yaml, tn)
    if errors:
        pytest.fail(f"{rule_yaml.name} -> {tn.name}: semgrep errors: {errors[:2]}")
    assert count == 0, (
        f"{rule_yaml.name} -> {tn.name}: TRUE NEGATIVE produced {count} finding(s) "
        f"(rule flags safe code - FALSE POSITIVE; add a pattern-not exclusion for the scoped variant)"
    )
