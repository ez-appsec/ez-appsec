"""Tests for PLAN-16 custom semgrep rule packs.

Validates:
- Rule YAML schema (required fields: id, message, severity, languages, pattern/pattern-either/patterns)
- resolve_rules_dirs maps language names to directories
- Rule file counts per language pack (>= 5)
"""

import os
from pathlib import Path

import pytest
import yaml

from ez_appsec.external_scanners import resolve_rules_dirs, RULES_LANGUAGE_MAP

RULES_ROOT = Path(__file__).parent.parent / "rules"
LANGUAGES = ["python", "ruby", "java", "javascript", "php"]

REQUIRED_RULE_FIELDS = {"id", "message", "severity", "languages"}
PATTERN_FIELDS = {"pattern", "pattern-either", "patterns", "pattern-regex"}


def _load_rules(language: str):
    """Load all rules from a language pack, yielding (file, rule) pairs."""
    lang_dir = RULES_ROOT / language
    for yaml_file in sorted(lang_dir.glob("*.yaml")):
        with open(yaml_file) as f:
            data = yaml.safe_load(f)
        for rule in data.get("rules", []):
            yield yaml_file.name, rule


class TestRuleYAMLSchema:
    """Each rule must have the required semgrep fields."""

    @pytest.mark.parametrize("language", LANGUAGES)
    def test_language_pack_exists(self, language):
        lang_dir = RULES_ROOT / language
        assert lang_dir.is_dir(), f"Missing rules/{language}/ directory"

    @pytest.mark.parametrize("language", LANGUAGES)
    def test_minimum_rule_count(self, language):
        rules = list(_load_rules(language))
        assert len(rules) >= 5, (
            f"{language} has only {len(rules)} rule(s), need >= 5"
        )

    @pytest.mark.parametrize("language", LANGUAGES)
    def test_required_fields(self, language):
        for filename, rule in _load_rules(language):
            for field in REQUIRED_RULE_FIELDS:
                assert field in rule, (
                    f"{language}/{filename} rule '{rule.get('id', '?')}' missing '{field}'"
                )

    @pytest.mark.parametrize("language", LANGUAGES)
    def test_has_pattern(self, language):
        for filename, rule in _load_rules(language):
            has_pattern = any(f in rule for f in PATTERN_FIELDS)
            assert has_pattern, (
                f"{language}/{filename} rule '{rule.get('id', '?')}' has no pattern field"
            )

    @pytest.mark.parametrize("language", LANGUAGES)
    def test_severity_values(self, language):
        valid = {"ERROR", "WARNING", "INFO"}
        for filename, rule in _load_rules(language):
            assert rule["severity"] in valid, (
                f"{language}/{filename} rule '{rule['id']}' has invalid severity "
                f"'{rule['severity']}', expected one of {valid}"
            )

    @pytest.mark.parametrize("language", LANGUAGES)
    def test_metadata_has_cwe(self, language):
        for filename, rule in _load_rules(language):
            meta = rule.get("metadata", {})
            assert "cwe" in meta, (
                f"{language}/{filename} rule '{rule['id']}' missing metadata.cwe"
            )

    @pytest.mark.parametrize("language", LANGUAGES)
    def test_metadata_has_category_security(self, language):
        for filename, rule in _load_rules(language):
            meta = rule.get("metadata", {})
            assert meta.get("category") == "security", (
                f"{language}/{filename} rule '{rule['id']}' metadata.category "
                f"should be 'security', got '{meta.get('category')}'"
            )


class TestTestFixtures:
    """Each rule should have test fixtures."""

    @pytest.mark.parametrize("language", LANGUAGES)
    def test_fixtures_directory_exists(self, language):
        tests_dir = RULES_ROOT / language / "tests"
        assert tests_dir.is_dir(), f"Missing rules/{language}/tests/ directory"

    @pytest.mark.parametrize("language", LANGUAGES)
    def test_has_true_positive_fixtures(self, language):
        tests_dir = RULES_ROOT / language / "tests"
        tp_files = list(tests_dir.glob("*_tp.*"))
        assert len(tp_files) >= 5, (
            f"{language} has only {len(tp_files)} true-positive fixture(s), need >= 5"
        )

    @pytest.mark.parametrize("language", LANGUAGES)
    def test_has_true_negative_fixtures(self, language):
        tests_dir = RULES_ROOT / language / "tests"
        tn_files = list(tests_dir.glob("*_tn.*"))
        assert len(tn_files) >= 5, (
            f"{language} has only {len(tn_files)} true-negative fixture(s), need >= 5"
        )


class TestResolveRulesDirs:
    """Test the resolve_rules_dirs helper."""

    def test_resolve_python(self):
        dirs = resolve_rules_dirs(["python"])
        assert len(dirs) == 1
        assert dirs[0].endswith("/python")

    def test_resolve_all(self):
        dirs = resolve_rules_dirs(["all"])
        assert len(dirs) >= 5

    def test_resolve_framework_alias(self):
        dirs = resolve_rules_dirs(["django"])
        assert len(dirs) == 1
        assert dirs[0].endswith("/python")

    def test_resolve_multiple(self):
        dirs = resolve_rules_dirs(["ruby", "php"])
        assert len(dirs) == 2

    def test_resolve_unknown_warns(self, caplog):
        dirs = resolve_rules_dirs(["cobol"])
        assert len(dirs) == 0

    def test_language_map_completeness(self):
        for lang in LANGUAGES:
            assert lang in RULES_LANGUAGE_MAP


class TestSemgrepScannerExtraRules:
    """Test that SemgrepScanner accepts extra_rules_dirs."""

    def test_init_default_empty(self):
        from ez_appsec.external_scanners import SemgrepScanner
        scanner = SemgrepScanner()
        assert scanner.extra_rules_dirs == []

    def test_init_with_dirs(self):
        from ez_appsec.external_scanners import SemgrepScanner
        dirs = ["/tmp/rules/python"]
        scanner = SemgrepScanner(extra_rules_dirs=dirs)
        assert scanner.extra_rules_dirs == dirs
