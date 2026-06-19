"""Tests for ez_appsec.schema — FindingV2, finding_id, ScanRecord."""

from datetime import datetime, timezone

from ez_appsec.schema import (
    Category,
    FindingV2,
    ScanRecord,
    Trend,
    compute_finding_id,
    finding_from_dict,
    normalize_path,
)


class TestNormalizePath:
    def test_empty(self):
        assert normalize_path("") == ""

    def test_forward_slashes_unchanged(self):
        assert normalize_path("src/main.py") == "src/main.py"

    def test_backslashes_to_forward(self):
        assert normalize_path("src\\main.py") == "src/main.py"

    def test_strips_leading_dot_slash(self):
        assert normalize_path("./src/main.py") == "src/main.py"

    def test_strips_multiple_leading_dot_slash(self):
        assert normalize_path("././src/main.py") == "src/main.py"

    def test_strips_src_prefix(self):
        assert normalize_path("/src/app/main.py") == "app/main.py"

    def test_mixed_backslash_and_dot_slash(self):
        assert normalize_path(".\\src\\main.py") == "src/main.py"


class TestComputeFindingId:
    def test_deterministic(self):
        id1 = compute_finding_id("rule-xss", "app/views.py", 42)
        id2 = compute_finding_id("rule-xss", "app/views.py", 42)
        assert id1 == id2

    def test_different_rule(self):
        id1 = compute_finding_id("rule-xss", "app/views.py", 42)
        id2 = compute_finding_id("rule-sqli", "app/views.py", 42)
        assert id1 != id2

    def test_different_file(self):
        id1 = compute_finding_id("rule-xss", "app/views.py", 42)
        id2 = compute_finding_id("rule-xss", "app/models.py", 42)
        assert id1 != id2

    def test_different_line(self):
        id1 = compute_finding_id("rule-xss", "app/views.py", 42)
        id2 = compute_finding_id("rule-xss", "app/views.py", 99)
        assert id1 != id2

    def test_path_normalization_forward_back(self):
        id1 = compute_finding_id("r1", "src/main.py", 1)
        id2 = compute_finding_id("r1", "src\\main.py", 1)
        assert id1 == id2

    def test_path_normalization_dot_slash(self):
        id1 = compute_finding_id("r1", "src/main.py", 1)
        id2 = compute_finding_id("r1", "./src/main.py", 1)
        assert id1 == id2

    def test_path_normalization_src_prefix(self):
        id1 = compute_finding_id("r1", "app/main.py", 1)
        id2 = compute_finding_id("r1", "/src/app/main.py", 1)
        assert id1 == id2

    def test_is_sha256_hex(self):
        fid = compute_finding_id("rule", "file.py", 1)
        assert len(fid) == 64
        assert all(c in "0123456789abcdef" for c in fid)


class TestFindingV2:
    def test_defaults(self):
        f = FindingV2()
        assert f.schema_version == "2"
        assert f.trend == Trend.new
        assert f.category == Category.unknown
        assert f.finding_id == ""

    def test_compute_id(self):
        f = FindingV2(rule_id="xss", file="app.py", line=10)
        fid = f.compute_id()
        assert fid == compute_finding_id("xss", "app.py", 10)
        assert f.finding_id == fid

    def test_extra_fields_allowed(self):
        f = FindingV2(rule_id="r1", custom_field="hello")
        assert f.custom_field == "hello"

    def test_v2_fields_populated(self):
        now = datetime.now(timezone.utc)
        f = FindingV2(
            rule_id="r1",
            file="a.py",
            line=5,
            scan_id="abc",
            scan_timestamp=now,
            first_seen=now,
            last_seen=now,
            age_days=3,
            trend=Trend.unchanged,
            category=Category.sast,
        )
        assert f.scan_id == "abc"
        assert f.age_days == 3
        assert f.trend == Trend.unchanged
        assert f.category == Category.sast


class TestScanRecord:
    def test_defaults(self):
        sr = ScanRecord()
        assert sr.schema_version == "2"
        assert sr.scan_id  # non-empty uuid
        assert sr.scan_timestamp is not None
        assert sr.finding_count == 0

    def test_custom_values(self):
        sr = ScanRecord(
            project="myapp",
            finding_count=5,
            new_count=2,
            resolved_count=1,
            duration_seconds=12.5,
        )
        assert sr.project == "myapp"
        assert sr.finding_count == 5
        assert sr.duration_seconds == 12.5

    def test_unique_scan_ids(self):
        sr1 = ScanRecord()
        sr2 = ScanRecord()
        assert sr1.scan_id != sr2.scan_id


class TestFindingFromDict:
    def test_v1_dict_standard_keys(self):
        d = {"rule_id": "xss", "file": "app.py", "line": 10, "severity": "HIGH", "message": "XSS found"}
        f = finding_from_dict(d)
        assert f.rule_id == "xss"
        assert f.file == "app.py"
        assert f.line == 10
        assert f.severity == "HIGH"
        assert f.finding_id == compute_finding_id("xss", "app.py", 10)
        assert f.schema_version == "2"

    def test_v1_dict_alternate_keys(self):
        d = {"ruleId": "sqli", "location": {"file": "db.py", "start_line": 20}}
        f = finding_from_dict(d)
        assert f.rule_id == "sqli"
        assert f.finding_id == compute_finding_id("sqli", "db.py", 20)

    def test_v1_dict_id_fallback(self):
        d = {"id": "leak", "file": "secret.txt", "line": 1}
        f = finding_from_dict(d)
        assert f.rule_id == "leak"

    def test_missing_fields(self):
        f = finding_from_dict({})
        assert f.rule_id == ""
        assert f.file == ""
        assert f.line == 0
        assert f.finding_id == compute_finding_id("", "", 0)

    def test_non_numeric_line(self):
        d = {"rule_id": "r1", "file": "a.py", "line": "not-a-number"}
        f = finding_from_dict(d)
        assert f.line == 0


class TestFindingV2AIRemediation:
    """AI remediation fields default to None and accept structured values."""

    def test_ai_remediation_defaults_none(self):
        f = FindingV2()
        assert f.fix_type is None
        assert f.fix_complexity is None
        assert f.effort_mins is None
        assert f.affected_symbol is None
        assert f.ai_context is None

    def test_ai_remediation_accepts_values(self):
        f = FindingV2(
            rule_id="CVE-2024-1",
            file="dep:requests",
            line=1,
            fix_type="upgrade",
            fix_complexity="trivial",
            effort_mins=5,
            affected_symbol="requests",
            ai_context={"fix_versions": ["2.32.0"], "current_version": "2.20.0"},
        )
        assert f.fix_type == "upgrade"
        assert f.fix_complexity == "trivial"
        assert f.effort_mins == 5
        assert f.affected_symbol == "requests"
        assert f.ai_context == {
            "fix_versions": ["2.32.0"],
            "current_version": "2.20.0",
        }

    def test_ai_remediation_optional_in_dict(self):
        f = FindingV2(rule_id="r", file="a.py", line=1)
        dumped = f.model_dump()
        # Optional fields are present but None, so consumers can filter them.
        assert dumped["fix_type"] is None
        assert dumped["ai_context"] is None
