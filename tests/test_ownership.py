"""Tests for finding ownership and SLA tracking (PLAN-06)."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ez_appsec.ownership import (
    OwnershipRecord,
    assign_owner,
    fingerprint_finding,
    is_overdue,
    load_ownership,
    load_sla_config,
    save_ownership,
    DEFAULT_SLA,
)


SAMPLE_FINDING = {
    "rule_id": "sql-injection",
    "file": "src/db.py",
    "line": 42,
    "severity": "critical",
}

SAMPLE_FINDING_2 = {
    "rule_id": "xss-reflected",
    "file": "src/views.py",
    "line": 10,
    "severity": "high",
}


@pytest.fixture
def tmp_repo(tmp_path):
    (tmp_path / "data" / "projects" / "test-proj").mkdir(parents=True)
    return str(tmp_path)


class TestFingerprint:
    def test_deterministic(self):
        fp1 = fingerprint_finding(SAMPLE_FINDING)
        fp2 = fingerprint_finding(SAMPLE_FINDING)
        assert fp1 == fp2

    def test_different_findings_differ(self):
        fp1 = fingerprint_finding(SAMPLE_FINDING)
        fp2 = fingerprint_finding(SAMPLE_FINDING_2)
        assert fp1 != fp2

    def test_matches_baseline_fingerprint(self):
        from ez_appsec.baseline import _fingerprint
        assert fingerprint_finding(SAMPLE_FINDING) == _fingerprint(SAMPLE_FINDING)


class TestSaveLoadOwnership:
    def test_round_trip(self, tmp_repo):
        fp = fingerprint_finding(SAMPLE_FINDING)
        records = {
            fp: OwnershipRecord(
                finding_fingerprint=fp,
                owner="alice",
                assigned_date="2026-04-20T12:00:00+00:00",
                sla_days=7,
            )
        }
        path = save_ownership("test-proj", records, tmp_repo)
        assert path.exists()

        loaded = load_ownership("test-proj", tmp_repo)
        assert fp in loaded
        assert loaded[fp].owner == "alice"
        assert loaded[fp].sla_days == 7
        assert loaded[fp].assigned_date == "2026-04-20T12:00:00+00:00"

    def test_load_missing_file(self, tmp_repo):
        records = load_ownership("no-such-project", tmp_repo)
        assert records == {}

    def test_load_corrupt_json(self, tmp_repo):
        path = Path(tmp_repo) / "data" / "projects" / "test-proj" / "ownership.json"
        path.write_text("{bad json")
        records = load_ownership("test-proj", tmp_repo)
        assert records == {}

    def test_multiple_records(self, tmp_repo):
        fp1 = fingerprint_finding(SAMPLE_FINDING)
        fp2 = fingerprint_finding(SAMPLE_FINDING_2)
        records = {
            fp1: OwnershipRecord(fp1, "alice", "2026-04-20T12:00:00+00:00", 7),
            fp2: OwnershipRecord(fp2, "bob", "2026-04-21T12:00:00+00:00", 30),
        }
        save_ownership("test-proj", records, tmp_repo)
        loaded = load_ownership("test-proj", tmp_repo)
        assert len(loaded) == 2
        assert loaded[fp1].owner == "alice"
        assert loaded[fp2].owner == "bob"

    def test_creates_directories(self, tmp_path):
        fp = fingerprint_finding(SAMPLE_FINDING)
        records = {fp: OwnershipRecord(fp, "carol", "2026-04-20T12:00:00+00:00", 7)}
        path = save_ownership("new-proj", records, str(tmp_path))
        assert path.exists()


class TestIsOverdue:
    def test_critical_past_due(self):
        assigned = datetime.now(timezone.utc) - timedelta(days=8)
        record = OwnershipRecord("fp1", "alice", assigned.isoformat(), sla_days=7)
        assert is_overdue(record) is True

    def test_sla_ok(self):
        assigned = datetime.now(timezone.utc) - timedelta(days=3)
        record = OwnershipRecord("fp1", "alice", assigned.isoformat(), sla_days=7)
        assert is_overdue(record) is False

    def test_exactly_at_boundary(self):
        now = datetime(2026, 4, 27, 12, 0, 0, tzinfo=timezone.utc)
        assigned = now - timedelta(days=7)
        record = OwnershipRecord("fp1", "alice", assigned.isoformat(), sla_days=7)
        assert is_overdue(record, now=now) is False

    def test_one_second_past_boundary(self):
        now = datetime(2026, 4, 27, 12, 0, 1, tzinfo=timezone.utc)
        assigned = now - timedelta(days=7, seconds=1)
        record = OwnershipRecord("fp1", "alice", assigned.isoformat(), sla_days=7)
        assert is_overdue(record, now=now) is True

    def test_invalid_date_not_overdue(self):
        record = OwnershipRecord("fp1", "alice", "not-a-date", sla_days=7)
        assert is_overdue(record) is False

    def test_custom_now(self):
        now = datetime(2026, 5, 1, 0, 0, 0, tzinfo=timezone.utc)
        record = OwnershipRecord(
            "fp1", "alice", "2026-04-20T00:00:00+00:00", sla_days=7
        )
        assert is_overdue(record, now=now) is True


class TestSlaConfig:
    def test_default_when_no_config(self, tmp_repo):
        sla = load_sla_config(tmp_repo)
        assert sla == DEFAULT_SLA

    def test_custom_config(self, tmp_repo):
        config_path = Path(tmp_repo) / "data" / "config.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps({"sla": {"critical": 3, "high": 14}}))
        sla = load_sla_config(tmp_repo)
        assert sla["critical"] == 3
        assert sla["high"] == 14
        assert sla["medium"] == 90  # default preserved

    def test_corrupt_config(self, tmp_repo):
        config_path = Path(tmp_repo) / "data" / "config.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("not json")
        sla = load_sla_config(tmp_repo)
        assert sla == DEFAULT_SLA


class TestAssignOwner:
    def test_assigns_and_persists(self, tmp_repo):
        record = assign_owner("test-proj", SAMPLE_FINDING, "dave", tmp_repo)
        assert record.owner == "dave"
        assert record.sla_days == 7  # critical default

        loaded = load_ownership("test-proj", tmp_repo)
        assert record.finding_fingerprint in loaded
        assert loaded[record.finding_fingerprint].owner == "dave"

    def test_custom_sla_override(self, tmp_repo):
        record = assign_owner("test-proj", SAMPLE_FINDING, "eve", tmp_repo, sla_days=5)
        assert record.sla_days == 5

    def test_reassign_overwrites(self, tmp_repo):
        assign_owner("test-proj", SAMPLE_FINDING, "alice", tmp_repo)
        record = assign_owner("test-proj", SAMPLE_FINDING, "bob", tmp_repo)
        assert record.owner == "bob"
        loaded = load_ownership("test-proj", tmp_repo)
        assert len(loaded) == 1

    def test_uses_severity_for_sla(self, tmp_repo):
        record = assign_owner("test-proj", SAMPLE_FINDING_2, "frank", tmp_repo)
        assert record.sla_days == 30  # high default
