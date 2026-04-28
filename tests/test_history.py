"""Tests for ez_appsec.history (PLAN-05: Scan History & Trend Tracking)."""

import json
from pathlib import Path

import pytest

from ez_appsec.history import (
    HistoryEntry,
    append_history,
    compute_trend,
    load_history,
    make_entry,
    trim_history,
)


class TestMakeEntry:
    def test_creates_entry_with_explicit_date(self):
        e = make_entry(total=10, critical=1, high=2, medium=3, low=4,
                       date="2026-01-15T00:00:00Z")
        assert e.date == "2026-01-15T00:00:00Z"
        assert e.total == 10
        assert e.critical == 1

    def test_auto_generates_date_when_omitted(self):
        e = make_entry(total=5, critical=0, high=0, medium=3, low=2)
        assert e.date.endswith("Z")
        assert len(e.date) > 10


class TestTrimHistory:
    def test_no_trim_when_under_limit(self):
        entries = [{"date": f"2026-01-{i:02d}", "total": i} for i in range(1, 11)]
        result = trim_history(entries, max_entries=90)
        assert len(result) == 10

    def test_trims_to_max_keeping_most_recent(self):
        entries = [{"date": f"d{i}", "total": i} for i in range(100)]
        result = trim_history(entries, max_entries=90)
        assert len(result) == 90
        assert result[0]["total"] == 10
        assert result[-1]["total"] == 99

    def test_exact_max_not_trimmed(self):
        entries = [{"date": f"d{i}", "total": i} for i in range(90)]
        result = trim_history(entries, max_entries=90)
        assert len(result) == 90


class TestComputeTrend:
    def test_worse_when_total_increases(self):
        entries = [{"total": 5}, {"total": 8}]
        assert compute_trend(entries) == "↑"

    def test_better_when_total_decreases(self):
        entries = [{"total": 10}, {"total": 3}]
        assert compute_trend(entries) == "↓"

    def test_stable_when_total_unchanged(self):
        entries = [{"total": 7}, {"total": 7}]
        assert compute_trend(entries) == "→"

    def test_stable_with_single_entry(self):
        entries = [{"total": 5}]
        assert compute_trend(entries) == "→"

    def test_stable_with_empty_list(self):
        assert compute_trend([]) == "→"


class TestLoadHistory:
    def test_returns_empty_for_missing_file(self, tmp_path):
        result = load_history(tmp_path / "nonexistent.json")
        assert result == []

    def test_returns_empty_for_corrupt_json(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{not valid json")
        assert load_history(f) == []

    def test_returns_empty_for_non_list_json(self, tmp_path):
        f = tmp_path / "obj.json"
        f.write_text('{"key": "value"}')
        assert load_history(f) == []

    def test_loads_valid_history(self, tmp_path):
        f = tmp_path / "history.json"
        data = [{"date": "2026-01-01", "total": 5}]
        f.write_text(json.dumps(data))
        assert load_history(f) == data


class TestAppendHistory:
    def test_creates_file_and_appends(self, tmp_path):
        entry = make_entry(total=10, critical=2, high=3, medium=4, low=1,
                           date="2026-04-01T00:00:00Z")
        result = append_history("my-project", entry, tmp_path)
        assert result.exists()
        data = json.loads(result.read_text())
        assert len(data) == 1
        assert data[0]["total"] == 10
        assert data[0]["date"] == "2026-04-01T00:00:00Z"

    def test_appends_to_existing(self, tmp_path):
        entry1 = make_entry(total=5, critical=1, high=1, medium=2, low=1,
                            date="2026-01-01T00:00:00Z")
        entry2 = make_entry(total=3, critical=0, high=1, medium=1, low=1,
                            date="2026-02-01T00:00:00Z")
        append_history("proj", entry1, tmp_path)
        result = append_history("proj", entry2, tmp_path)
        data = json.loads(result.read_text())
        assert len(data) == 2
        assert data[0]["total"] == 5
        assert data[1]["total"] == 3

    def test_trims_at_max_entries(self, tmp_path):
        for i in range(95):
            entry = make_entry(total=i, critical=0, high=0, medium=0, low=i,
                               date=f"2026-01-{(i % 28) + 1:02d}T00:00:00Z")
            append_history("proj", entry, tmp_path, max_entries=90)
        result_path = tmp_path / "public" / "data" / "projects" / "proj" / "history.json"
        data = json.loads(result_path.read_text())
        assert len(data) == 90
        assert data[-1]["total"] == 94

    def test_custom_history_file_path(self, tmp_path):
        custom = tmp_path / "custom" / "history.json"
        entry = make_entry(total=7, critical=1, high=2, medium=3, low=1,
                           date="2026-03-01T00:00:00Z")
        result = append_history("slug", entry, tmp_path, history_file=custom)
        assert result == custom
        assert custom.exists()
        data = json.loads(custom.read_text())
        assert len(data) == 1
        assert data[0]["total"] == 7
