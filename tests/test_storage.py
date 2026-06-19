"""Tests for storage backends."""

import json
from datetime import datetime, timezone

import pytest

from ez_appsec.schema import Category, FindingV2, ScanRecord, Trend
from ez_appsec.storage import ConfigurationError, JsonFileBackend, SqlBackend, get_storage_backend


def make_finding(**overrides):
    data = {
        "rule_id": "semgrep.python.insecure-hash",
        "file": "app/security.py",
        "line": 42,
        "severity": "high",
        "message": "MD5 is not suitable for password hashing",
        "finding_id": "finding-1",
        "scan_id": "scan-1",
        "scan_timestamp": datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        "first_seen": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "last_seen": datetime(2026, 1, 2, tzinfo=timezone.utc),
        "trend": Trend.new,
        "category": Category.sast,
        "fix_type": "code_change",
        "fix_complexity": "low",
        "effort_mins": 15,
        "affected_symbol": "hash_password",
        "ai_context": {"safe_api": "bcrypt"},
    }
    data.update(overrides)
    return FindingV2(**data)


def make_scan_record(**overrides):
    data = {
        "scan_id": "scan-1",
        "scan_timestamp": datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        "project": "demo",
        "scanner_versions": {"semgrep": "1.99.0"},
        "finding_count": 1,
        "new_count": 1,
        "resolved_count": 0,
        "duration_seconds": 1.25,
    }
    data.update(overrides)
    return ScanRecord(**data)


class TestJsonFileBackend:
    def test_write_findings_uses_legacy_vulnerabilities_json_shape(self, tmp_path):
        backend = JsonFileBackend()
        finding = make_finding()
        scan_record = make_scan_record()

        output_path = backend.write_findings([finding], scan_record, tmp_path / "vulnerabilities.json")

        assert output_path == tmp_path / "vulnerabilities.json"
        payload = json.loads(output_path.read_text())
        assert payload["version"] == "15.0.0"
        assert payload["schema_version"] == "2"
        assert payload["remediations"] == []
        assert len(payload["vulnerabilities"]) == 1
        assert payload["vulnerabilities"][0]["rule_id"] == finding.rule_id
        assert payload["vulnerabilities"][0]["scan_timestamp"] == "2026-01-02T03:04:05Z"
        assert payload["vulnerabilities"][0]["fix_type"] == "code_change"
        assert payload["scan_record"]["scan_id"] == scan_record.scan_id

    def test_write_to_directory_defaults_to_vulnerabilities_json(self, tmp_path):
        backend = JsonFileBackend()

        output_path = backend.write_findings([make_finding()], make_scan_record(), tmp_path)

        assert output_path == tmp_path / "vulnerabilities.json"
        assert output_path.exists()

    def test_read_findings_round_trips_finding_v2_models(self, tmp_path):
        backend = JsonFileBackend()
        finding = make_finding()
        output_path = backend.write_findings([finding], make_scan_record(), tmp_path)

        findings = backend.read_findings(output_path)

        assert findings == [finding]
        assert findings[0].trend is Trend.new
        assert findings[0].category is Category.sast
        assert findings[0].ai_context == {"safe_api": "bcrypt"}

    def test_read_scan_records_round_trips_embedded_scan_record(self, tmp_path):
        backend = JsonFileBackend()
        scan_record = make_scan_record()
        output_path = backend.write_findings([make_finding()], scan_record, tmp_path)

        records = backend.read_scan_records(output_path)

        assert records == [scan_record]

    def test_read_scan_records_supports_scan_records_list(self, tmp_path):
        backend = JsonFileBackend()
        record = make_scan_record(scan_id="scan-list")
        path = tmp_path / "vulnerabilities.json"
        path.write_text(
            json.dumps(
                {
                    "version": "15.0.0",
                    "vulnerabilities": [],
                    "scan_records": [record.model_dump(mode="json")],
                }
            )
        )

        assert backend.read_scan_records(path) == [record]

    def test_read_findings_supports_legacy_gitlab_vulnerability_shape(self, tmp_path):
        backend = JsonFileBackend()
        path = tmp_path / "vulnerabilities.json"
        path.write_text(
            json.dumps(
                {
                    "version": "15.0.0",
                    "vulnerabilities": [
                        {
                            "id": "legacy-id",
                            "name": "Hardcoded secret",
                            "message": "Secret found",
                            "severity": "high",
                            "identifiers": [{"value": "gitleaks.generic-api-key"}],
                            "location": {
                                "file": "./src/settings.py",
                                "start_line": 12,
                            },
                        }
                    ],
                    "remediations": [],
                }
            )
        )

        findings = backend.read_findings(path)

        assert len(findings) == 1
        assert findings[0].rule_id == "gitleaks.generic-api-key"
        assert findings[0].file == "src/settings.py"
        assert findings[0].line == 12
        assert findings[0].severity == "high"
        assert findings[0].message == "Secret found"
        assert findings[0].finding_id


class TestGetStorageBackend:
    def test_json_backend_is_default_when_env_unset(self, monkeypatch):
        monkeypatch.delenv("EZ_APPSEC_STORAGE_BACKEND", raising=False)

        assert isinstance(get_storage_backend(), JsonFileBackend)

    @pytest.mark.parametrize("value", ["", "json", "jsonfile", "json-file", "JSON"])
    def test_json_backend_aliases(self, monkeypatch, value):
        monkeypatch.setenv("EZ_APPSEC_STORAGE_BACKEND", value)

        assert isinstance(get_storage_backend(), JsonFileBackend)

    def test_unknown_backend_raises_clear_error(self, monkeypatch):
        monkeypatch.setenv("EZ_APPSEC_STORAGE_BACKEND", "sqlite")

        with pytest.raises(ValueError, match="Unsupported EZ_APPSEC_STORAGE_BACKEND: sqlite"):
            get_storage_backend()

    def test_sql_backend_requires_storage_url(self, monkeypatch):
        monkeypatch.setenv("EZ_APPSEC_STORAGE_BACKEND", "sql")
        monkeypatch.delenv("EZ_APPSEC_STORAGE_URL", raising=False)

        with pytest.raises(ConfigurationError, match="EZ_APPSEC_STORAGE_URL"):
            get_storage_backend()


class TestSqlBackend:
    @pytest.fixture
    def backend(self, tmp_path):
        pytest.importorskip("sqlalchemy")
        backend = SqlBackend(f"sqlite:///{tmp_path / 'storage.db'}")
        try:
            yield backend
        finally:
            backend.close()

    def test_write_and_read_findings_round_trips_models(self, backend, tmp_path):
        finding = make_finding()
        scan_record = make_scan_record()

        returned_path = backend.write_findings([finding], scan_record, tmp_path / "ignored.json")

        assert returned_path == tmp_path / "ignored.json"
        assert backend.read_findings(tmp_path) == [finding]
        assert backend.list_findings(scan_id="scan-1") == [finding]
        assert backend.list_findings(scan_id="missing") == []

    def test_write_and_read_scan_records_round_trips_models(self, backend, tmp_path):
        scan_record = make_scan_record()

        backend.write_findings([make_finding()], scan_record, tmp_path)

        assert backend.read_scan_records(tmp_path) == [scan_record]
        assert backend.get_scan_record("scan-1") == scan_record
        assert backend.get_scan_record("missing") is None
        assert backend.list_scan_records(project="demo") == [scan_record]
        assert backend.list_scan_records(project="other") == []

    def test_creates_expected_tables(self, backend):
        sqlalchemy = pytest.importorskip("sqlalchemy")

        inspector = sqlalchemy.inspect(backend.engine)
        assert set(inspector.get_table_names()) >= {"findings", "scan_records"}
