"""Storage backends for ez-appsec findings and scan records."""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Iterable, List, Mapping, Optional, Sequence, Tuple, Type

from ez_appsec.schema import FindingV2, ScanRecord, finding_from_dict, normalize_path


SCHEMA_VERSION = "2"
DEFAULT_STORAGE_BACKEND = "json"


class ConfigurationError(ValueError):
    """Raised when storage configuration is invalid or incomplete."""


class StorageBackend(ABC):
    """Abstract persistence contract for scan findings and scan records."""

    @abstractmethod
    def write_findings(
        self,
        findings: Sequence[FindingV2],
        scan_record: ScanRecord,
        path: str | Path,
    ) -> Path:
        """Write findings and their scan record to path and return the JSON file path."""

    @abstractmethod
    def read_findings(self, path: str | Path) -> List[FindingV2]:
        """Read findings from path."""

    @abstractmethod
    def read_scan_records(self, path: str | Path) -> List[ScanRecord]:
        """Read scan records from path."""

    def close(self) -> None:
        """Release backend resources, if any."""


class JsonFileBackend(StorageBackend):
    """JSON file storage compatible with the existing vulnerabilities.json output."""

    filename = "vulnerabilities.json"

    def write_findings(
        self,
        findings: Sequence[FindingV2],
        scan_record: ScanRecord,
        path: str | Path,
    ) -> Path:
        """Write findings in the legacy vulnerability report shape plus schema_version."""
        output_path = self._resolve_path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "version": "15.0.0",
            "schema_version": SCHEMA_VERSION,
            "vulnerabilities": [
                finding.model_dump(mode="json") for finding in findings
            ],
            "remediations": [],
            "scan_record": scan_record.model_dump(mode="json"),
        }

        output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return output_path

    def read_findings(self, path: str | Path) -> List[FindingV2]:
        """Read FindingV2 records from a vulnerabilities.json-compatible file."""
        payload = self._read_json(path)
        raw_findings = self._extract_findings(payload)
        return [self._parse_finding(item) for item in raw_findings]

    def read_scan_records(self, path: str | Path) -> List[ScanRecord]:
        """Read embedded scan_record or scan_records entries from a JSON file."""
        payload = self._read_json(path)
        if not isinstance(payload, Mapping):
            return []

        records: list[Any] = []
        single_record = payload.get("scan_record")
        if single_record is not None:
            records.append(single_record)

        multiple_records = payload.get("scan_records")
        if isinstance(multiple_records, list):
            records.extend(multiple_records)

        return [ScanRecord.model_validate(record) for record in records]

    def _resolve_path(self, path: str | Path) -> Path:
        output_path = Path(path)
        if output_path.suffix:
            return output_path
        return output_path / self.filename

    def _read_json(self, path: str | Path) -> Any:
        input_path = self._resolve_path(path)
        with input_path.open(encoding="utf-8") as f:
            return json.load(f)

    def _extract_findings(self, payload: Any) -> list[Mapping[str, Any]]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, Mapping)]
        if isinstance(payload, Mapping):
            vulnerabilities = payload.get("vulnerabilities", [])
            if isinstance(vulnerabilities, list):
                return [item for item in vulnerabilities if isinstance(item, Mapping)]
        return []

    def _parse_finding(self, item: Mapping[str, Any]) -> FindingV2:
        if self._looks_like_finding_v2(item):
            return FindingV2.model_validate(item)
        return finding_from_dict(self._normalize_legacy_finding(item))

    def _normalize_legacy_finding(self, item: Mapping[str, Any]) -> dict[str, Any]:
        normalized = dict(item)
        identifiers = normalized.get("identifiers")
        if isinstance(identifiers, list):
            for identifier in identifiers:
                if isinstance(identifier, Mapping) and identifier.get("value"):
                    normalized["rule_id"] = identifier["value"]
                    break
        location = normalized.get("location")
        if isinstance(location, Mapping) and location.get("file"):
            normalized["file"] = normalize_path(str(location["file"]))
        return normalized

    def _looks_like_finding_v2(self, item: Mapping[str, Any]) -> bool:
        return any(
            key in item
            for key in (
                "finding_id",
                "scan_id",
                "scan_timestamp",
                "first_seen",
                "last_seen",
                "schema_version",
            )
        )


_SQLALCHEMY_MODELS: Optional[Tuple[Any, Type[Any], Type[Any]]] = None


def _load_sqlalchemy_models() -> Tuple[Any, Type[Any], Type[Any]]:
    """Import SQLAlchemy and lazily define ORM table mappings."""

    global _SQLALCHEMY_MODELS
    if _SQLALCHEMY_MODELS is not None:
        return _SQLALCHEMY_MODELS

    try:
        from sqlalchemy import DateTime, Integer, JSON, String, Text
        from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
    except ImportError as exc:  # pragma: no cover - depends on optional dependency
        raise ConfigurationError(
            "SQL storage requires optional dependency 'sqlalchemy'. "
            "Install ez-appsec with the 'sql' extra."
        ) from exc

    class Base(DeclarativeBase):
        pass

    class FindingRow(Base):
        __tablename__ = "findings"

        finding_id: Mapped[str] = mapped_column(String(128), primary_key=True)
        scan_id: Mapped[str] = mapped_column(String(64), index=True, default="")
        rule_id: Mapped[str] = mapped_column(String(255), index=True, default="")
        file: Mapped[str] = mapped_column(Text, default="")
        line: Mapped[int] = mapped_column(Integer, default=0)
        severity: Mapped[str] = mapped_column(String(64), index=True, default="")
        category: Mapped[str] = mapped_column(String(64), index=True, default="unknown")
        trend: Mapped[str] = mapped_column(String(64), default="new")
        scan_timestamp: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
        payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    class ScanRecordRow(Base):
        __tablename__ = "scan_records"

        scan_id: Mapped[str] = mapped_column(String(64), primary_key=True)
        scan_timestamp: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
        project: Mapped[str] = mapped_column(String(255), index=True, default="")
        finding_count: Mapped[int] = mapped_column(Integer, default=0)
        new_count: Mapped[int] = mapped_column(Integer, default=0)
        resolved_count: Mapped[int] = mapped_column(Integer, default=0)
        payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    _SQLALCHEMY_MODELS = (Base, FindingRow, ScanRecordRow)
    return _SQLALCHEMY_MODELS


def _model_payload(model: Any) -> dict[str, Any]:
    """Return a JSON-safe Pydantic payload for SQL JSON columns."""

    return model.model_dump(mode="json")


class SqlBackend(StorageBackend):
    """SQLAlchemy ORM storage for FindingV2 and ScanRecord models.

    The connection URL is passed directly to SQLAlchemy, so SQLite and
    PostgreSQL URLs are both supported when the appropriate driver is installed.
    """

    filename = "sql-storage"

    def __init__(self, storage_url: str, *, create_tables: bool = True) -> None:
        if not storage_url:
            raise ConfigurationError("SQL storage requires EZ_APPSEC_STORAGE_URL to be set.")

        try:
            from sqlalchemy import create_engine, select
            from sqlalchemy.orm import sessionmaker
        except ImportError as exc:  # pragma: no cover - depends on optional dependency
            raise ConfigurationError(
                "SQL storage requires optional dependency 'sqlalchemy'. "
                "Install ez-appsec with the 'sql' extra."
            ) from exc

        self._select = select
        self._base, self._finding_row, self._scan_record_row = _load_sqlalchemy_models()
        self.engine = create_engine(storage_url, future=True)
        self._sessionmaker = sessionmaker(self.engine, future=True)
        if create_tables:
            self._base.metadata.create_all(self.engine)

    @classmethod
    def from_env(cls) -> "SqlBackend":
        """Create a SQL backend from EZ_APPSEC_STORAGE_URL."""

        storage_url = os.getenv("EZ_APPSEC_STORAGE_URL", "")
        if not storage_url:
            raise ConfigurationError("SQL storage requires EZ_APPSEC_STORAGE_URL to be set.")
        return cls(storage_url)

    def write_findings(
        self,
        findings: Sequence[FindingV2],
        scan_record: ScanRecord,
        path: str | Path,
    ) -> Path:
        """Persist a scan record and its findings in SQL tables.

        The path argument is accepted for StorageBackend compatibility and is
        returned unchanged after persistence; SQL storage location comes from the
        configured SQLAlchemy URL.
        """

        self._save_scan_record(scan_record)
        self._save_findings(findings)
        return Path(path)

    def read_findings(self, path: str | Path) -> List[FindingV2]:
        """Read all persisted findings.

        The path argument is ignored and exists only for StorageBackend
        compatibility with file-based backends.
        """

        stmt = self._select(self._finding_row).order_by(
            self._finding_row.file.asc(), self._finding_row.line.asc()
        )
        with self._sessionmaker() as session:
            return [FindingV2.model_validate(row.payload) for row in session.scalars(stmt)]

    def read_scan_records(self, path: str | Path) -> List[ScanRecord]:
        """Read all persisted scan records newest-first."""

        stmt = self._select(self._scan_record_row).order_by(
            self._scan_record_row.scan_timestamp.desc()
        )
        with self._sessionmaker() as session:
            return [ScanRecord.model_validate(row.payload) for row in session.scalars(stmt)]

    def list_findings(self, scan_id: Optional[str] = None) -> List[FindingV2]:
        """Read findings, optionally filtered by scan_id."""

        stmt = self._select(self._finding_row).order_by(
            self._finding_row.file.asc(), self._finding_row.line.asc()
        )
        if scan_id is not None:
            stmt = stmt.where(self._finding_row.scan_id == scan_id)
        with self._sessionmaker() as session:
            return [FindingV2.model_validate(row.payload) for row in session.scalars(stmt)]

    def get_scan_record(self, scan_id: str) -> Optional[ScanRecord]:
        """Read one scan record by scan_id."""

        with self._sessionmaker() as session:
            row = session.get(self._scan_record_row, scan_id)
            if row is None:
                return None
            return ScanRecord.model_validate(row.payload)

    def list_scan_records(self, project: Optional[str] = None) -> List[ScanRecord]:
        """Read scan records, optionally filtered by project."""

        stmt = self._select(self._scan_record_row).order_by(
            self._scan_record_row.scan_timestamp.desc()
        )
        if project is not None:
            stmt = stmt.where(self._scan_record_row.project == project)
        with self._sessionmaker() as session:
            return [ScanRecord.model_validate(row.payload) for row in session.scalars(stmt)]

    def close(self) -> None:
        """Dispose the SQLAlchemy engine."""

        self.engine.dispose()

    def _save_scan_record(self, scan_record: ScanRecord) -> None:
        payload = _model_payload(scan_record)
        row = self._scan_record_row(
            scan_id=scan_record.scan_id,
            scan_timestamp=scan_record.scan_timestamp,
            project=scan_record.project,
            finding_count=scan_record.finding_count,
            new_count=scan_record.new_count,
            resolved_count=scan_record.resolved_count,
            payload=payload,
        )
        with self._sessionmaker() as session:
            session.merge(row)
            session.commit()

    def _save_findings(self, findings: Iterable[FindingV2]) -> None:
        rows = []
        for finding in findings:
            finding_id = finding.finding_id or finding.compute_id()
            rows.append(
                self._finding_row(
                    finding_id=finding_id,
                    scan_id=finding.scan_id,
                    rule_id=finding.rule_id,
                    file=finding.file,
                    line=finding.line,
                    severity=finding.severity,
                    category=finding.category.value,
                    trend=finding.trend.value,
                    scan_timestamp=finding.scan_timestamp,
                    payload=_model_payload(finding),
                )
            )

        with self._sessionmaker() as session:
            for row in rows:
                session.merge(row)
            session.commit()


def get_storage_backend() -> StorageBackend:
    """Return the configured storage backend, defaulting to JSON files."""
    backend = os.getenv("EZ_APPSEC_STORAGE_BACKEND", DEFAULT_STORAGE_BACKEND).strip().lower()
    if backend in {"", "json", "jsonfile", "json-file"}:
        return JsonFileBackend()
    if backend == "sql":
        return SqlBackend.from_env()
    raise ConfigurationError(f"Unsupported EZ_APPSEC_STORAGE_BACKEND: {backend}")
