"""Tests for opt-in structured logging and OpenTelemetry attributes."""

import json
import logging

from ez_appsec.config import Config
from ez_appsec.scanner import (
    JsonLogFormatter,
    SecurityScanner,
    _build_otel_attributes,
    configure_logging_from_env,
)


def test_default_logging_configuration_unchanged(monkeypatch):
    monkeypatch.delenv("EZ_APPSEC_LOG_FORMAT", raising=False)

    assert configure_logging_from_env() is False


def test_json_log_formatter_includes_context_fields():
    formatter = JsonLogFormatter()
    record = logging.LogRecord(
        name="ez_appsec.scanner",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="Security scan completed",
        args=(),
        exc_info=None,
    )
    record.scan_id = "scan-123"
    record.finding_count = 2

    payload = json.loads(formatter.format(record))

    assert payload["level"] == "INFO"
    assert payload["message"] == "Security scan completed"
    assert payload["scan_id"] == "scan-123"
    assert payload["finding_count"] == 2
    assert "timestamp" in payload


def test_json_log_format_env_configures_existing_handlers(monkeypatch):
    monkeypatch.setenv("EZ_APPSEC_LOG_FORMAT", "json")
    root_logger = logging.getLogger()
    handler = logging.StreamHandler()
    original_handlers = root_logger.handlers[:]
    root_logger.handlers = [handler]
    try:
        assert configure_logging_from_env() is True
        assert isinstance(handler.formatter, JsonLogFormatter)
    finally:
        root_logger.handlers = original_handlers


def test_scan_tracking_populates_otel_attributes_when_sdk_available(monkeypatch):
    scanner = SecurityScanner(Config(), use_external_scanners=False)
    monkeypatch.setattr("ez_appsec.scanner._opentelemetry_sdk_available", lambda: True)
    issues = [{"rule_id": "xss", "file": "app.py", "line": 10, "severity": "high"}]

    scanner._apply_scan_tracking(issues, [], "scan-123", __import__("datetime").datetime.now(__import__("datetime").timezone.utc))

    assert issues[0]["otel_attributes"]["ez_appsec.scan_id"] == "scan-123"
    assert issues[0]["otel_attributes"]["ez_appsec.rule_id"] == "xss"
    assert issues[0]["otel_attributes"]["code.filepath"] == "app.py"


def test_scan_tracking_skips_otel_attributes_without_sdk(monkeypatch):
    scanner = SecurityScanner(Config(), use_external_scanners=False)
    monkeypatch.setattr("ez_appsec.scanner._opentelemetry_sdk_available", lambda: False)
    issues = [{"rule_id": "xss"}]

    scanner._apply_scan_tracking(issues, [], "scan-123", __import__("datetime").datetime.now(__import__("datetime").timezone.utc))

    assert "otel_attributes" not in issues[0]


def test_build_otel_attributes_omits_empty_values():
    attrs = _build_otel_attributes({"finding_id": "f1", "line": 0}, "scan-123")

    assert attrs["ez_appsec.scan_id"] == "scan-123"
    assert attrs["ez_appsec.finding_id"] == "f1"
    assert "ez_appsec.rule_id" not in attrs
