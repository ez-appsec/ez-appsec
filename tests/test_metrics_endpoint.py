"""Tests for the Prometheus metrics endpoint."""

from datetime import datetime, timezone

import pytest

from ez_appsec.schema import Category, FindingV2, ScanRecord, Trend
from ez_appsec.storage import JsonFileBackend


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
    }
    data.update(overrides)
    return FindingV2(**data)


def make_scan_record(**overrides):
    data = {
        "scan_id": "scan-1",
        "scan_timestamp": datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        "project": "demo-project",
        "scanner_versions": {"semgrep": "1.99.0"},
        "finding_count": 3,
        "schema_version": "2",
    }
    data.update(overrides)
    return ScanRecord(**data)


def test_module_imports_without_prometheus_client():
    from ez_appsec import metrics_endpoint

    assert metrics_endpoint.METRIC_NAME == "ez_appsec_findings_total"


def test_missing_prometheus_client_raises_clear_error(monkeypatch):
    from ez_appsec import metrics_endpoint

    monkeypatch.setattr(metrics_endpoint, "CollectorRegistry", None)
    monkeypatch.setattr(metrics_endpoint, "Gauge", None)
    monkeypatch.setattr(metrics_endpoint, "generate_latest", None)

    with pytest.raises(metrics_endpoint.MetricsDependencyError, match=r"ez-appsec\[metrics\]"):
        metrics_endpoint.render_metrics("vulnerabilities.json", backend=JsonFileBackend())


def test_render_metrics_groups_findings_by_severity_category_and_project(tmp_path):
    pytest.importorskip("prometheus_client")
    from ez_appsec.metrics_endpoint import render_metrics

    backend = JsonFileBackend()
    findings_path = tmp_path / "vulnerabilities.json"
    findings = [
        make_finding(finding_id="finding-1", severity="high", category=Category.sast),
        make_finding(finding_id="finding-2", severity="high", category=Category.sast),
        make_finding(finding_id="finding-3", severity="low", category=Category.secrets),
    ]
    backend.write_findings(findings, make_scan_record(project="checkout-api"), findings_path)

    output = render_metrics(findings_path, backend=backend).decode("utf-8")

    assert "# HELP ez_appsec_findings_total" in output
    assert (
        'ez_appsec_findings_total{category="sast",project="checkout-api",severity="high"} 2.0'
        in output
    )
    assert (
        'ez_appsec_findings_total{category="secrets",project="checkout-api",severity="low"} 1.0'
        in output
    )
