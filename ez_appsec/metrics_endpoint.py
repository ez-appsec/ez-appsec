"""Prometheus metrics endpoint for ez-appsec findings."""

from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterable, Optional, Type

from ez_appsec.schema import FindingV2
from ez_appsec.storage import StorageBackend, get_storage_backend

try:  # Optional dependency; importable without the metrics extra installed.
    from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Gauge, generate_latest
except ImportError:  # pragma: no cover - constants are exercised via require_prometheus tests.
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"
    CollectorRegistry = None  # type: ignore[assignment]
    Gauge = None  # type: ignore[assignment]
    generate_latest = None  # type: ignore[assignment]

DEFAULT_FINDINGS_PATH = "vulnerabilities.json"
DEFAULT_PROJECT = "unknown"
METRIC_NAME = "ez_appsec_findings_total"


class MetricsDependencyError(RuntimeError):
    """Raised when prometheus_client is required but not installed."""


def require_prometheus() -> None:
    """Raise a clear error if prometheus_client is unavailable."""
    if CollectorRegistry is None or Gauge is None or generate_latest is None:
        raise MetricsDependencyError(
            "Prometheus metrics require the optional dependency 'prometheus_client'. "
            "Install ez-appsec with the metrics extra, for example: pip install 'ez-appsec[metrics]'."
        )


def _label_value(value: object, default: str = "unknown") -> str:
    if value is None:
        return default
    text = getattr(value, "value", value)
    text = str(text).strip()
    return text or default


def _resolve_project(
    backend: StorageBackend,
    storage_path: str | Path,
    explicit_project: Optional[str],
) -> str:
    if explicit_project:
        return explicit_project

    env_project = os.getenv("EZ_APPSEC_PROJECT")
    if env_project:
        return env_project

    try:
        records = backend.read_scan_records(storage_path)
    except Exception:
        return DEFAULT_PROJECT

    for record in records:
        project = _label_value(getattr(record, "project", None), default="")
        if project:
            return project
    return DEFAULT_PROJECT


def collect_findings(
    storage_path: str | Path = DEFAULT_FINDINGS_PATH,
    *,
    backend: Optional[StorageBackend] = None,
) -> list[FindingV2]:
    """Read findings from the configured storage backend."""
    selected_backend = backend or get_storage_backend()
    return selected_backend.read_findings(storage_path)


def render_metrics(
    storage_path: str | Path = DEFAULT_FINDINGS_PATH,
    *,
    backend: Optional[StorageBackend] = None,
    project: Optional[str] = None,
) -> bytes:
    """Render ez-appsec findings in Prometheus text exposition format."""
    require_prometheus()

    selected_backend = backend or get_storage_backend()
    findings = selected_backend.read_findings(storage_path)
    project_label = _resolve_project(selected_backend, storage_path, project)

    registry = CollectorRegistry()
    gauge = Gauge(
        METRIC_NAME,
        "Number of ez-appsec findings grouped by severity, category, and project.",
        ["severity", "category", "project"],
        registry=registry,
    )

    counts: dict[tuple[str, str, str], int] = {}
    for finding in findings:
        key = (
            _label_value(finding.severity),
            _label_value(finding.category),
            project_label,
        )
        counts[key] = counts.get(key, 0) + 1

    for (severity, category, project_name), count in sorted(counts.items()):
        gauge.labels(severity=severity, category=category, project=project_name).set(count)

    return generate_latest(registry)


def make_metrics_handler(
    storage_path: str | Path = DEFAULT_FINDINGS_PATH,
    *,
    backend: Optional[StorageBackend] = None,
    project: Optional[str] = None,
) -> Type[BaseHTTPRequestHandler]:
    """Create a BaseHTTPRequestHandler subclass serving GET /metrics."""

    class MetricsHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path.split("?", 1)[0] != "/metrics":
                self.send_error(404, "Not Found")
                return

            try:
                body = render_metrics(storage_path, backend=backend, project=project)
            except MetricsDependencyError as exc:
                body = f"{exc}\n".encode("utf-8")
                self.send_response(503)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE_LATEST)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            """Keep the standalone handler quiet by default."""
            return

    return MetricsHandler


def serve_metrics(
    host: str = "127.0.0.1",
    port: int = 9108,
    *,
    storage_path: str | Path = DEFAULT_FINDINGS_PATH,
    backend: Optional[StorageBackend] = None,
    project: Optional[str] = None,
) -> ThreadingHTTPServer:
    """Start a blocking HTTP server exposing GET /metrics."""
    handler = make_metrics_handler(storage_path, backend=backend, project=project)
    server = ThreadingHTTPServer((host, port), handler)
    server.serve_forever()
    return server


__all__ = [
    "DEFAULT_FINDINGS_PATH",
    "METRIC_NAME",
    "MetricsDependencyError",
    "collect_findings",
    "make_metrics_handler",
    "render_metrics",
    "require_prometheus",
    "serve_metrics",
]
