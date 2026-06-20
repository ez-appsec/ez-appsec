"""Triggers ez-appsec scans as subprocesses and tracks job state."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Hard cap on retained jobs so _jobs cannot grow without bound. Older finished
# jobs are evicted first when the cap is exceeded.
_MAX_JOBS = 1000
# Drop completed/failed jobs older than this many seconds during sweeps.
_JOB_TTL_SECONDS = 60 * 60 * 24  # 24h

_VALID_SEVERITIES = {"all", "low", "medium", "high", "critical"}
_GIT_URL_PREFIXES = ("http://", "https://", "ssh://", "git://")


def _allowed_roots() -> list[Path]:
    """Return configured scan roots from EZ_APPSEC_ALLOWED_ROOTS (colon-separated).

    Empty list means "no allowlist enforced". Roots are resolved to absolute
    paths so symlinks/relative entries behave predictably.
    """
    raw = os.environ.get("EZ_APPSEC_ALLOWED_ROOTS", "").strip()
    if not raw:
        return []
    return [Path(entry).expanduser().resolve() for entry in raw.split(":") if entry.strip()]


def _is_within_allowed_roots(path: str) -> bool:
    roots = _allowed_roots()
    if not roots:
        return True
    try:
        resolved = Path(path).expanduser().resolve()
    except (OSError, RuntimeError):
        return False
    for root in roots:
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _is_git_url(path: str) -> bool:
    value = path.strip().lower()
    return value.startswith(_GIT_URL_PREFIXES)


def _validate_scan_path(path: str) -> None:
    """Reject dangerous scan targets before they reach a subprocess.

    - Leading-dash paths are flag-injection vectors for git and ez-appsec.
    - SSH-style git URLs (git@host:repo) require key material the API process
      does not have; reject with a clear message instead of a confusing failure.
    - When EZ_APPSEC_ALLOWED_ROOTS is set, local paths must live under a root.
    """
    stripped = path.strip()
    if not stripped:
        raise ValueError("scan path must not be empty")
    if stripped.startswith("-"):
        raise ValueError("scan path must not start with '-'")
    if stripped.lower().startswith("git@"):
        raise ValueError("SSH git URLs (git@host:repo) are not supported; use an https:// URL instead")
    if not _is_git_url(stripped) and not _is_within_allowed_roots(stripped):
        raise ValueError("scan path is outside EZ_APPSEC_ALLOWED_ROOTS")


def _validate_severity(severity: str) -> str:
    key = (severity or "all").strip().lower()
    if key not in _VALID_SEVERITIES:
        raise ValueError(f"severity must be one of {sorted(_VALID_SEVERITIES)}, got {severity!r}")
    return key


@dataclass
class _Job:
    job_id: str
    path: str = ""
    severity: str = "all"
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    result: dict[str, Any] | None = None
    error: str | None = None


_jobs: dict[str, _Job] = {}
_lock = threading.Lock()
# Bounded worker pool prevents unbounded thread/subprocess fan-out under load.
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ez-appsec-scan")


def _prepare_scan_path(path: str, workspace: Path) -> str:
    if not _is_git_url(path):
        return path

    clone_dir = workspace / "repo"
    # `--` terminates option parsing so a URL beginning with '-' cannot be
    # interpreted as a git flag (e.g. --upload-pack RCE).
    proc = subprocess.run(
        ["git", "clone", "--depth", "1", "--", path, str(clone_dir)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout or "git clone failed")
    return str(clone_dir)


def _sweep_locked(now: float) -> None:
    """Evict finished jobs past their TTL or beyond the cap. Caller holds _lock.

    Eviction target is _MAX_JOBS - 1 so there is always room for the job the
    caller is about to insert. TTL-based eviction runs every sweep; cap-based
    eviction only kicks in once the store is at the cap.
    """
    # TTL sweep first.
    stale = [
        jid
        for jid, job in _jobs.items()
        if job.status in {"complete", "failed"}
        and job.finished_at is not None
        and now - job.finished_at > _JOB_TTL_SECONDS
    ]
    for jid in stale:
        _jobs.pop(jid, None)

    if len(_jobs) >= _MAX_JOBS:
        target = _MAX_JOBS - 1
        finished = [(jid, job) for jid, job in _jobs.items() if job.status in {"complete", "failed"}]
        finished.sort(key=lambda item: item[1].finished_at or item[1].created_at)
        to_remove = max(0, len(_jobs) - target)
        for jid, _job in finished[:to_remove]:
            _jobs.pop(jid, None)


def submit_scan(path: str, severity: str = "all") -> str:
    """Validate inputs, enqueue the scan, and return the job id.

    Raises ValueError on invalid path/severity so the FastAPI layer can map it
    to a 4xx without a try/except swallowing programming errors.
    """
    clean_path = path.strip() if isinstance(path, str) else ""
    clean_severity = _validate_severity(severity)
    _validate_scan_path(clean_path)

    job_id = uuid.uuid4().hex[:12]
    job = _Job(job_id=job_id, path=clean_path, severity=clean_severity)
    with _lock:
        _sweep_locked(now=time.time())
        _jobs[job_id] = job
    _executor.submit(_run, job)
    return job_id


def get_job(job_id: str) -> dict[str, Any] | None:
    with _lock:
        job = _jobs.get(job_id)
        if job is None:
            return None
        out: dict[str, Any] = {
            "job_id": job.job_id,
            "status": job.status,
        }
        if job.result is not None:
            out["result"] = job.result
        if job.error is not None:
            out["error"] = job.error
        return out


def _run(job: _Job) -> None:
    # Mark running under the lock; subprocess + file I/O happen outside the
    # lock so concurrent status reads are not serialized.
    with _lock:
        job.status = "running"
    try:
        with tempfile.TemporaryDirectory(prefix="ez-appsec-api-") as workspace:
            workspace_path = Path(workspace)
            output_dir = workspace_path / "results"
            scan_path = _prepare_scan_path(job.path, workspace_path)
            # `--` before the scan path prevents a path that begins with '-'
            # from being interpreted as an ez-appsec flag.
            cmd = ["ez-appsec", "scan", "--", scan_path, "--output", str(output_dir)]
            if job.severity != "all":
                cmd.extend(["--severity", job.severity])
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            # Read results outside the lock; only mutate job state inside it.
            new_result: dict[str, Any] | None = None
            new_error: str | None = None
            new_status: str
            if proc.returncode == 0:
                results_path = output_dir / "vulnerabilities.json"
                try:
                    with results_path.open(encoding="utf-8") as fh:
                        new_result = json.load(fh)
                    new_status = "complete"
                except Exception as exc:
                    new_error = f"scan completed but results could not be read: {exc}"
                    new_status = "failed"
            else:
                new_error = proc.stderr or proc.stdout or "scan exited non-zero"
                new_status = "failed"

            with _lock:
                job.result = new_result
                job.error = new_error
                job.status = new_status
                job.finished_at = time.time()
    except subprocess.TimeoutExpired:
        with _lock:
            job.error = "scan timed out after 600s"
            job.status = "failed"
            job.finished_at = time.time()
    except FileNotFoundError:
        with _lock:
            job.error = "ez-appsec CLI not found on PATH"
            job.status = "failed"
            job.finished_at = time.time()
    except Exception as exc:
        with _lock:
            job.error = str(exc)
            job.status = "failed"
            job.finished_at = time.time()
