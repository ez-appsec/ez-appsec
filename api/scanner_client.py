"""Triggers ez-appsec scans as subprocesses and tracks job state."""

from __future__ import annotations

import subprocess
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class _Job:
    job_id: str
    status: str = "queued"
    path: str = ""
    severity: str = "all"
    result: dict[str, Any] | None = None
    error: str | None = None


_jobs: dict[str, _Job] = {}
_lock = threading.Lock()


def submit_scan(path: str, severity: str = "all") -> str:
    job_id = uuid.uuid4().hex[:12]
    job = _Job(job_id=job_id, path=path, severity=severity)
    with _lock:
        _jobs[job_id] = job
    t = threading.Thread(target=_run, args=(job,), daemon=True)
    t.start()
    return job_id


def get_job(job_id: str) -> dict[str, Any] | None:
    with _lock:
        job = _jobs.get(job_id)
    if job is None:
        return None
    out: dict[str, Any] = {"job_id": job.job_id, "status": job.status}
    if job.result is not None:
        out["result"] = job.result
    if job.error is not None:
        out["error"] = job.error
    return out


def _run(job: _Job) -> None:
    with _lock:
        job.status = "running"
    try:
        cmd = ["ez-appsec", "scan", job.path, "--output", "json"]
        if job.severity != "all":
            cmd.extend(["--severity", job.severity])
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        with _lock:
            if proc.returncode == 0:
                import json

                try:
                    job.result = json.loads(proc.stdout)
                except Exception:
                    job.result = {"raw": proc.stdout}
                job.status = "complete"
            else:
                job.error = proc.stderr or proc.stdout or "scan exited non-zero"
                job.status = "failed"
    except subprocess.TimeoutExpired:
        with _lock:
            job.error = "scan timed out after 600s"
            job.status = "failed"
    except FileNotFoundError:
        with _lock:
            job.error = "ez-appsec CLI not found on PATH"
            job.status = "failed"
    except Exception as e:
        with _lock:
            job.error = str(e)
            job.status = "failed"
