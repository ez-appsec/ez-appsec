"""Triggers ez-appsec scans as subprocesses and tracks job state."""

from __future__ import annotations

import json
import subprocess
import tempfile
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
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


def _is_git_url(path: str) -> bool:
    value = path.strip().lower()
    return value.startswith(("http://", "https://", "ssh://", "git://")) or value.startswith("git@")


def _prepare_scan_path(path: str, workspace: Path) -> str:
    if not _is_git_url(path):
        return path

    clone_dir = workspace / "repo"
    proc = subprocess.run(
        ["git", "clone", "--depth", "1", path, str(clone_dir)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout or "git clone failed")
    return str(clone_dir)


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
        with tempfile.TemporaryDirectory(prefix="ez-appsec-api-") as workspace:
            workspace_path = Path(workspace)
            output_dir = workspace_path / "results"
            scan_path = _prepare_scan_path(job.path, workspace_path)
            cmd = ["ez-appsec", "scan", scan_path, "--output", str(output_dir)]
            if job.severity != "all":
                cmd.extend(["--severity", job.severity])
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            with _lock:
                if proc.returncode == 0:
                    results_path = output_dir / "vulnerabilities.json"
                    try:
                        with results_path.open(encoding="utf-8") as fh:
                            job.result = json.load(fh)
                        job.status = "complete"
                    except Exception as exc:
                        job.error = f"scan completed but results could not be read: {exc}"
                        job.status = "failed"
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
