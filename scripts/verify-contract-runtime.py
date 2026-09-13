#!/usr/bin/env python3
"""Exercise every standard-image component through the networkless M036 contract."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from ez_appsec.incremental_contract import canonical_json, execute_scan_plan


SCANNER_IMAGE = "ghcr.io/ez-appsec/ez-appsec@sha256:" + "a" * 64
COMPONENTS = ("custom_php", "gitleaks", "grype", "kics", "semgrep")


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return completed.stdout.strip()


def _plan(head_sha: str) -> dict:
    body = {
        "schema_version": "sourcebastion.scan-plan.v1",
        "job_id": "standard-image-smoke",
        "account_id": "standard-image-smoke",
        "source": {
            "provider_host": "github.com",
            "repository_id": "standard-image-smoke",
            "ref": "refs/heads/main",
            "head_sha": head_sha,
        },
        "created_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "baseline": None,
        "scanner": {
            "image": SCANNER_IMAGE,
            "result_schema_version": "sourcebastion.scan-result.v1",
            "finding_identity_version": "finding-id.v2",
            "config_digest": "sha256:" + "b" * 64,
            "enabled_components": list(COMPONENTS),
        },
        "mode": "full",
        "components": [
            {
                "name": name,
                "mode": "full",
                "reason": "no_compatible_baseline",
                "compatibility_key": "c" * 64,
                "covered_paths": [],
                "deleted_paths": [],
                "iac_units": [],
            }
            for name in COMPONENTS
        ],
        "limits": {
            "max_execution_seconds": 1800,
            "max_findings": 100_000,
            "max_path_bytes": 2 * 1024 * 1024,
            "max_scope_entries": 10_000,
            "max_source_bytes": 512 * 1024 * 1024,
        },
    }
    return {
        **body,
        "plan_digest": hashlib.sha256(canonical_json(body)).hexdigest(),
    }


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="contract-runtime-smoke-") as raw:
        repository = Path(raw)
        _git(repository, "init", "-q", "-b", "main")
        _git(repository, "config", "user.name", "Contract smoke")
        _git(repository, "config", "user.email", "contract-smoke@example.test")
        (repository / "app.py").write_text(
            'print("networkless contract smoke")\n', encoding="utf-8"
        )
        (repository / "package-lock.json").write_text(
            json.dumps(
                {
                    "name": "contract-runtime-smoke",
                    "version": "1.0.0",
                    "lockfileVersion": 3,
                    "requires": True,
                    "packages": {
                        "": {
                            "name": "contract-runtime-smoke",
                            "version": "1.0.0",
                            "dependencies": {"lodash": "4.17.19"},
                        },
                        "node_modules/lodash": {"version": "4.17.19"},
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        _git(repository, "add", "app.py", "package-lock.json")
        _git(repository, "commit", "-q", "-m", "contract smoke")
        envelope = execute_scan_plan(
            str(repository), _plan(_git(repository, "rev-parse", "HEAD")), SCANNER_IMAGE
        )

    statuses = {
        component["name"]: component["status"]
        for component in envelope["components"]
    }
    if statuses != {name: "complete" for name in COMPONENTS}:
        diagnostics = {
            component["name"]: component["diagnostic_code"]
            for component in envelope["components"]
        }
        raise SystemExit(
            "networkless contract smoke incomplete: "
            + json.dumps(diagnostics, sort_keys=True)
        )
    grype = next(
        component for component in envelope["components"] if component["name"] == "grype"
    )
    if not grype["findings"]:
        raise SystemExit("networkless contract smoke missed the locked vulnerable package")
    print("networkless contract smoke complete: " + ", ".join(COMPONENTS))


if __name__ == "__main__":
    main()
