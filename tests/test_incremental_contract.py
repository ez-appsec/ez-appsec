"""M036 S03 portable scan-plan and result-envelope contract."""

import hashlib
import itertools
import json
import subprocess

from click.testing import CliRunner

from ez_appsec.cli import main
from ez_appsec.external_scanners import GitleaksScanner
from ez_appsec.incremental_contract import IncrementalContractError, validate_result_envelope


SCANNER_IMAGE = "ghcr.io/ez-appsec/ez-appsec@sha256:" + "1" * 64


def _canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _git(path, *args):
    return subprocess.run(
        ["git", "-C", str(path), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _source_tree(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "-b", "main")
    _git(source, "config", "user.name", "M036")
    _git(source, "config", "user.email", "m036@example.invalid")
    (source / "app.py").write_text("print('safe')\n", encoding="utf-8")
    _git(source, "add", "app.py")
    _git(source, "commit", "-m", "fixture")
    return source, _git(source, "rev-parse", "HEAD")


def _full_plan(head_sha):
    body = {
        "schema_version": "sourcebastion.scan-plan.v1",
        "job_id": "job-1",
        "account_id": "account-1",
        "source": {
            "provider_host": "github.com",
            "repository_id": "repository-1",
            "ref": "refs/heads/main",
            "head_sha": head_sha,
        },
        "created_at": "2026-09-11T00:00:00Z",
        "baseline": None,
        "scanner": {
            "image": SCANNER_IMAGE,
            "result_schema_version": "sourcebastion.scan-result.v1",
            "finding_identity_version": "finding-v2",
            "config_digest": "sha256:" + "2" * 64,
            "enabled_components": ["gitleaks"],
        },
        "mode": "full",
        "components": [
            {
                "name": "gitleaks",
                "mode": "full",
                "reason": "capability_full_only",
                "compatibility_key": "3" * 64,
                "covered_paths": [],
                "deleted_paths": [],
                "iac_units": [],
            }
        ],
        "limits": {
            "max_execution_seconds": 1800,
            "max_findings": 100,
            "max_path_bytes": 4096,
            "max_scope_entries": 100,
            "max_source_bytes": 1024 * 1024,
        },
    }
    return {
        **body,
        "plan_digest": hashlib.sha256(_canonical(body)).hexdigest(),
    }


def _redigest(plan):
    body = {key: value for key, value in plan.items() if key != "plan_digest"}
    plan["plan_digest"] = hashlib.sha256(_canonical(body)).hexdigest()
    return plan


def test_contract_scan_executes_full_plan_and_emits_bound_envelope(tmp_path, monkeypatch):
    source, head_sha = _source_tree(tmp_path)
    plan = _full_plan(head_sha)
    plan_path = tmp_path / "plan.json"
    result_path = tmp_path / "result.json"
    plan_path.write_bytes(_canonical(plan))
    monkeypatch.setattr(
        GitleaksScanner,
        "scan",
        lambda self, path: [
            {
                "scanner": "gitleaks",
                "rule_id": "generic-api-key",
                "file": "app.py",
                "line": 1,
                "severity": "critical",
                "title": "Example",
                "description": "bounded finding",
            }
        ],
    )

    result = CliRunner().invoke(
        main,
        [
            "contract-scan",
            str(source),
            "--plan",
            str(plan_path),
            "--result-envelope",
            str(result_path),
            "--scanner-image",
            SCANNER_IMAGE,
        ],
    )

    assert result.exit_code == 0, result.output
    envelope = json.loads(result_path.read_text(encoding="utf-8"))
    assert envelope["schema_version"] == "sourcebastion.scan-result.v1"
    assert envelope["observed_head_sha"] == head_sha
    assert envelope["plan_digest"] == plan["plan_digest"]
    assert envelope["scanner_image"] == SCANNER_IMAGE
    assert envelope["components"] == [
        {
            "name": "gitleaks",
            "status": "complete",
            "compatibility_key": "3" * 64,
            "covered_paths": [],
            "deleted_paths": [],
            "iac_units": [],
            "findings": [
                {
                    "scanner": "gitleaks",
                    "rule_id": "generic-api-key",
                    "file": "app.py",
                    "line": 1,
                    "severity": "critical",
                    "title": "Example",
                    "description": "bounded finding",
                }
            ],
            "diagnostic_code": None,
        }
    ]
    digest = envelope.pop("result_digest")
    assert digest == hashlib.sha256(_canonical(envelope)).hexdigest()


def test_contract_scan_rejects_malformed_plan_with_bounded_error(tmp_path):
    source, head_sha = _source_tree(tmp_path)
    plan = _full_plan(head_sha)
    del plan["components"]
    _redigest(plan)
    plan_path = tmp_path / "plan.json"
    plan_path.write_bytes(_canonical(plan))

    result = CliRunner().invoke(
        main,
        [
            "contract-scan",
            str(source),
            "--plan",
            str(plan_path),
            "--result-envelope",
            str(tmp_path / "result.json"),
            "--scanner-image",
            SCANNER_IMAGE,
        ],
    )

    assert result.exit_code == 1
    assert "scan_plan_invalid" in result.output
    assert "components" not in result.output


def test_contract_scan_marks_unimplemented_partial_scope_not_run(tmp_path):
    source, head_sha = _source_tree(tmp_path)
    plan = _full_plan(head_sha)
    plan["mode"] = "incremental"
    plan["baseline"] = {
        "run_id": 7,
        "sha": head_sha,
        "age_seconds": 60,
        "same_ref": True,
        "ancestor": True,
        "applied": True,
        "complete": True,
    }
    plan["components"][0].update(
        {
            "mode": "partial",
            "reason": "component_scope_changed",
            "covered_paths": ["app.py"],
        }
    )
    _redigest(plan)
    plan_path = tmp_path / "plan.json"
    result_path = tmp_path / "result.json"
    plan_path.write_bytes(_canonical(plan))

    result = CliRunner().invoke(
        main,
        [
            "contract-scan",
            str(source),
            "--plan",
            str(plan_path),
            "--result-envelope",
            str(result_path),
            "--scanner-image",
            SCANNER_IMAGE,
        ],
    )

    assert result.exit_code == 1
    envelope = json.loads(result_path.read_text(encoding="utf-8"))
    assert envelope["components"][0]["status"] == "not_run"
    assert envelope["components"][0]["diagnostic_code"] == "unsupported_mode"
    assert envelope["components"][0]["findings"] == []


def test_contract_scan_rejects_traversal_scope_before_execution(tmp_path, monkeypatch):
    source, head_sha = _source_tree(tmp_path)
    plan = _full_plan(head_sha)
    plan["mode"] = "incremental"
    plan["baseline"] = {
        "run_id": 7,
        "sha": head_sha,
        "age_seconds": 60,
        "same_ref": True,
        "ancestor": True,
        "applied": True,
        "complete": True,
    }
    plan["components"][0].update(
        {
            "mode": "partial",
            "reason": "component_scope_changed",
            "covered_paths": ["../outside.py"],
        }
    )
    _redigest(plan)
    plan_path = tmp_path / "plan.json"
    plan_path.write_bytes(_canonical(plan))
    invoked = []
    monkeypatch.setattr(GitleaksScanner, "scan", lambda self, path: invoked.append(path))

    result = CliRunner().invoke(
        main,
        [
            "contract-scan",
            str(source),
            "--plan",
            str(plan_path),
            "--result-envelope",
            str(tmp_path / "result.json"),
            "--scanner-image",
            SCANNER_IMAGE,
        ],
    )

    assert result.exit_code == 1
    assert "scan_plan_invalid" in result.output
    assert invoked == []


def test_contract_scan_enforces_source_byte_limit_before_execution(tmp_path, monkeypatch):
    source, head_sha = _source_tree(tmp_path)
    plan = _full_plan(head_sha)
    plan["limits"]["max_source_bytes"] = 1
    _redigest(plan)
    plan_path = tmp_path / "plan.json"
    plan_path.write_bytes(_canonical(plan))
    invoked = []
    monkeypatch.setattr(GitleaksScanner, "scan", lambda self, path: invoked.append(path))

    result = CliRunner().invoke(
        main,
        [
            "contract-scan",
            str(source),
            "--plan",
            str(plan_path),
            "--result-envelope",
            str(tmp_path / "result.json"),
            "--scanner-image",
            SCANNER_IMAGE,
        ],
    )

    assert result.exit_code == 1
    assert "source_limit_exceeded" in result.output
    assert invoked == []


def test_contract_scan_discards_findings_that_exceed_plan_limit(tmp_path, monkeypatch):
    source, head_sha = _source_tree(tmp_path)
    plan = _full_plan(head_sha)
    plan["limits"]["max_findings"] = 1
    _redigest(plan)
    plan_path = tmp_path / "plan.json"
    result_path = tmp_path / "result.json"
    plan_path.write_bytes(_canonical(plan))
    monkeypatch.setattr(
        GitleaksScanner,
        "scan",
        lambda self, path: [
            {"scanner": "gitleaks", "file": "app.py", "rule_id": "one"},
            {"scanner": "gitleaks", "file": "app.py", "rule_id": "two"},
        ],
    )

    result = CliRunner().invoke(
        main,
        [
            "contract-scan",
            str(source),
            "--plan",
            str(plan_path),
            "--result-envelope",
            str(result_path),
            "--scanner-image",
            SCANNER_IMAGE,
        ],
    )

    assert result.exit_code == 1
    component = json.loads(result_path.read_text(encoding="utf-8"))["components"][0]
    assert component["status"] == "failed"
    assert component["diagnostic_code"] == "findings_limit_exceeded"
    assert component["findings"] == []


def test_contract_scan_bounds_unexpected_component_failure(tmp_path, monkeypatch):
    source, head_sha = _source_tree(tmp_path)
    plan = _full_plan(head_sha)
    plan_path = tmp_path / "plan.json"
    result_path = tmp_path / "result.json"
    plan_path.write_bytes(_canonical(plan))

    def fail(_self, _path):
        raise RuntimeError("customer-secret-must-not-escape")

    monkeypatch.setattr(GitleaksScanner, "scan", fail)
    result = CliRunner().invoke(
        main,
        [
            "contract-scan",
            str(source),
            "--plan",
            str(plan_path),
            "--result-envelope",
            str(result_path),
            "--scanner-image",
            SCANNER_IMAGE,
        ],
    )

    assert result.exit_code == 1
    component = json.loads(result_path.read_text(encoding="utf-8"))["components"][0]
    assert component["status"] == "failed"
    assert component["diagnostic_code"] == "execution_failed"
    assert "customer-secret" not in result.output
    assert "customer-secret" not in result_path.read_text(encoding="utf-8")


def test_contract_scan_rejects_cross_component_findings(tmp_path, monkeypatch):
    source, head_sha = _source_tree(tmp_path)
    plan = _full_plan(head_sha)
    plan_path = tmp_path / "plan.json"
    result_path = tmp_path / "result.json"
    plan_path.write_bytes(_canonical(plan))
    monkeypatch.setattr(
        GitleaksScanner,
        "scan",
        lambda self, path: [
            {"scanner": "semgrep", "file": "app.py", "rule_id": "wrong-owner"}
        ],
    )

    result = CliRunner().invoke(
        main,
        [
            "contract-scan",
            str(source),
            "--plan",
            str(plan_path),
            "--result-envelope",
            str(result_path),
            "--scanner-image",
            SCANNER_IMAGE,
        ],
    )

    assert result.exit_code == 1
    component = json.loads(result_path.read_text(encoding="utf-8"))["components"][0]
    assert component["status"] == "failed"
    assert component["diagnostic_code"] == "finding_ownership_mismatch"
    assert component["findings"] == []


def test_gitleaks_contract_finding_never_contains_detected_secret(tmp_path, monkeypatch):
    secret = "sb_live_customer_secret_value"
    scanner = GitleaksScanner()
    monkeypatch.setattr(scanner, "is_installed", lambda: True)

    def write_report(command, **_kwargs):
        report_path = command[command.index("--report-path") + 1]
        with open(report_path, "w", encoding="utf-8") as report:
            json.dump(
                [
                    {
                        "RuleID": "generic-api-key",
                        "Match": secret,
                        "File": "app.py",
                        "StartLine": 1,
                    }
                ],
                report,
            )
        return subprocess.CompletedProcess(command, 1, "", "")

    monkeypatch.setattr("ez_appsec.external_scanners.subprocess.run", write_report)
    findings = scanner.scan(str(tmp_path))

    assert len(findings) == 1
    assert secret not in json.dumps(findings)
    assert "redacted" in findings[0]["description"]


def test_result_validator_rejects_envelope_bound_to_another_plan(tmp_path, monkeypatch):
    source, head_sha = _source_tree(tmp_path)
    plan = _full_plan(head_sha)
    plan_path = tmp_path / "plan.json"
    result_path = tmp_path / "result.json"
    plan_path.write_bytes(_canonical(plan))
    monkeypatch.setattr(GitleaksScanner, "scan", lambda self, path: [])
    result = CliRunner().invoke(
        main,
        [
            "contract-scan",
            str(source),
            "--plan",
            str(plan_path),
            "--result-envelope",
            str(result_path),
            "--scanner-image",
            SCANNER_IMAGE,
        ],
    )
    assert result.exit_code == 0, result.output
    envelope = json.loads(result_path.read_text(encoding="utf-8"))
    envelope["plan_digest"] = "f" * 64
    body = {key: value for key, value in envelope.items() if key != "result_digest"}
    envelope["result_digest"] = hashlib.sha256(_canonical(body)).hexdigest()

    try:
        validate_result_envelope(envelope, plan)
    except IncrementalContractError as exc:
        assert str(exc) == "result_binding_mismatch"
    else:
        raise AssertionError("tampered result binding was accepted")


def test_contract_scan_marks_execution_over_deadline_incomplete(tmp_path, monkeypatch):
    source, head_sha = _source_tree(tmp_path)
    plan = _full_plan(head_sha)
    plan["limits"]["max_execution_seconds"] = 1
    _redigest(plan)
    plan_path = tmp_path / "plan.json"
    result_path = tmp_path / "result.json"
    plan_path.write_bytes(_canonical(plan))
    monkeypatch.setattr(GitleaksScanner, "scan", lambda self, path: [])
    ticks = iter([0.0, 2.0])
    monkeypatch.setattr(
        "ez_appsec.incremental_contract.time.monotonic",
        lambda: next(ticks),
    )

    result = CliRunner().invoke(
        main,
        [
            "contract-scan",
            str(source),
            "--plan",
            str(plan_path),
            "--result-envelope",
            str(result_path),
            "--scanner-image",
            SCANNER_IMAGE,
        ],
    )

    assert result.exit_code == 1
    component = json.loads(result_path.read_text(encoding="utf-8"))["components"][0]
    assert component["status"] == "failed"
    assert component["diagnostic_code"] == "execution_limit_exceeded"


def test_contract_scan_rejects_duplicate_json_keys(tmp_path):
    source, head_sha = _source_tree(tmp_path)
    encoded = _canonical(_full_plan(head_sha)).decode("utf-8")
    encoded = encoded.replace(
        '"job_id":"job-1"',
        '"job_id":"shadow-job","job_id":"job-1"',
        1,
    )
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(encoded, encoding="utf-8")

    result = CliRunner().invoke(
        main,
        [
            "contract-scan",
            str(source),
            "--plan",
            str(plan_path),
            "--result-envelope",
            str(tmp_path / "result.json"),
            "--scanner-image",
            SCANNER_IMAGE,
        ],
    )

    assert result.exit_code == 1
    assert "scan_plan_invalid" in result.output
