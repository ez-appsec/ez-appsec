"""M036 S03 portable scan-plan and result-envelope contract."""

import hashlib
import json
import subprocess
from pathlib import Path

from click.testing import CliRunner

from ez_appsec.cli import main
from ez_appsec.external_scanners import (
    GitleaksScanner,
    KicsScanner,
    PHPVulnScanner,
    SemgrepScanner,
)
from ez_appsec.incremental_contract import IncrementalContractError, validate_result_envelope
from ez_appsec.schema import compute_finding_id


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


def _partial_sast_plan(head_sha):
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
    plan["scanner"]["enabled_components"] = ["gitleaks", "semgrep"]
    plan["components"] = [
        {
            "name": name,
            "mode": "partial",
            "reason": "component_scope_changed",
            "compatibility_key": digit * 64,
            "covered_paths": ["app.py"],
            "deleted_paths": [],
            "iac_units": [],
        }
        for name, digit in (("gitleaks", "3"), ("semgrep", "4"))
    ]
    return _redigest(plan)


def _partial_kics_plan(head_sha, *, units=("infra",), covered=("infra/main.tf",)):
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
    plan["scanner"]["enabled_components"] = ["kics"]
    plan["components"] = [
        {
            "name": "kics",
            "mode": "partial",
            "reason": "component_scope_changed",
            "compatibility_key": "5" * 64,
            "covered_paths": list(covered),
            "deleted_paths": [],
            "iac_units": list(units),
        }
    ]
    return _redigest(plan)


def test_contract_scan_executes_full_plan_and_emits_bound_envelope(tmp_path, monkeypatch):
    source, head_sha = _source_tree(tmp_path)
    plan = _full_plan(head_sha)
    plan_path = tmp_path / "plan.json"
    result_path = tmp_path / "result.json"
    plan_path.write_bytes(_canonical(plan))
    monkeypatch.setattr(
        GitleaksScanner,
        "scan_current_tree",
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
    plan["scanner"]["enabled_components"] = ["grype"]
    plan["components"][0].update(
        {
            "name": "grype",
            "mode": "partial",
            "reason": "component_scope_changed",
            "covered_paths": ["package-lock.json"],
            "iac_units": [],
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
    monkeypatch.setattr(
        GitleaksScanner, "scan_current_tree", lambda self, path: invoked.append(path)
    )

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
    monkeypatch.setattr(
        GitleaksScanner, "scan_current_tree", lambda self, path: invoked.append(path)
    )

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
        "scan_current_tree",
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

    monkeypatch.setattr(GitleaksScanner, "scan_current_tree", fail)
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
        "scan_current_tree",
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
    monkeypatch.setattr(GitleaksScanner, "scan_current_tree", lambda self, path: [])
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
    monkeypatch.setattr(GitleaksScanner, "scan_current_tree", lambda self, path: [])
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


def test_contract_scan_executes_complete_file_secret_and_sast_scopes(tmp_path, monkeypatch):
    source, head_sha = _source_tree(tmp_path)
    plan = _partial_sast_plan(head_sha)
    plan_path = tmp_path / "plan.json"
    result_path = tmp_path / "result.json"
    plan_path.write_bytes(_canonical(plan))
    calls = []

    def scan_paths(scanner_name):
        def execute(_self, source_path, covered_paths):
            calls.append((scanner_name, source_path, tuple(covered_paths)))
            return [
                {
                    "scanner": scanner_name,
                    "file": "app.py",
                    "rule_id": f"{scanner_name}-rule",
                }
            ]

        return execute

    monkeypatch.setattr(GitleaksScanner, "scan_paths", scan_paths("gitleaks"), raising=False)
    monkeypatch.setattr(SemgrepScanner, "scan_paths", scan_paths("semgrep"), raising=False)
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
    assert calls == [
        ("gitleaks", str(source), ("app.py",)),
        ("semgrep", str(source), ("app.py",)),
    ]
    components = json.loads(result_path.read_text(encoding="utf-8"))["components"]
    assert [item["status"] for item in components] == ["complete", "complete"]


def test_gitleaks_partial_scope_uses_current_tree_and_only_complete_planned_files(
    tmp_path, monkeypatch
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("token = 'complete-file'\n", encoding="utf-8")
    (source / "other.py").write_text("token = 'not-planned'\n", encoding="utf-8")
    scanner = GitleaksScanner()
    monkeypatch.setattr(scanner, "is_installed", lambda: True)

    def run_gitleaks(command, **_kwargs):
        assert command[:2] == ["gitleaks", "dir"]
        scoped_root = Path(command[2])
        assert (scoped_root / "app.py").read_text(encoding="utf-8") == "token = 'complete-file'\n"
        assert not (scoped_root / "other.py").exists()
        report_path = Path(command[command.index("--report-path") + 1])
        report_path.write_text(
            json.dumps(
                [
                    {
                        "RuleID": "generic-api-key",
                        "Match": "complete-file",
                        "File": str(scoped_root / "app.py"),
                        "StartLine": 1,
                    }
                ]
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 1, "", "")

    monkeypatch.setattr("ez_appsec.external_scanners.subprocess.run", run_gitleaks)
    findings = scanner.scan_paths(str(source), ["app.py"])

    assert len(findings) == 1
    assert findings[0]["file"] == "app.py"


def test_semgrep_partial_scope_uses_only_complete_planned_files(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    (source / "other.py").write_text("print('not planned')\n", encoding="utf-8")
    scanner = SemgrepScanner()
    monkeypatch.setattr(scanner, "is_installed", lambda: True)

    def run_semgrep(command, **_kwargs):
        assert command[0] == "semgrep"
        scoped_root = Path(command[-1])
        assert (scoped_root / "app.py").read_text(encoding="utf-8") == "eval(user_input)\n"
        assert not (scoped_root / "other.py").exists()
        report_path = Path(command[command.index("--output") + 1])
        report_path.write_text(
            json.dumps(
                {
                    "errors": [],
                    "results": [
                        {
                            "check_id": "python.lang.security.audit.eval-detected",
                            "path": str(scoped_root / "app.py"),
                            "start": {"line": 1},
                            "extra": {
                                "severity": "ERROR",
                                "message": "eval detected",
                                "metadata": {"cwe": "CWE-95"},
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("ez_appsec.external_scanners.subprocess.run", run_semgrep)
    findings = scanner.scan_paths(str(source), ["app.py"])

    assert len(findings) == 1
    assert findings[0]["file"] == "app.py"
    assert findings[0]["finding_id"] == compute_finding_id(
        "python.lang.security.audit.eval-detected", "app.py", 1
    )


def test_partial_component_rejects_finding_outside_covered_paths(tmp_path, monkeypatch):
    source, head_sha = _source_tree(tmp_path)
    plan = _partial_sast_plan(head_sha)
    plan_path = tmp_path / "plan.json"
    result_path = tmp_path / "result.json"
    plan_path.write_bytes(_canonical(plan))
    monkeypatch.setattr(
        GitleaksScanner,
        "scan_paths",
        lambda self, source_path, paths: [
            {"scanner": "gitleaks", "file": "other.py", "rule_id": "outside"}
        ],
    )
    monkeypatch.setattr(
        SemgrepScanner,
        "scan_paths",
        lambda self, source_path, paths: [],
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
    assert component["diagnostic_code"] == "finding_scope_mismatch"
    assert component["findings"] == []


def test_semgrep_partial_javascript_scope_preserves_full_scan_rule_selection(
    tmp_path, monkeypatch
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.js").write_text("eval(userInput)\n", encoding="utf-8")
    scanner = SemgrepScanner()
    monkeypatch.setattr(scanner, "is_installed", lambda: True)
    commands = []

    def run_semgrep(command, **_kwargs):
        commands.append(command)
        report_path = Path(command[command.index("--output") + 1])
        report_path.write_text('{"errors":[],"results":[]}', encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("ez_appsec.external_scanners.subprocess.run", run_semgrep)
    full_findings, full_output = scanner.scan_with_raw_output(str(source))
    Path(full_output).unlink()
    assert full_findings == []
    assert scanner.scan_paths(str(source), ["app.js"]) == []
    full_configs = [item for item in commands[0] if item.startswith("--config=")]
    partial_configs = [item for item in commands[1] if item.startswith("--config=")]
    assert partial_configs == full_configs
    assert not any(item.endswith("js-semgrep-rules.yaml") for item in full_configs)


def test_gitleaks_partial_scope_uses_repository_config(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("token = 'candidate'\n", encoding="utf-8")
    config = source / ".gitleaks.toml"
    config.write_text("[allowlist]\npaths = ['app.py']\n", encoding="utf-8")
    scanner = GitleaksScanner()
    monkeypatch.setattr(scanner, "is_installed", lambda: True)

    def run_gitleaks(command, **_kwargs):
        assert command[command.index("--config") + 1] == str(config)
        report_path = Path(command[command.index("--report-path") + 1])
        report_path.write_text("[]", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("ez_appsec.external_scanners.subprocess.run", run_gitleaks)
    assert scanner.scan_paths(str(source), ["app.py"]) == []


def test_contract_scan_accepts_planned_reuse_without_executing_component(
    tmp_path, monkeypatch
):
    source, head_sha = _source_tree(tmp_path)
    plan = _partial_sast_plan(head_sha)
    plan["components"][0].update(
        {
            "mode": "reuse",
            "reason": "component_unchanged",
            "covered_paths": [],
        }
    )
    _redigest(plan)
    plan_path = tmp_path / "plan.json"
    result_path = tmp_path / "result.json"
    plan_path.write_bytes(_canonical(plan))

    def unexpected(*_args):
        raise AssertionError("reuse component executed")

    monkeypatch.setattr(GitleaksScanner, "scan_paths", unexpected)
    monkeypatch.setattr(
        SemgrepScanner,
        "scan_paths",
        lambda self, source_path, paths: [],
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
    components = json.loads(result_path.read_text(encoding="utf-8"))["components"]
    assert components[0]["status"] == "not_run"
    assert components[0]["diagnostic_code"] == "component_unchanged"
    assert components[1]["status"] == "complete"


def test_deleted_only_partial_scope_completes_without_scanner_execution(
    tmp_path, monkeypatch
):
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
            "covered_paths": [],
            "deleted_paths": ["deleted.py"],
        }
    )
    _redigest(plan)
    plan_path = tmp_path / "plan.json"
    result_path = tmp_path / "result.json"
    plan_path.write_bytes(_canonical(plan))

    def unexpected(*_args):
        raise AssertionError("deleted-only component executed")

    monkeypatch.setattr(GitleaksScanner, "scan_paths", unexpected)
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
    component = json.loads(result_path.read_text(encoding="utf-8"))["components"][0]
    assert component["status"] == "complete"
    assert component["findings"] == []
    assert component["deleted_paths"] == ["deleted.py"]


def test_gitleaks_partial_scope_uses_repository_ignore_file(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("token = 'candidate'\n", encoding="utf-8")
    ignore_file = source / ".gitleaksignore"
    ignore_file.write_text("fingerprint:app.py:generic-api-key:1\n", encoding="utf-8")
    scanner = GitleaksScanner()
    monkeypatch.setattr(scanner, "is_installed", lambda: True)

    def run_gitleaks(command, **_kwargs):
        assert command[command.index("--gitleaks-ignore-path") + 1] == str(ignore_file)
        report_path = Path(command[command.index("--report-path") + 1])
        report_path.write_text("[]", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("ez_appsec.external_scanners.subprocess.run", run_gitleaks)
    assert scanner.scan_paths(str(source), ["app.py"]) == []


def test_semgrep_partial_scope_preserves_repository_ignore_rules(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    (source / ".semgrepignore").write_text("app.py\n", encoding="utf-8")
    scanner = SemgrepScanner()
    monkeypatch.setattr(scanner, "is_installed", lambda: True)

    def run_semgrep(command, **_kwargs):
        scoped_root = Path(command[-1])
        assert (scoped_root / ".semgrepignore").read_text(encoding="utf-8") == "app.py\n"
        report_path = Path(command[command.index("--output") + 1])
        report_path.write_text('{"errors":[],"results":[]}', encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("ez_appsec.external_scanners.subprocess.run", run_semgrep)
    assert scanner.scan_paths(str(source), ["app.py"]) == []


def test_custom_php_partial_scope_scans_only_complete_planned_files(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    vulnerable = "<?php mysql_query($_GET['id']); SELECT * FROM users; ?>\n"
    (source / "app.php").write_text(vulnerable, encoding="utf-8")
    (source / "other.php").write_text(vulnerable, encoding="utf-8")

    findings = PHPVulnScanner().scan_paths(str(source), ["app.php"])

    assert findings
    assert {finding["file"] for finding in findings} == {"app.php"}
    assert all(finding["scanner"] == "php-vuln-scanner" for finding in findings)


def test_kics_partial_scope_scans_complete_planned_unit(tmp_path, monkeypatch):
    source = tmp_path / "source"
    unit = source / "infra"
    unit.mkdir(parents=True)
    (unit / "main.tf").write_text('module "app" { source = "./module" }\n')
    module = unit / "module"
    module.mkdir()
    (module / "security.tf").write_text('resource "aws_s3_bucket" "app" {}\n')
    (source / "outside.tf").write_text('resource "aws_s3_bucket" "outside" {}\n')
    scanner = KicsScanner()
    monkeypatch.setattr(scanner, "is_installed", lambda: True)
    monkeypatch.setattr(scanner, "_find_assets_path", lambda: tmp_path / "assets")

    def run_kics(command, **_kwargs):
        scoped_root = Path(command[command.index("-p") + 1])
        assert (scoped_root / "infra/main.tf").is_file()
        assert (scoped_root / "infra/module/security.tf").is_file()
        assert not (scoped_root / "outside.tf").exists()
        output_dir = Path(command[command.index("-o") + 1])
        (output_dir / "results.json").write_text(
            json.dumps(
                {
                    "queries": [
                        {
                            "queryName": "Bucket Encryption Disabled",
                            "description": "Encryption is required",
                            "severity": "HIGH",
                            "results": [
                                {
                                    "file": str(scoped_root / "infra/module/security.tf"),
                                    "line": 1,
                                }
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 20, "", "")

    monkeypatch.setattr("ez_appsec.external_scanners.subprocess.run", run_kics)
    findings = scanner.scan_units(str(source), ["infra"])

    assert len(findings) == 1
    assert findings[0]["file"] == "infra/module/security.tf"
    assert findings[0]["finding_id"] == compute_finding_id(
        "Bucket Encryption Disabled", "infra/module/security.tf", 1
    )


def test_contract_scan_executes_kics_unit_and_accepts_unit_owned_finding(
    tmp_path, monkeypatch
):
    source, _ = _source_tree(tmp_path)
    infra = source / "infra"
    infra.mkdir()
    (infra / "main.tf").write_text('resource "aws_s3_bucket" "app" {}\n')
    _git(source, "add", "infra/main.tf")
    _git(source, "commit", "-m", "iac fixture")
    head_sha = _git(source, "rev-parse", "HEAD")
    plan = _partial_kics_plan(head_sha)
    plan_path = tmp_path / "plan.json"
    result_path = tmp_path / "result.json"
    plan_path.write_bytes(_canonical(plan))
    calls = []

    def scan_units(_self, source_path, units):
        calls.append((source_path, tuple(units)))
        return [
            {
                "scanner": "kics",
                "rule_id": "iac-rule",
                "file": "infra/main.tf",
                "line": 1,
            }
        ]

    monkeypatch.setattr(KicsScanner, "scan_units", scan_units, raising=False)
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
    assert calls == [(str(source), ("infra",))]
    component = json.loads(result_path.read_text(encoding="utf-8"))["components"][0]
    assert component["status"] == "complete"
    assert component["findings"][0]["file"] == "infra/main.tf"


def test_kics_partial_scope_rejects_unplanned_local_module_reference(
    tmp_path, monkeypatch
):
    source = tmp_path / "source"
    unit = source / "infra"
    unit.mkdir(parents=True)
    (unit / "main.tf").write_text('module "shared" { source = "../shared" }\n')
    shared = source / "shared"
    shared.mkdir()
    (shared / "main.tf").write_text('resource "aws_s3_bucket" "shared" {}\n')
    scanner = KicsScanner()
    monkeypatch.setattr(scanner, "is_installed", lambda: True)
    invoked = []
    monkeypatch.setattr(
        "ez_appsec.external_scanners.subprocess.run",
        lambda *args, **kwargs: invoked.append(args),
    )

    try:
        scanner.scan_units(str(source), ["infra"])
    except Exception as exc:
        assert getattr(exc, "code", None) == "scope_unresolved"
    else:
        raise AssertionError("unplanned local module reference was scanned")
    assert invoked == []


def test_kics_partial_scope_rejects_unparsed_terraform_module(tmp_path, monkeypatch):
    source = tmp_path / "source"
    unit = source / "infra"
    unit.mkdir(parents=True)
    (unit / "main.tf").write_text(
        'module /* planner cannot safely parse this */ "shared" {\n'
        '  source = "../shared"\n}\n',
        encoding="utf-8",
    )
    shared = source / "shared"
    shared.mkdir()
    (shared / "main.tf").write_text('resource "null_resource" "shared" {}\n')
    scanner = KicsScanner()
    monkeypatch.setattr(scanner, "is_installed", lambda: True)
    invoked = []
    monkeypatch.setattr(
        "ez_appsec.external_scanners.subprocess.run",
        lambda *args, **kwargs: invoked.append(args),
    )

    try:
        scanner.scan_units(str(source), ["infra"])
    except Exception as exc:
        assert getattr(exc, "code", None) == "scope_unresolved"
    else:
        raise AssertionError("unparsed Terraform module was scanned")
    assert invoked == []


def test_kics_partial_scope_rejects_unplanned_tf_json_module_reference(
    tmp_path, monkeypatch
):
    source = tmp_path / "source"
    unit = source / "infra"
    unit.mkdir(parents=True)
    (unit / "main.tf.json").write_text(
        json.dumps({"module": {"shared": {"source": "../shared"}}}),
        encoding="utf-8",
    )
    shared = source / "shared"
    shared.mkdir()
    (shared / "main.tf").write_text('resource "aws_s3_bucket" "shared" {}\n')
    scanner = KicsScanner()
    monkeypatch.setattr(scanner, "is_installed", lambda: True)
    invoked = []
    monkeypatch.setattr(
        "ez_appsec.external_scanners.subprocess.run",
        lambda *args, **kwargs: invoked.append(args),
    )

    try:
        scanner.scan_units(str(source), ["infra"])
    except Exception as exc:
        assert getattr(exc, "code", None) == "scope_unresolved"
    else:
        raise AssertionError("unplanned tf.json module reference was scanned")
    assert invoked == []


def test_kics_partial_scope_rejects_unplanned_kustomize_resource(
    tmp_path, monkeypatch
):
    source = tmp_path / "source"
    deploy = source / "deploy"
    deploy.mkdir(parents=True)
    (deploy / "kustomization.yaml").write_text(
        "resources:\n  - deployment.yaml\n", encoding="utf-8"
    )
    (deploy / "deployment.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\n", encoding="utf-8"
    )
    scanner = KicsScanner()
    monkeypatch.setattr(scanner, "is_installed", lambda: True)
    invoked = []
    monkeypatch.setattr(
        "ez_appsec.external_scanners.subprocess.run",
        lambda *args, **kwargs: invoked.append(args),
    )

    try:
        scanner.scan_units(str(source), ["deploy/kustomization.yaml"])
    except Exception as exc:
        assert getattr(exc, "code", None) == "scope_unresolved"
    else:
        raise AssertionError("incomplete Kustomize unit was scanned")
    assert invoked == []


def test_kics_partial_scope_accepts_complete_kustomize_unit(tmp_path, monkeypatch):
    source = tmp_path / "source"
    deploy = source / "deploy"
    deploy.mkdir(parents=True)
    (deploy / "kustomization.yaml").write_text(
        "resources:\n  - deployment.yaml\n", encoding="utf-8"
    )
    (deploy / "deployment.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\n", encoding="utf-8"
    )
    scanner = KicsScanner()
    monkeypatch.setattr(scanner, "is_installed", lambda: True)
    monkeypatch.setattr(scanner, "_find_assets_path", lambda: tmp_path / "assets")

    def run_kics(command, **_kwargs):
        output_dir = Path(command[command.index("-o") + 1])
        (output_dir / "results.json").write_text(
            '{"queries": []}', encoding="utf-8"
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("ez_appsec.external_scanners.subprocess.run", run_kics)
    assert scanner.scan_units(str(source), ["deploy"]) == []


def test_contract_scan_rejects_kics_finding_outside_planned_unit(tmp_path, monkeypatch):
    source, _ = _source_tree(tmp_path)
    infra = source / "infra"
    infra.mkdir()
    (infra / "main.tf").write_text('resource "aws_s3_bucket" "app" {}\n')
    _git(source, "add", "infra/main.tf")
    _git(source, "commit", "-m", "iac fixture")
    head_sha = _git(source, "rev-parse", "HEAD")
    plan = _partial_kics_plan(head_sha)
    plan_path = tmp_path / "plan.json"
    result_path = tmp_path / "result.json"
    plan_path.write_bytes(_canonical(plan))
    monkeypatch.setattr(
        KicsScanner,
        "scan_units",
        lambda self, source_path, units: [
            {"scanner": "kics", "rule_id": "outside", "file": "other/main.tf"}
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
    assert component["diagnostic_code"] == "finding_scope_mismatch"
    assert component["findings"] == []
