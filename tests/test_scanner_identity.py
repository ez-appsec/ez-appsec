"""M036 S03/T05: bounded scanner identity for dependency reuse."""

import json
import os
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from ez_appsec import scanner_identity
from ez_appsec.cli import main
from ez_appsec.scanner_identity import (
    ScannerIdentityError,
    component_identity,
    scanner_identity as build_scanner_identity,
    validate_component_identity,
)


SCANNER_IMAGE = "ghcr.io/ez-appsec/ez-appsec@sha256:" + "1" * 64
ARCHIVE_CHECKSUM = "sha256:" + "7" * 64
GRYPE_VERSION = {
    "application": "grype",
    "version": "0.118.0",
    "syftVersion": "v1.51.1",
    "supportedDbSchema": 6,
}
GRYPE_STATUS = {
    "schemaVersion": "v6.1.9",
    "from": (
        "https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.9.tar.zst"
        f"?checksum=sha256%3A{'7' * 64}"
    ),
    "built": "2026-09-13T06:31:42Z",
    "path": "/opt/grype-db/6/vulnerability.db",
    "valid": True,
}
GRYPE_CONFIG = """
# effective configuration
db:
  cache-dir: /opt/grype-db
  auto-update: false
output: [table]
search:
  scope: squashed
add-cpes-if-none: false
match:
  java:
    using-cpes: false
ignore: []
exclude: []
only-fixed: false
only-notfixed: false
ignore-wontfix: ''
fail-on-severity: ''
external-sources:
  enable: false
fix-channel: {}
"""


def _grype_runner(*, version=None, status=None, config=None, calls=None):
    version = GRYPE_VERSION if version is None else version
    status = GRYPE_STATUS if status is None else status
    config = GRYPE_CONFIG if config is None else config

    def run(command, **kwargs):
        if calls is not None:
            calls.append((tuple(command), kwargs.get("cwd")))
        if command[:2] == ["grype", "version"]:
            stdout = json.dumps(version)
        elif command[:3] == ["grype", "db", "status"]:
            stdout = json.dumps(status)
        elif command[:2] == ["grype", "config"]:
            # Only the loaded configuration reflects the environment.
            assert command[2:] == ["--load"], command
            stdout = config
        else:
            raise AssertionError(f"unexpected command {command}")
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    return run


def test_grype_identity_reports_exact_advisory_and_configuration(monkeypatch):
    calls = []
    monkeypatch.setattr(scanner_identity.subprocess, "run", _grype_runner(calls=calls))

    identity = component_identity("grype")

    assert identity == {
        "advisory_built_at": "2026-09-13T06:31:42Z",
        "advisory_checksum": ARCHIVE_CHECKSUM,
        "advisory_schema": "v6.1.9",
        "cataloger_config_digest": identity["cataloger_config_digest"],
        "policy_digest": identity["policy_digest"],
        "syft_version": "1.51.1",
        "tool_version": "0.118.0",
    }
    assert identity["cataloger_config_digest"].startswith("sha256:")
    assert identity["policy_digest"].startswith("sha256:")
    # Identity describes the image: every probe runs from a neutral directory,
    # never from a repository whose `.grype.yaml` could leak into it.
    assert all(cwd is not None and "grype-identity-" in cwd for _, cwd in calls)
    assert not any(Path(cwd) == Path.cwd() for _, cwd in calls)


def test_grype_identity_is_deterministic_and_separates_policy_from_cataloging(
    monkeypatch,
):
    monkeypatch.setattr(scanner_identity.subprocess, "run", _grype_runner())
    baseline = component_identity("grype")
    monkeypatch.setattr(scanner_identity.subprocess, "run", _grype_runner())
    assert component_identity("grype") == baseline

    policy_changed = GRYPE_CONFIG.replace("ignore: []", "ignore:\n  - vulnerability: CVE-1\n")
    monkeypatch.setattr(
        scanner_identity.subprocess, "run", _grype_runner(config=policy_changed)
    )
    changed = component_identity("grype")
    assert changed["policy_digest"] != baseline["policy_digest"]
    assert changed["cataloger_config_digest"] == baseline["cataloger_config_digest"]

    cataloger_changed = GRYPE_CONFIG.replace("scope: squashed", "scope: all-layers")
    monkeypatch.setattr(
        scanner_identity.subprocess, "run", _grype_runner(config=cataloger_changed)
    )
    changed = component_identity("grype")
    assert changed["cataloger_config_digest"] != baseline["cataloger_config_digest"]
    assert changed["policy_digest"] == baseline["policy_digest"]

    # Placement and formatting settings do not change what is found.
    cosmetic = GRYPE_CONFIG.replace("cache-dir: /opt/grype-db", "cache-dir: /elsewhere")
    monkeypatch.setattr(scanner_identity.subprocess, "run", _grype_runner(config=cosmetic))
    assert component_identity("grype") == baseline


@pytest.mark.parametrize(
    "status",
    [
        {**GRYPE_STATUS, "valid": False},
        {**GRYPE_STATUS, "from": "https://grype.anchore.io/databases/v6/db.tar.zst"},
        {**GRYPE_STATUS, "from": GRYPE_STATUS["from"].replace("sha256%3A", "md5%3A")},
        {key: value for key, value in GRYPE_STATUS.items() if key != "built"},
        {**GRYPE_STATUS, "schemaVersion": "v6.1.9 with spaces"},
    ],
)
def test_grype_identity_fails_closed_without_a_verifiable_database(monkeypatch, status):
    monkeypatch.setattr(scanner_identity.subprocess, "run", _grype_runner(status=status))
    with pytest.raises(ScannerIdentityError) as failure:
        component_identity("grype")
    assert failure.value.code == "identity_unavailable"


def test_grype_identity_fails_closed_when_grype_is_missing(monkeypatch):
    def missing(command, **_kwargs):
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(scanner_identity.subprocess, "run", missing)
    with pytest.raises(ScannerIdentityError) as failure:
        component_identity("grype")
    assert failure.value.code == "identity_unavailable"


def test_rule_digest_depends_on_content_and_path_only(tmp_path):
    rules = tmp_path / "rules"
    (rules / "python").mkdir(parents=True)
    (rules / "python" / "a.yml").write_text("rules: [a]\n", encoding="utf-8")
    (rules / "python" / "b.yml").write_text("rules: [b]\n", encoding="utf-8")
    first = scanner_identity._tree_digest("semgrep", [("rules", rules)])

    os.utime(rules / "python" / "a.yml", (1, 1))
    assert scanner_identity._tree_digest("semgrep", [("rules", rules)]) == first

    (rules / "python" / "b.yml").write_text("rules: [c]\n", encoding="utf-8")
    assert scanner_identity._tree_digest("semgrep", [("rules", rules)]) != first

    (rules / "python" / "b.yml").write_text("rules: [b]\n", encoding="utf-8")
    (rules / "python" / "b.yml").rename(rules / "python" / "z.yml")
    assert scanner_identity._tree_digest("semgrep", [("rules", rules)]) != first


def test_semgrep_identity_is_unpinned_when_only_registry_rules_are_available(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(
        scanner_identity.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, stdout="1.157.0\n", stderr=""
        ),
    )
    monkeypatch.setattr(
        scanner_identity, "semgrep_rule_sources", lambda: [tmp_path / "absent.yml"]
    )
    with pytest.raises(ScannerIdentityError) as failure:
        component_identity("semgrep")
    assert failure.value.code == "rule_source_unpinned"


@pytest.mark.parametrize(
    ("component", "identity"),
    [
        ("grype", {}),
        ("grype", {"tool_version": "0.118.0", "unexpected": "x"}),
        ("grype", {"advisory_checksum": "7" * 64}),
        ("grype", {"advisory_checksum": "sha256:" + "G" * 64}),
        ("grype", {"tool_version": ""}),
        ("grype", {"tool_version": "0.118.0 beta"}),
        ("grype", {"tool_version": 118}),
        ("semgrep", {"advisory_schema": "v6"}),
        ("unknown", {"tool_version": "1"}),
        ("grype", ["tool_version"]),
    ],
)
def test_component_identity_validation_rejects_unbindable_values(component, identity):
    with pytest.raises(ScannerIdentityError) as failure:
        validate_component_identity(component, identity)
    assert failure.value.code == "identity_invalid"


def test_component_identity_validation_canonicalizes_field_order():
    assert list(
        validate_component_identity(
            "semgrep", {"tool_version": "1.157.0", "rule_digest": "sha256:" + "a" * 64}
        )
    ) == ["rule_digest", "tool_version"]


def _stub_identities(monkeypatch, overrides=None):
    identities = {
        "gitleaks": {"tool_version": "8.18.0"},
        "semgrep": {"tool_version": "1.157.0", "rule_digest": "sha256:" + "a" * 64},
        "custom_php": {"tool_version": "0.1.0", "rule_digest": "sha256:" + "b" * 64},
        "kics": {"tool_version": "2.1.20", "rule_digest": "sha256:" + "c" * 64},
        "grype": {
            "tool_version": "0.118.0",
            "syft_version": "1.51.1",
            "advisory_schema": "v6.1.9",
            "advisory_built_at": "2026-09-13T06:31:42Z",
            "advisory_checksum": ARCHIVE_CHECKSUM,
            "cataloger_config_digest": "sha256:" + "d" * 64,
            "policy_digest": "sha256:" + "e" * 64,
        },
        **(overrides or {}),
    }
    monkeypatch.setattr(
        scanner_identity,
        "_PROVIDERS",
        {name: (lambda value=value: value) for name, value in identities.items()},
    )
    return identities


def test_scanner_identity_document_is_complete_and_digest_bound(monkeypatch):
    identities = _stub_identities(monkeypatch)
    document = build_scanner_identity(SCANNER_IMAGE)
    assert document["schema_version"] == "sourcebastion.scanner-identity.v1"
    assert document["scanner_image"] == SCANNER_IMAGE
    assert document["contract_features"] == ["component-identity-v1"]
    assert set(document["components"]) == set(identities)
    assert document["components"]["grype"] == dict(sorted(identities["grype"].items()))
    digest = document.pop("identity_digest")
    assert digest == scanner_identity.hashlib.sha256(
        scanner_identity.canonical_json(document)
    ).hexdigest()


def test_scanner_identity_document_fails_closed_on_any_incomplete_component(monkeypatch):
    _stub_identities(monkeypatch)

    def unavailable():
        raise ScannerIdentityError("kics", "identity_unavailable")

    scanner_identity._PROVIDERS["kics"] = unavailable
    with pytest.raises(ScannerIdentityError):
        build_scanner_identity(SCANNER_IMAGE)


def test_contract_identity_cli_writes_canonical_document(monkeypatch, tmp_path):
    _stub_identities(monkeypatch)
    output = tmp_path / "identity.json"
    result = CliRunner().invoke(
        main,
        ["contract-identity", "--output", str(output), "--scanner-image", SCANNER_IMAGE],
    )
    assert result.exit_code == 0, result.output
    encoded = output.read_bytes()
    document = json.loads(encoded)
    assert encoded == scanner_identity.canonical_json(document)
    assert document["components"]["grype"]["advisory_checksum"] == ARCHIVE_CHECKSUM


def test_contract_identity_cli_rejects_unpinned_image_reference(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            "contract-identity",
            "--output",
            str(tmp_path / "identity.json"),
            "--scanner-image",
            "ghcr.io/ez-appsec/ez-appsec:latest",
        ],
    )
    assert result.exit_code == 1
    assert "scanner_image_invalid" in result.output
    assert not (tmp_path / "identity.json").exists()


def test_contract_identity_cli_reports_bounded_failure(monkeypatch, tmp_path):
    _stub_identities(monkeypatch)

    def unavailable():
        raise ScannerIdentityError("grype", "identity_unavailable")

    scanner_identity._PROVIDERS["grype"] = unavailable
    output = tmp_path / "identity.json"
    result = CliRunner().invoke(
        main,
        ["contract-identity", "--output", str(output), "--scanner-image", SCANNER_IMAGE],
    )
    assert result.exit_code == 1
    assert "grype: identity_unavailable" in result.output
    assert not output.exists()



def test_grype_identity_changes_when_the_database_may_refresh_at_run_time(monkeypatch):
    monkeypatch.setattr(scanner_identity.subprocess, "run", _grype_runner())
    pinned = component_identity("grype")
    refreshing = GRYPE_CONFIG.replace("auto-update: false", "auto-update: true")
    monkeypatch.setattr(scanner_identity.subprocess, "run", _grype_runner(config=refreshing))
    drifted = component_identity("grype")
    assert drifted["cataloger_config_digest"] != pinned["cataloger_config_digest"]
    assert drifted["advisory_checksum"] == pinned["advisory_checksum"]
