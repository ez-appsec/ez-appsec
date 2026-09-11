"""Portable M036 scan-plan execution and result-envelope contract."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import tempfile
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict

from ez_appsec.external_scanners import ExternalScannerManager, ScannerExecutionError


PLAN_VERSION = "sourcebastion.scan-plan.v1"
RESULT_VERSION = "sourcebastion.scan-result.v1"
COMPONENT_NAMES = {
    "gitleaks": "gitleaks",
    "semgrep": "semgrep",
    "custom_php": "php-vuln",
    "kics": "kics",
    "grype": "grype",
}
_FINDING_SCANNERS = {
    "gitleaks": {"gitleaks"},
    "semgrep": {"semgrep"},
    "custom_php": {"php-vuln-scanner"},
    "kics": {"kics"},
    "grype": {"grype"},
}
MAX_PLAN_BYTES = 256 * 1024
MAX_COMPONENTS = 16
MAX_BASELINE_AGE_SECONDS = 7 * 24 * 60 * 60
_GIT_OID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PREFIXED_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PROVIDER = re.compile(r"^[a-z0-9.-]{1,255}$")
_REF = re.compile(r"^refs/(?:heads|pull|tags)/[^\x00-\x1f\\]{1,240}$")
_PLAN_MODES = {"full", "partial", "reuse"}
_PLAN_REASONS = {
    "capability_full_only",
    "capability_reuse_only",
    "component_config_changed",
    "component_identity_incomplete",
    "component_incompatible",
    "component_scope_changed",
    "component_unchanged",
    "dependency_inputs_changed",
    "no_compatible_baseline",
}
_MODE_REASONS = {
    "full": _PLAN_REASONS - {"component_scope_changed", "component_unchanged"},
    "partial": {"component_scope_changed"},
    "reuse": {"component_unchanged"},
}
_LIMIT_CEILINGS = {
    "max_execution_seconds": 1800,
    "max_findings": 100_000,
    "max_path_bytes": 2 * 1024 * 1024,
    "max_scope_entries": 10_000,
    "max_source_bytes": 512 * 1024 * 1024,
}
_RESULT_STATUSES = {"complete", "failed", "not_run"}
_DIAGNOSTIC_CODES = ScannerExecutionError.VALID_CODES | {
    "unsupported_mode",
    "findings_limit_exceeded",
    "finding_ownership_mismatch",
    "finding_scope_mismatch",
    "execution_limit_exceeded",
    "component_unchanged",
}
_PARTIAL_COMPONENTS = {"gitleaks", "semgrep", "custom_php", "kics"}


class IncrementalContractError(ValueError):
    """A bounded, non-sensitive contract validation failure."""


def canonical_json(value: Dict[str, Any]) -> bytes:
    """Encode deterministic JSON for contract digests."""
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IncrementalContractError("contract_json_invalid") from exc


def _sha256(value: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _object_without_duplicate_keys(pairs: list) -> Dict[str, Any]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise IncrementalContractError("scan_plan_invalid")
        value[key] = item
    return value


def _invalid() -> None:
    raise IncrementalContractError("scan_plan_invalid")


def _exact_dict(
    value: Any,
    fields: set,
    error_code: str = "scan_plan_invalid",
) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise IncrementalContractError(error_code)
    return value


def _valid_identity(value: Any) -> bool:
    return isinstance(value, str) and _IDENTITY.fullmatch(value) is not None


def _valid_ref(value: Any) -> bool:
    if not isinstance(value, str) or _REF.fullmatch(value) is None:
        return False
    remainder = value.split("/", 2)[-1]
    return not (
        ".." in value
        or "//" in value
        or "@{" in value
        or value.endswith(("/", "."))
        or any(character in value for character in " ~^:?*[")
        or any(
            not part or part.startswith(".") or part.endswith((".", ".lock"))
            for part in remainder.split("/")
        )
    )


def _valid_path(value: Any, allow_root: bool = False) -> bool:
    if allow_root and value == ".":
        return True
    if not isinstance(value, str) or not value or "\0" in value or "\\" in value:
        return False
    pure = PurePosixPath(value)
    return not (
        pure.is_absolute()
        or pure.as_posix() != value
        or value.endswith("/")
        or "//" in value
        or any(part in {"", ".", ".."} for part in pure.parts)
        or unicodedata.normalize("NFC", value) != value
        or len(value.encode("utf-8")) > 4096
        or any(len(part.encode("utf-8")) > 255 for part in pure.parts)
    )


def _validate_scope(value: Any, limit: int, allow_root: bool = False) -> list:
    if not isinstance(value, list) or len(value) > limit:
        _invalid()
    if not all(_valid_path(path, allow_root=allow_root) for path in value):
        _invalid()
    if value != sorted(set(value)):
        _invalid()
    return value


def _validate_scan_plan(plan: Dict[str, Any]) -> None:
    _exact_dict(
        plan,
        {
            "schema_version",
            "job_id",
            "account_id",
            "source",
            "created_at",
            "baseline",
            "scanner",
            "mode",
            "components",
            "limits",
            "plan_digest",
        },
    )
    if not _valid_identity(plan["job_id"]) or not _valid_identity(plan["account_id"]):
        _invalid()

    source = _exact_dict(
        plan["source"], {"provider_host", "repository_id", "ref", "head_sha"}
    )
    provider = source["provider_host"]
    if (
        not isinstance(provider, str)
        or _PROVIDER.fullmatch(provider) is None
        or provider.startswith((".", "-"))
        or provider.endswith((".", "-"))
        or any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            for label in provider.split(".")
        )
        or not _valid_identity(source["repository_id"])
        or not _valid_ref(source["ref"])
        or not isinstance(source["head_sha"], str)
        or _GIT_OID.fullmatch(source["head_sha"]) is None
    ):
        _invalid()

    if not isinstance(plan["created_at"], str):
        _invalid()
    try:
        created = datetime.fromisoformat(plan["created_at"].replace("Z", "+00:00"))
    except ValueError:
        _invalid()
    canonical_time = (
        created.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    if created.tzinfo is None or plan["created_at"] != canonical_time:
        _invalid()

    limits = _exact_dict(plan["limits"], set(_LIMIT_CEILINGS))
    for name, ceiling in _LIMIT_CEILINGS.items():
        value = limits[name]
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= ceiling
        ):
            _invalid()

    scanner = _exact_dict(
        plan["scanner"],
        {
            "image",
            "result_schema_version",
            "finding_identity_version",
            "config_digest",
            "enabled_components",
        },
    )
    if (
        not isinstance(scanner["image"], str)
        or _IMAGE.fullmatch(scanner["image"]) is None
        or scanner["result_schema_version"] != RESULT_VERSION
        or not _valid_identity(scanner["finding_identity_version"])
        or not isinstance(scanner["config_digest"], str)
        or _PREFIXED_DIGEST.fullmatch(scanner["config_digest"]) is None
        or not isinstance(scanner["enabled_components"], list)
    ):
        _invalid()

    components = plan["components"]
    if not isinstance(components, list) or not 1 <= len(components) <= MAX_COMPONENTS:
        _invalid()
    names = []
    scope_entries = 0
    path_bytes = 0
    incremental = False
    for component in components:
        component = _exact_dict(
            component,
            {
                "name",
                "mode",
                "reason",
                "compatibility_key",
                "covered_paths",
                "deleted_paths",
                "iac_units",
            },
        )
        name = component["name"]
        mode = component["mode"]
        reason = component["reason"]
        if (
            name not in COMPONENT_NAMES
            or mode not in _PLAN_MODES
            or reason not in _PLAN_REASONS
            or reason not in _MODE_REASONS[mode]
            or not isinstance(component["compatibility_key"], str)
            or _DIGEST.fullmatch(component["compatibility_key"]) is None
        ):
            _invalid()
        covered = _validate_scope(component["covered_paths"], limits["max_scope_entries"])
        deleted = _validate_scope(component["deleted_paths"], limits["max_scope_entries"])
        units = _validate_scope(
            component["iac_units"], limits["max_scope_entries"], allow_root=True
        )
        if set(covered) & set(deleted):
            _invalid()
        if mode != "partial" and (covered or deleted or units):
            _invalid()
        if mode == "partial" and not (covered or deleted or units):
            _invalid()
        if units and name != "kics":
            _invalid()
        names.append(name)
        incremental = incremental or mode in {"partial", "reuse"}
        scope_entries += len(covered) + len(deleted) + len(units)
        path_bytes += sum(len(path.encode("utf-8")) for path in covered + deleted + units)
    if (
        names != sorted(set(names))
        or scanner["enabled_components"] != names
        or scope_entries > limits["max_scope_entries"]
        or path_bytes > limits["max_path_bytes"]
    ):
        _invalid()

    baseline = plan["baseline"]
    if baseline is not None:
        baseline = _exact_dict(
            baseline,
            {
                "run_id",
                "sha",
                "age_seconds",
                "same_ref",
                "ancestor",
                "applied",
                "complete",
            },
        )
        if (
            isinstance(baseline["run_id"], bool)
            or not isinstance(baseline["run_id"], int)
            or baseline["run_id"] < 1
            or not isinstance(baseline["sha"], str)
            or _GIT_OID.fullmatch(baseline["sha"]) is None
            or isinstance(baseline["age_seconds"], bool)
            or not isinstance(baseline["age_seconds"], int)
            or not 0 <= baseline["age_seconds"] <= MAX_BASELINE_AGE_SECONDS
            or any(
                baseline[field] is not True
                for field in ("same_ref", "ancestor", "applied", "complete")
            )
        ):
            _invalid()
    expected_mode = "incremental" if incremental else "full"
    if incremental != (baseline is not None) or plan["mode"] != expected_mode:
        _invalid()


def validate_scan_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    """Validate untrusted in-memory plan data and return a detached value."""
    if not isinstance(plan, dict) or plan.get("schema_version") != PLAN_VERSION:
        raise IncrementalContractError("scan_plan_version_unsupported")
    _validate_scan_plan(plan)
    supplied = plan.get("plan_digest")
    body = {key: value for key, value in plan.items() if key != "plan_digest"}
    if (
        not isinstance(supplied, str)
        or _DIGEST.fullmatch(supplied) is None
        or not hmac.compare_digest(supplied, _sha256(body))
    ):
        raise IncrementalContractError("scan_plan_digest_mismatch")
    return json.loads(canonical_json(plan).decode("utf-8"))


def load_scan_plan(path: str) -> Dict[str, Any]:
    """Load a portable plan and verify its version and canonical digest."""
    try:
        encoded = Path(path).read_bytes()
        if len(encoded) > MAX_PLAN_BYTES:
            raise IncrementalContractError("scan_plan_invalid")
        plan = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise IncrementalContractError("scan_plan_invalid") from exc
    return validate_scan_plan(plan)


def _observed_head(source_path: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", source_path, "rev-parse", "--verify", "HEAD^{commit}"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise IncrementalContractError("source_head_unavailable") from exc
    return result.stdout.strip().lower()


def _validate_source_tree(source_path: str, max_source_bytes: int) -> None:
    """Bound regular source content without following repository symlinks."""
    total = 0
    try:
        for current_root, directory_names, file_names in os.walk(
            source_path, followlinks=False
        ):
            if ".git" in directory_names:
                if (Path(current_root) / ".git").is_symlink():
                    raise IncrementalContractError("source_tree_invalid")
                directory_names.remove(".git")
            for directory_name in directory_names:
                if (Path(current_root) / directory_name).is_symlink():
                    raise IncrementalContractError("source_tree_invalid")
            for file_name in file_names:
                if file_name == ".git":
                    continue
                file_path = Path(current_root) / file_name
                metadata = file_path.lstat()
                if not stat.S_ISREG(metadata.st_mode):
                    raise IncrementalContractError("source_tree_invalid")
                total += metadata.st_size
                if total > max_source_bytes:
                    raise IncrementalContractError("source_limit_exceeded")
    except IncrementalContractError:
        raise
    except OSError as exc:
        raise IncrementalContractError("source_tree_invalid") from exc


def _finding_in_component_scope(finding: Dict[str, Any], component: Dict[str, Any]) -> bool:
    """Check finding ownership against file or complete-IaC unit coverage."""
    path = finding.get("file")
    if not _valid_path(path):
        return False
    if component["name"] != "kics":
        return path in component["covered_paths"]
    return any(
        unit == "." or path == unit or path.startswith(f"{unit}/")
        for unit in component["iac_units"]
    )


def execute_scan_plan(
    source_path: str,
    plan: Dict[str, Any],
    scanner_image: str,
) -> Dict[str, Any]:
    """Execute one full-mode plan and return its bound result envelope."""
    plan = validate_scan_plan(plan)
    if plan.get("scanner", {}).get("image") != scanner_image:
        raise IncrementalContractError("scanner_image_mismatch")
    _validate_source_tree(source_path, plan["limits"]["max_source_bytes"])
    observed_head = _observed_head(source_path)
    if plan.get("source", {}).get("head_sha") != observed_head:
        raise IncrementalContractError("source_head_mismatch")

    manager = ExternalScannerManager(
        enabled_scanners=[COMPONENT_NAMES[item["name"]] for item in plan["components"]]
    )
    started_at = datetime.now(timezone.utc).replace(microsecond=0)
    started_monotonic = time.monotonic()
    component_results = []
    total_findings = 0
    for component in plan["components"]:
        name = component["name"]
        mode = component["mode"]
        if mode == "reuse":
            findings = []
            status = "not_run"
            diagnostic_code = "component_unchanged"
        elif (
            mode == "partial"
            and name in _PARTIAL_COMPONENTS
            and not component["covered_paths"]
            and not component["iac_units"]
        ):
            findings = []
            status = "complete"
            diagnostic_code = None
        elif mode == "partial" and name not in _PARTIAL_COMPONENTS:
            findings = []
            status = "not_run"
            diagnostic_code = "unsupported_mode"
        else:
            scanner = manager.scanners[COMPONENT_NAMES[name]]
            try:
                if mode == "partial" and name == "kics":
                    findings = scanner.scan_units(source_path, component["iac_units"])
                elif mode == "partial":
                    findings = scanner.scan_paths(source_path, component["covered_paths"])
                elif name == "gitleaks":
                    findings = scanner.scan_current_tree(source_path)
                else:
                    findings = scanner.scan(source_path)
                if (
                    time.monotonic() - started_monotonic
                    > plan["limits"]["max_execution_seconds"]
                ):
                    findings = []
                    status = "failed"
                    diagnostic_code = "execution_limit_exceeded"
                elif not isinstance(findings, list):
                    findings = []
                    status = "failed"
                    diagnostic_code = "invalid_output"
                elif any(
                    not isinstance(finding, dict)
                    or finding.get("scanner") not in _FINDING_SCANNERS[name]
                    for finding in findings
                ):
                    findings = []
                    status = "failed"
                    diagnostic_code = "finding_ownership_mismatch"
                elif mode == "partial" and any(
                    not _finding_in_component_scope(finding, component)
                    for finding in findings
                ):
                    findings = []
                    status = "failed"
                    diagnostic_code = "finding_scope_mismatch"
                elif total_findings + len(findings) > plan["limits"]["max_findings"]:
                    findings = []
                    status = "failed"
                    diagnostic_code = "findings_limit_exceeded"
                else:
                    total_findings += len(findings)
                    status = "complete"
                    diagnostic_code = None
            except ScannerExecutionError as exc:
                findings = []
                status = "failed"
                diagnostic_code = exc.code
            except Exception:
                findings = []
                status = "failed"
                diagnostic_code = "execution_failed"
        component_results.append(
            {
                "name": name,
                "status": status,
                "compatibility_key": component["compatibility_key"],
                "covered_paths": component["covered_paths"],
                "deleted_paths": component["deleted_paths"],
                "iac_units": component["iac_units"],
                "findings": findings,
                "diagnostic_code": diagnostic_code,
            }
        )

    body = {
        "schema_version": RESULT_VERSION,
        "observed_head_sha": observed_head,
        "plan_digest": plan["plan_digest"],
        "scanner_image": scanner_image,
        "started_at": started_at.isoformat().replace("+00:00", "Z"),
        "finished_at": (
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        ),
        "components": component_results,
    }
    return validate_result_envelope(
        {**body, "result_digest": _sha256(body)},
        plan,
    )


def _result_invalid() -> None:
    raise IncrementalContractError("result_envelope_invalid")


def _parse_result_time(value: Any) -> datetime:
    if not isinstance(value, str):
        _result_invalid()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _result_invalid()
    if parsed.tzinfo is None:
        _result_invalid()
    return parsed.astimezone(timezone.utc)


def validate_result_envelope(
    envelope: Dict[str, Any],
    plan: Dict[str, Any],
) -> Dict[str, Any]:
    """Validate a scanner result and bind it to the exact accepted plan."""
    if not isinstance(envelope, dict):
        _result_invalid()
    result = _exact_dict(
        envelope,
        {
            "schema_version",
            "observed_head_sha",
            "plan_digest",
            "scanner_image",
            "started_at",
            "finished_at",
            "components",
            "result_digest",
        },
        "result_envelope_invalid",
    )
    if result["schema_version"] != RESULT_VERSION:
        raise IncrementalContractError("result_version_unsupported")
    plan = validate_scan_plan(plan)
    if (
        result["observed_head_sha"] != plan["source"]["head_sha"]
        or result["plan_digest"] != plan["plan_digest"]
        or result["scanner_image"] != plan["scanner"]["image"]
    ):
        raise IncrementalContractError("result_binding_mismatch")
    if (
        not isinstance(result["observed_head_sha"], str)
        or _GIT_OID.fullmatch(result["observed_head_sha"]) is None
        or not isinstance(result["plan_digest"], str)
        or _DIGEST.fullmatch(result["plan_digest"]) is None
        or not isinstance(result["scanner_image"], str)
        or _IMAGE.fullmatch(result["scanner_image"]) is None
    ):
        _result_invalid()
    started = _parse_result_time(result["started_at"])
    finished = _parse_result_time(result["finished_at"])
    if finished < started:
        _result_invalid()

    components = result["components"]
    if not isinstance(components, list) or len(components) != len(plan["components"]):
        _result_invalid()
    finding_count = 0
    for component, planned in zip(components, plan["components"]):
        component = _exact_dict(
            component,
            {
                "name",
                "status",
                "compatibility_key",
                "covered_paths",
                "deleted_paths",
                "iac_units",
                "findings",
                "diagnostic_code",
            },
            "result_envelope_invalid",
        )
        status = component["status"]
        if (
            component["name"] != planned["name"]
            or component["compatibility_key"] != planned["compatibility_key"]
            or component["covered_paths"] != planned["covered_paths"]
            or component["deleted_paths"] != planned["deleted_paths"]
            or component["iac_units"] != planned["iac_units"]
            or status not in _RESULT_STATUSES
            or (status == "complete" and component["diagnostic_code"] is not None)
            or (
                status != "complete"
                and component["diagnostic_code"] not in _DIAGNOSTIC_CODES
            )
            or not isinstance(component["findings"], list)
            or (status != "complete" and component["findings"])
            or (
                planned["mode"] == "reuse"
                and (
                    status != "not_run"
                    or component["diagnostic_code"] != "component_unchanged"
                )
            )
            or (
                planned["mode"] != "reuse"
                and status == "not_run"
                and component["diagnostic_code"] != "unsupported_mode"
            )
        ):
            _result_invalid()
        if any(
            not isinstance(finding, dict)
            or finding.get("scanner") not in _FINDING_SCANNERS[component["name"]]
            for finding in component["findings"]
        ):
            _result_invalid()
        if planned["mode"] == "partial" and any(
            not _finding_in_component_scope(finding, planned)
            for finding in component["findings"]
        ):
            _result_invalid()
        finding_count += len(component["findings"])
    if finding_count > plan["limits"]["max_findings"]:
        _result_invalid()

    supplied_digest = result["result_digest"]
    body = {key: value for key, value in result.items() if key != "result_digest"}
    if (
        not isinstance(supplied_digest, str)
        or _DIGEST.fullmatch(supplied_digest) is None
        or not hmac.compare_digest(supplied_digest, _sha256(body))
    ):
        raise IncrementalContractError("result_digest_mismatch")
    return json.loads(canonical_json(result).decode("utf-8"))


def write_result_envelope(path: str, envelope: Dict[str, Any]) -> None:
    """Atomically write the canonical result envelope."""
    target = Path(path)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=str(target.parent),
            prefix=f".{target.name}.",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(canonical_json(envelope))
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, target)
    except OSError as exc:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass
        raise IncrementalContractError("result_write_failed") from exc
