"""Bounded runtime identity for the M036 scanner components.

The trusted platform fingerprints every input that can change a component's
findings before it may reuse or narrow a prior observation. Most of those
inputs live inside the scanner image, so the image has to report them itself:
tool versions, bundled rule content, and for Grype the exact vulnerability
database and matching configuration. This module computes that identity in a
deterministic, non-sensitive form and lets a plan pin the identity it expects
so a scanner whose runtime state has drifted (for example a refreshed advisory
database) fails closed instead of silently producing a different result.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from importlib import metadata
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import parse_qs, urlsplit

import yaml


IDENTITY_VERSION = "sourcebastion.scanner-identity.v1"
CONTRACT_FEATURES = ("component-identity-v1",)
IDENTITY_FIELDS: Dict[str, frozenset] = {
    "gitleaks": frozenset({"tool_version"}),
    "semgrep": frozenset({"tool_version", "rule_digest"}),
    "custom_php": frozenset({"tool_version", "rule_digest"}),
    "kics": frozenset({"tool_version", "rule_digest"}),
    "grype": frozenset(
        {
            "tool_version",
            "syft_version",
            "advisory_schema",
            "advisory_built_at",
            "advisory_checksum",
            "cataloger_config_digest",
            "policy_digest",
        }
    ),
}
GRYPE_REUSE_FIELDS = IDENTITY_FIELDS["grype"]
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$")
_PREFIXED_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERSION_TOKEN = re.compile(r"v?\d+(?:\.\d+)+(?:[-+.][A-Za-z0-9.-]+)?")
_SAST_RULES_ROOT = Path("/usr/local/share/sast-rules")
_SAST_LANGUAGES = ("c", "csharp", "go", "java", "javascript", "python", "scala")
# Grype settings that decide which packages are catalogued and how they are
# matched, and separately which matches survive to the report. Anything else
# in `grype config` is output formatting, network or cache placement, none of
# which changes a finding for the same input tree and database.
_GRYPE_CATALOGER_KEYS = (
    "add-cpes-if-none",
    "distro",
    "match",
    "match-upstream-kernel-headers",
    "platform",
    "search",
)
_GRYPE_POLICY_KEYS = (
    "exclude",
    "external-sources",
    "fail-on-severity",
    "fix-channel",
    "ignore",
    "ignore-wontfix",
    "only-fixed",
    "only-notfixed",
)


class ScannerIdentityError(RuntimeError):
    """A bounded, non-sensitive identity failure."""

    VALID_CODES = frozenset(
        {
            "identity_unavailable",
            "identity_invalid",
            "rule_source_unpinned",
        }
    )

    def __init__(self, component: str, code: str):
        if code not in self.VALID_CODES:
            raise ValueError(f"unknown identity failure code: {code}")
        super().__init__(f"{component}: {code}")
        self.component = component
        self.code = code


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def is_digest_field(name: str) -> bool:
    return name.endswith("digest") or name.endswith("checksum")


def valid_identity_value(name: str, value: Any) -> bool:
    """Match the platform's bounded token and digest formats exactly."""
    if not isinstance(value, str):
        return False
    if is_digest_field(name):
        return _PREFIXED_DIGEST.fullmatch(value) is not None
    return _TOKEN.fullmatch(value) is not None


def validate_component_identity(component: str, identity: Any) -> Dict[str, str]:
    """Reject identity mappings the contract cannot bind."""
    fields = IDENTITY_FIELDS.get(component)
    if fields is None or not isinstance(identity, dict) or not identity:
        raise ScannerIdentityError(component, "identity_invalid")
    if set(identity) - fields:
        raise ScannerIdentityError(component, "identity_invalid")
    if any(not valid_identity_value(name, value) for name, value in identity.items()):
        raise ScannerIdentityError(component, "identity_invalid")
    return dict(sorted(identity.items()))


def _run(component: str, command: List[str], *, env=None, cwd=None) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
            env=env,
            cwd=cwd,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        raise ScannerIdentityError(component, "identity_unavailable") from None
    return result.stdout


def _version_token(component: str, text: str) -> str:
    match = _VERSION_TOKEN.search(text or "")
    if match is None:
        raise ScannerIdentityError(component, "identity_unavailable")
    return match.group(0).lstrip("v")


def _tree_digest(component: str, roots: Iterable[Tuple[str, Path]]) -> str:
    """Digest labelled file trees by relative path and content, never by mtime."""
    hasher = hashlib.sha256()
    seen = False
    for label, root in roots:
        try:
            if root.is_file():
                files = [root]
                base = root.parent
            elif root.is_dir():
                files = sorted(
                    path for path in root.rglob("*") if path.is_file() and not path.is_symlink()
                )
                base = root
            else:
                continue
            for path in files:
                relative = path.relative_to(base).as_posix()
                hasher.update(canonical_json([label, relative]))
                hasher.update(b"\0")
                with open(path, "rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        hasher.update(chunk)
                hasher.update(b"\0")
                seen = True
        except OSError:
            raise ScannerIdentityError(component, "identity_unavailable") from None
    if not seen:
        raise ScannerIdentityError(component, "rule_source_unpinned")
    return "sha256:" + hasher.hexdigest()


def semgrep_rule_sources() -> List[Path]:
    """The local rule inputs a full or partial Semgrep scan may load.

    Mirrors the selection in ``SemgrepScanner.scan_with_raw_output``. A rule
    file that is absent is simply not part of the identity; if every local
    source is absent the scanner falls back to the registry, and that
    selection is unpinned by definition.
    """
    package_root = Path(__file__).resolve().parent.parent
    sources = [
        package_root / "custom-semgrep-rules.yaml",
        package_root / "js-semgrep-rules.yaml",
    ]
    sources.extend(_SAST_RULES_ROOT / language for language in _SAST_LANGUAGES)
    sources.append(_SAST_RULES_ROOT / "ruby.yml")
    return sources


def _gitleaks_identity() -> Dict[str, str]:
    return {"tool_version": _version_token("gitleaks", _run("gitleaks", ["gitleaks", "version"]))}


def _semgrep_identity() -> Dict[str, str]:
    version = _version_token(
        "semgrep",
        _run(
            "semgrep",
            ["semgrep", "--version"],
            env={**os.environ, "SEMGREP_ENABLE_VERSION_CHECK": "0"},
        ),
    )
    sources = [(path.name, path) for path in semgrep_rule_sources()]
    return {"tool_version": version, "rule_digest": _tree_digest("semgrep", sources)}


def _custom_php_identity() -> Dict[str, str]:
    try:
        version = metadata.version("ez-appsec")
    except metadata.PackageNotFoundError:
        raise ScannerIdentityError("custom_php", "identity_unavailable") from None
    package = Path(__file__).resolve().parent
    rules = [
        ("php_vuln_scanner", package / "php_vuln_scanner.py"),
        ("php_vuln_scanner_simple", package / "php_vuln_scanner_simple.py"),
    ]
    return {
        "tool_version": _version_token("custom_php", version),
        "rule_digest": _tree_digest("custom_php", rules),
    }


def _kics_identity() -> Dict[str, str]:
    from ez_appsec.external_scanners import KicsScanner

    version = _version_token("kics", _run("kics", ["kics", "version"]))
    assets = KicsScanner._find_assets_path()
    if assets is None:
        raise ScannerIdentityError("kics", "identity_unavailable")
    return {
        "tool_version": version,
        "rule_digest": _tree_digest(
            "kics", [("queries", assets / "queries"), ("libraries", assets / "libraries")]
        ),
    }


def _grype_json(command: List[str], env: Dict[str, str], cwd: str) -> Dict[str, Any]:
    output = _run("grype", command, env=env, cwd=cwd)
    try:
        value = json.loads(output)
    except json.JSONDecodeError:
        raise ScannerIdentityError("grype", "identity_unavailable") from None
    if not isinstance(value, dict):
        raise ScannerIdentityError("grype", "identity_unavailable")
    return value


def _grype_config(env: Dict[str, str], cwd: str) -> Dict[str, Any]:
    output = _run("grype", ["grype", "config"], env=env, cwd=cwd)
    try:
        value = yaml.safe_load(output)
    except yaml.YAMLError:
        raise ScannerIdentityError("grype", "identity_unavailable") from None
    if not isinstance(value, dict):
        raise ScannerIdentityError("grype", "identity_unavailable")
    return value


def _advisory_checksum(status: Dict[str, Any]) -> str:
    """The archive checksum Grype recorded for the imported database."""
    source = status.get("from")
    if not isinstance(source, str):
        raise ScannerIdentityError("grype", "identity_unavailable")
    try:
        query = parse_qs(urlsplit(source).query)
    except ValueError:
        raise ScannerIdentityError("grype", "identity_unavailable") from None
    checksums = query.get("checksum") or []
    if len(checksums) != 1 or _PREFIXED_DIGEST.fullmatch(checksums[0]) is None:
        raise ScannerIdentityError("grype", "identity_unavailable")
    return checksums[0]


def _grype_identity() -> Dict[str, str]:
    from ez_appsec.external_scanners import GrypeScanner

    env = GrypeScanner._runtime_env()
    # Identity describes the image, not the repository being scanned, so read
    # the effective configuration from an empty directory where no repository
    # `.grype.yaml` can be picked up. A repository config change is a global
    # invalidator on the platform side and forces a full component run.
    with tempfile.TemporaryDirectory(prefix="grype-identity-") as neutral:
        version = _grype_json(["grype", "version", "-o", "json"], env, neutral)
        status = _grype_json(["grype", "db", "status", "-o", "json"], env, neutral)
        config = _grype_config(env, neutral)
    if status.get("valid") is not True:
        raise ScannerIdentityError("grype", "identity_unavailable")
    identity = {
        "tool_version": _version_token("grype", str(version.get("version", ""))),
        "syft_version": _version_token("grype", str(version.get("syftVersion", ""))),
        "advisory_schema": str(status.get("schemaVersion", "")),
        "advisory_built_at": str(status.get("built", "")),
        "advisory_checksum": _advisory_checksum(status),
        "cataloger_config_digest": _digest(
            {key: config.get(key) for key in _GRYPE_CATALOGER_KEYS}
        ),
        "policy_digest": _digest({key: config.get(key) for key in _GRYPE_POLICY_KEYS}),
    }
    try:
        return validate_component_identity("grype", identity)
    except ScannerIdentityError:
        raise ScannerIdentityError("grype", "identity_unavailable") from None


_PROVIDERS = {
    "gitleaks": _gitleaks_identity,
    "semgrep": _semgrep_identity,
    "custom_php": _custom_php_identity,
    "kics": _kics_identity,
    "grype": _grype_identity,
}


def component_identity(component: str) -> Dict[str, str]:
    """Compute one component's bounded runtime identity, or fail closed."""
    provider = _PROVIDERS.get(component)
    if provider is None:
        raise ScannerIdentityError(component, "identity_invalid")
    return validate_component_identity(component, provider())


def scanner_identity(scanner_image: str) -> Dict[str, Any]:
    """Describe every contract component of this image for the trusted planner."""
    body = {
        "schema_version": IDENTITY_VERSION,
        "scanner_image": scanner_image,
        "contract_features": list(CONTRACT_FEATURES),
        "components": {name: component_identity(name) for name in sorted(_PROVIDERS)},
    }
    return {
        **body,
        "identity_digest": hashlib.sha256(canonical_json(body)).hexdigest(),
    }
