"""License compliance checker — extracts licenses from syft/grype output and
checks them against configurable allowed/denied lists (PLAN-11)"""

import json
import logging
import subprocess
import tempfile
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def _normalize_license(license_id: str) -> str:
    """Normalize a license identifier for comparison."""
    return license_id.strip()


def _matches_pattern(license_id: str, pattern: str) -> bool:
    """Check if a license matches a pattern (supports wildcards like GPL*)."""
    return fnmatch(license_id.upper(), pattern.upper())


def _matches_any(license_id: str, patterns: List[str]) -> bool:
    """Check if a license matches any pattern in the list."""
    normalized = _normalize_license(license_id)
    return any(_matches_pattern(normalized, p) for p in patterns)


class LicensePolicy:
    """Configurable license policy with allowed and denied lists."""

    def __init__(
        self,
        allowed_licenses: Optional[List[str]] = None,
        denied_licenses: Optional[List[str]] = None,
    ):
        self.allowed_licenses = allowed_licenses or []
        self.denied_licenses = denied_licenses or []

    def check(self, license_id: str) -> str:
        """Check a license against the policy.

        Returns: "allowed", "denied", or "unknown"
        """
        if not license_id or license_id.lower() in ("unknown", "none", ""):
            return "unknown"

        if self.denied_licenses and _matches_any(license_id, self.denied_licenses):
            return "denied"

        if self.allowed_licenses and _matches_any(license_id, self.allowed_licenses):
            return "allowed"

        if self.allowed_licenses:
            return "unknown"

        return "allowed"


class PackageLicense:
    """A package with its detected license(s)."""

    def __init__(self, name: str, version: str, licenses: List[str], pkg_type: str = ""):
        self.name = name
        self.version = version
        self.licenses = licenses
        self.pkg_type = pkg_type

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "licenses": self.licenses,
            "type": self.pkg_type,
        }


def extract_licenses_from_syft(syft_json: Dict[str, Any]) -> List[PackageLicense]:
    """Extract package license information from syft JSON output.

    Syft output contains an 'artifacts' array (syft < 1.0) or 'packages' array
    (syft >= 1.0), each with a 'licenses' field.
    """
    packages = []
    artifacts = syft_json.get("artifacts") or syft_json.get("packages") or []

    for artifact in artifacts:
        name = artifact.get("name", "")
        version = artifact.get("version", "")
        pkg_type = artifact.get("type", "")

        license_ids = []
        raw_licenses = artifact.get("licenses") or []

        for lic in raw_licenses:
            if isinstance(lic, str):
                license_ids.append(lic)
            elif isinstance(lic, dict):
                spdx = lic.get("spdxExpression") or lic.get("value") or lic.get("name") or ""
                if spdx:
                    license_ids.append(spdx)

        if not license_ids:
            license_ids = ["UNKNOWN"]

        packages.append(PackageLicense(
            name=name,
            version=version,
            licenses=license_ids,
            pkg_type=pkg_type,
        ))

    return packages


def run_syft(path: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """Run syft on a path and return (parsed JSON, raw output path).

    Returns (None, "") if syft is not installed or fails.

    Note: Path is canonicalized to prevent directory traversal attacks.
    """
    try:
        subprocess.run(["syft", "version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.warning("syft not installed — license check unavailable")
        return None, ""

    # Canonicalize path to prevent directory traversal (e.g., "../other-dir")
    # Use resolve(strict=False) to allow non-existent paths (syft will validate)
    # Handle case where cwd was deleted (e.g., by buggy test) by catching FileNotFoundError
    try:
        scan_path = str(Path(path).expanduser().absolute().resolve(strict=False))
    except FileNotFoundError:
        # cwd was deleted, path will be handled by syft (or fail appropriately)
        scan_path = path

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        raw_path = f.name

    try:
        result = subprocess.run(
            ["syft", "dir:" + scan_path, "-o", "json", "--file", raw_path],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            logger.error(f"syft exited with code {result.returncode}: {result.stderr.strip()}")
            return None, raw_path
        with open(raw_path) as f:
            data = json.load(f)
        return data, raw_path
    except subprocess.TimeoutExpired:
        logger.error("syft scan timed out after 300s")
        return None, raw_path
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.error(f"syft output error: {e}")
        return None, raw_path
    except Exception as e:
        logger.error(f"syft scan failed: {e}")
        return None, raw_path


def check_licenses(
    path: str,
    policy: LicensePolicy,
    syft_json: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run license compliance check on a path.

    Args:
        path: Directory to scan
        policy: License policy to evaluate against
        syft_json: Pre-existing syft output (if None, runs syft)

    Returns dict with:
        - findings: list of license_compliance finding dicts
        - packages: list of all packages with licenses
        - summary: {total, allowed, denied, unknown}

    Note: Summary counts are per-license, not per-package. A dual-licensed
    package (e.g., MIT+GPL-3.0) will increment multiple counters if licenses
    differ in classification (e.g., 1 allowed, 1 denied).
    """
    if syft_json is None:
        syft_json, raw_path = run_syft(path)
        if raw_path:
            try:
                Path(raw_path).unlink()
            except OSError:
                pass
        if syft_json is None:
            return {
                "findings": [],
                "packages": [],
                "summary": {"total": 0, "allowed": 0, "denied": 0, "unknown": 0},
            }

    packages = extract_licenses_from_syft(syft_json)

    findings = []
    allowed_count = 0
    denied_count = 0
    unknown_count = 0

    for pkg in packages:
        for lic in pkg.licenses:
            verdict = policy.check(lic)

            if verdict == "denied":
                denied_count += 1
                other_licenses = [l for l in pkg.licenses if l != lic]
                desc = (
                    f"Package {pkg.name}@{pkg.version} uses license '{lic}' "
                    f"which is on the denied list."
                )
                if other_licenses:
                    desc += (
                        f" This package also declares: {', '.join(other_licenses)}. "
                        f"If dual-licensed, you may be able to use it under an alternative license."
                    )
                solution = (
                    f"Option 1: Replace {pkg.name} with a permissively-licensed alternative. "
                    f"Option 2: Add an ignore rule (rule_id: license-denied-{lic}) with justification. "
                    f"Option 3: If dual-licensed, confirm the alternative license applies to your usage."
                )
                findings.append({
                    "type": "license_compliance",
                    "category": "license_compliance",
                    "title": f"Denied license: {lic} in {pkg.name}@{pkg.version}",
                    "description": desc,
                    "solution": solution,
                    "file": f"dependency: {pkg.name}",
                    "line": 0,  # License findings have no file/line context
                    "severity": "high",
                    "scanner": "license-checker",
                    "rule_id": f"license-denied-{lic}",
                    "license": lic,
                    "all_licenses": pkg.licenses,
                    "package": pkg.name,
                    "package_version": pkg.version,
                    "package_type": pkg.pkg_type,
                })
            elif verdict == "unknown":
                unknown_count += 1
                is_missing = lic.upper() == "UNKNOWN"
                if is_missing:
                    desc = (
                        f"Package {pkg.name}@{pkg.version} has no license metadata. "
                        f"This may indicate a private/internal package or missing LICENSE file."
                    )
                    solution = (
                        f"Check the package source for a LICENSE file. "
                        f"If the license is acceptable, add it to allowed_licenses in your config. "
                        f"If the package is internal, add an ignore rule (rule_id: license-unknown-UNKNOWN)."
                    )
                else:
                    desc = (
                        f"Package {pkg.name}@{pkg.version} uses license '{lic}' "
                        f"which is not on your allowed list. "
                        f"Review whether this license is compatible with your project."
                    )
                    solution = (
                        f"If '{lic}' is acceptable, add it to allowed_licenses in .ez-appsec.yaml. "
                        f"If not acceptable, add it to denied_licenses to flag it as high severity. "
                        f"To suppress: add an ignore rule (rule_id: license-unknown-{lic})."
                    )
                findings.append({
                    "type": "license_compliance",
                    "category": "license_compliance",
                    "title": f"Unknown license: {lic} in {pkg.name}@{pkg.version}",
                    "description": desc,
                    "solution": solution,
                    "file": f"dependency: {pkg.name}",
                    "line": 0,  # License findings have no file/line context
                    "severity": "medium",
                    "scanner": "license-checker",
                    "rule_id": f"license-unknown-{lic}",
                    "license": lic,
                    "all_licenses": pkg.licenses,
                    "package": pkg.name,
                    "package_version": pkg.version,
                    "package_type": pkg.pkg_type,
                })
            else:
                allowed_count += 1

    return {
        "findings": findings,
        "packages": [p.to_dict() for p in packages],
        "summary": {
            "total": len(packages),
            "allowed": allowed_count,
            "denied": denied_count,
            "unknown": unknown_count,
        },
    }
