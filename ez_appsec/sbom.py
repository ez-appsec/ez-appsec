"""CycloneDX SBOM generation via grype"""

import json
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def generate_cyclonedx(
    path: str,
    out_path: str,
    sbom_version: str = "1.4",
) -> str:
    """Generate a CycloneDX JSON SBOM from a directory using grype.

    Args:
        path: Directory to scan for dependencies.
        out_path: Destination file for the CycloneDX JSON output.
        sbom_version: CycloneDX spec version used for validation only
            (grype determines the output version itself).

    Returns:
        The resolved output path on success.

    Raises:
        FileNotFoundError: If grype is not installed.
        RuntimeError: If grype exits non-zero or the output is invalid.
    """
    if not _grype_installed():
        raise FileNotFoundError(
            "grype is not installed. Install with: "
            "brew install grype  # or: curl https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh"
        )

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        [
            "grype",
            f"dir:{path}",
            "-o", "cyclonedx-json",
            "--file", str(out),
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )

    if result.returncode != 0:
        logger.warning(
            "grype exited with code %d: %s",
            result.returncode, (result.stderr or "")[:200],
        )

    if not out.exists():
        stderr_snippet = (result.stderr or "")[:500]
        raise RuntimeError(
            f"grype did not produce SBOM output at {out}. stderr: {stderr_snippet}"
        )

    _validate_cyclonedx(out, sbom_version)

    logger.info("SBOM written to %s", out)
    return str(out)


def _grype_installed() -> bool:
    try:
        subprocess.run(
            ["grype", "--version"],
            capture_output=True,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _validate_cyclonedx(path: Path, expected_version: str) -> None:
    """Validate that the file is a well-formed CycloneDX BOM."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        raise RuntimeError(f"SBOM file is not valid JSON: {exc}") from exc

    bom_format = data.get("bomFormat")
    if bom_format != "CycloneDX":
        raise RuntimeError(
            f"Expected bomFormat 'CycloneDX', got '{bom_format}'"
        )

    spec_version = data.get("specVersion", "")
    expected_major = int(expected_version.split(".")[0])
    actual_major = int(spec_version.split(".")[0]) if spec_version else -1
    if actual_major != expected_major:
        logger.warning(
            "SBOM specVersion %s has different major version than expected %s",
            spec_version, expected_version,
        )

    for required_key in ("components", "metadata"):
        if required_key not in data:
            raise RuntimeError(
                f"CycloneDX SBOM missing required key: '{required_key}'"
            )
