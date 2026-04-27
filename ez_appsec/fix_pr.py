"""Automated fix PRs for dependency CVEs (PLAN-04)

Parses grype scan output, groups vulnerable dependencies by package ecosystem,
applies version bumps to manifest files, and opens a PR/MR with the fixes.
"""

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class VulnerableDependency:
    package: str
    current_version: str
    fixed_version: str
    cve_id: str
    severity: str
    cvss_score: Optional[float] = None
    data_source: str = ""


@dataclass
class EcosystemFixPlan:
    ecosystem: str
    manifest_file: str
    fixes: List[VulnerableDependency] = field(default_factory=list)


ECOSYSTEM_MANIFESTS = {
    "npm": "package.json",
    "python": "requirements.txt",
    "go-module": "go.mod",
    "gem": "Gemfile",
    "java-archive": "pom.xml",
}

GRYPE_TYPE_TO_ECOSYSTEM = {
    "npm": "npm",
    "python": "python",
    "pip": "python",
    "go-module": "go-module",
    "gem": "gem",
    "java-archive": "java-archive",
    "maven": "java-archive",
}


def parse_grype_findings(grype_json_path: str) -> List[VulnerableDependency]:
    """Parse raw grype JSON output into a list of fixable dependencies."""
    with open(grype_json_path) as f:
        data = json.load(f)

    deps = []
    for match in data.get("matches", []):
        artifact = match.get("artifact", {})
        vuln = match.get("vulnerability", {})
        fix_info = vuln.get("fix", {})
        fix_versions = fix_info.get("versions", [])

        if not fix_versions:
            continue

        cvss_entries = vuln.get("cvss", [])
        cvss_score = None
        if cvss_entries:
            cvss_score = cvss_entries[0].get("metrics", {}).get("baseScore")

        deps.append(VulnerableDependency(
            package=artifact.get("name", ""),
            current_version=artifact.get("version", ""),
            fixed_version=fix_versions[0],
            cve_id=vuln.get("id", ""),
            severity=vuln.get("severity", "Unknown"),
            cvss_score=cvss_score,
            data_source=vuln.get("dataSource", ""),
        ))

    return deps


def parse_gitlab_findings(vulns_json_path: str) -> List[VulnerableDependency]:
    """Parse GitLab-format vulnerabilities.json for dependency findings with fix info.

    Falls back to extracting version info from the solution text when structured
    fix data isn't available.
    """
    with open(vulns_json_path) as f:
        data = json.load(f)

    vulns = data.get("vulnerabilities", [])
    deps = []

    for v in vulns:
        location = v.get("location", {})
        dep_info = location.get("dependency", {})
        if not dep_info:
            continue

        pkg_name = dep_info.get("package", {}).get("name", "")
        current_ver = dep_info.get("version", "")
        if not pkg_name:
            continue

        cve_id = ""
        for ident in v.get("identifiers", []):
            if ident.get("type") == "cve":
                cve_id = ident.get("value", "")
                break

        fixed_version = _extract_fixed_version(v.get("solution", ""), pkg_name)
        if not fixed_version:
            continue

        deps.append(VulnerableDependency(
            package=pkg_name,
            current_version=current_ver,
            fixed_version=fixed_version,
            cve_id=cve_id,
            severity=v.get("severity", "Unknown"),
            data_source=v.get("links", [{}])[0].get("url", "") if v.get("links") else "",
        ))

    return deps


def _extract_fixed_version(solution: str, package: str) -> str:
    """Try to extract a fixed version from solution text.

    Looks for patterns like "upgrade to 1.2.3" or ">=1.2.3".
    """
    if not solution:
        return ""

    patterns = [
        r"(?:upgrade|update)\s+(?:to\s+)?(?:version\s+)?(\d+\.\d+[\.\d]*)",
        r">=\s*(\d+\.\d+[\.\d]*)",
        r"version\s+(\d+\.\d+[\.\d]*)\s+(?:or|and)\s+(?:later|above|higher)",
    ]
    for pattern in patterns:
        m = re.search(pattern, solution, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def group_by_ecosystem(
    deps: List[VulnerableDependency],
    repo_path: str,
) -> List[EcosystemFixPlan]:
    """Group fixable deps by ecosystem, only including ecosystems with a manifest present."""
    pkg_to_ecosystem = _detect_ecosystems(repo_path)

    ecosystem_map: Dict[str, EcosystemFixPlan] = {}
    for dep in deps:
        eco = pkg_to_ecosystem.get(dep.package)
        if not eco:
            eco = _guess_ecosystem(dep.package, repo_path)
        if not eco:
            logger.debug(f"Skipping {dep.package}: no matching ecosystem manifest found")
            continue

        if eco not in ecosystem_map:
            manifest = ECOSYSTEM_MANIFESTS[eco]
            ecosystem_map[eco] = EcosystemFixPlan(
                ecosystem=eco,
                manifest_file=manifest,
            )
        ecosystem_map[eco].fixes.append(dep)

    return list(ecosystem_map.values())


def _detect_ecosystems(repo_path: str) -> Dict[str, str]:
    """Detect which ecosystems are present by checking for manifest files.

    Returns a mapping that can be used to assign packages to ecosystems.
    For now, returns an empty dict — the per-package _guess_ecosystem handles it.
    """
    return {}


def _guess_ecosystem(package: str, repo_path: str) -> Optional[str]:
    """Guess ecosystem for a package by checking which manifest files exist."""
    p = Path(repo_path)
    for eco, manifest in ECOSYSTEM_MANIFESTS.items():
        if (p / manifest).exists():
            return eco
    return None


def apply_version_bump(plan: EcosystemFixPlan, repo_path: str) -> List[str]:
    """Apply version bumps to the manifest file. Returns list of modified files."""
    manifest_path = Path(repo_path) / plan.manifest_file
    if not manifest_path.exists():
        logger.warning(f"Manifest not found: {manifest_path}")
        return []

    bumpers = {
        "npm": _bump_package_json,
        "python": _bump_requirements_txt,
        "go-module": _bump_go_mod,
        "gem": _bump_gemfile,
        "java-archive": _bump_pom_xml,
    }

    bumper = bumpers.get(plan.ecosystem)
    if not bumper:
        logger.warning(f"No bumper for ecosystem: {plan.ecosystem}")
        return []

    modified = bumper(manifest_path, plan.fixes)
    return modified


def _bump_package_json(manifest: Path, fixes: List[VulnerableDependency]) -> List[str]:
    """Bump versions in package.json."""
    with open(manifest) as f:
        data = json.load(f)

    modified = False
    for dep in fixes:
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            deps_section = data.get(section, {})
            if dep.package in deps_section:
                old = deps_section[dep.package]
                prefix = ""
                if old and old[0] in ("^", "~", ">=", ">"):
                    for p in (">=", "^", "~", ">"):
                        if old.startswith(p):
                            prefix = p
                            break
                deps_section[dep.package] = f"{prefix}{dep.fixed_version}"
                modified = True

    if modified:
        with open(manifest, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        return [str(manifest)]
    return []


def _bump_requirements_txt(manifest: Path, fixes: List[VulnerableDependency]) -> List[str]:
    """Bump versions in requirements.txt."""
    lines = manifest.read_text().splitlines()
    fix_map = {dep.package.lower(): dep for dep in fixes}
    new_lines = []
    modified = False

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue

        pkg_match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([><=!~]+)\s*(.+)$", stripped)
        if pkg_match:
            pkg_name = pkg_match.group(1).lower().replace("-", "_").replace(".", "_")
            dep = fix_map.get(pkg_name)
            if not dep:
                dep = fix_map.get(pkg_match.group(1).lower())
            if dep:
                new_lines.append(f"{pkg_match.group(1)}>={dep.fixed_version}")
                modified = True
                continue

        new_lines.append(line)

    if modified:
        manifest.write_text("\n".join(new_lines) + "\n")
        return [str(manifest)]
    return []


def _bump_go_mod(manifest: Path, fixes: List[VulnerableDependency]) -> List[str]:
    """Bump versions in go.mod."""
    content = manifest.read_text()
    modified = False

    for dep in fixes:
        pattern = re.compile(
            rf"(\s+{re.escape(dep.package)}\s+)v[\d.]+",
        )
        new_content = pattern.sub(rf"\g<1>v{dep.fixed_version}", content)
        if new_content != content:
            content = new_content
            modified = True

    if modified:
        manifest.write_text(content)
        return [str(manifest)]
    return []


def _bump_gemfile(manifest: Path, fixes: List[VulnerableDependency]) -> List[str]:
    """Bump versions in Gemfile."""
    content = manifest.read_text()
    modified = False

    for dep in fixes:
        pattern = re.compile(
            rf"""(gem\s+['"]){re.escape(dep.package)}(['"],\s*['"])[~>=<]*\s*[\d.]+(['"])""",
        )
        replacement = rf"\g<1>{dep.package}\g<2>~> {dep.fixed_version}\g<3>"
        new_content = pattern.sub(replacement, content)
        if new_content != content:
            content = new_content
            modified = True

    if modified:
        manifest.write_text(content)
        return [str(manifest)]
    return []


def _bump_pom_xml(manifest: Path, fixes: List[VulnerableDependency]) -> List[str]:
    """Bump versions in pom.xml.

    Uses simple regex rather than XML parsing to avoid reformatting.
    """
    content = manifest.read_text()
    modified = False

    for dep in fixes:
        parts = dep.package.rsplit(":", 1) if ":" in dep.package else [None, dep.package]
        artifact_id = parts[-1]

        pattern = re.compile(
            rf"(<artifactId>\s*{re.escape(artifact_id)}\s*</artifactId>\s*"
            rf"<version>)\s*[^<]+\s*(</version>)",
            re.DOTALL,
        )
        new_content = pattern.sub(rf"\g<1>{dep.fixed_version}\g<2>", content)
        if new_content != content:
            content = new_content
            modified = True

    if modified:
        manifest.write_text(content)
        return [str(manifest)]
    return []


def build_pr_body(plans: List[EcosystemFixPlan]) -> str:
    """Build PR/MR description listing all CVEs fixed."""
    lines = [
        "## Automated Security Fix",
        "",
        "This PR bumps vulnerable dependencies to fixed versions.",
        "",
    ]

    for plan in plans:
        lines.append(f"### {plan.ecosystem} (`{plan.manifest_file}`)")
        lines.append("")
        lines.append("| Package | Current | Fixed | CVE | Severity | CVSS |")
        lines.append("|---------|---------|-------|-----|----------|------|")
        for dep in plan.fixes:
            cvss = f"{dep.cvss_score:.1f}" if dep.cvss_score is not None else "N/A"
            cve_link = dep.cve_id
            if dep.data_source:
                cve_link = f"[{dep.cve_id}]({dep.data_source})"
            lines.append(
                f"| {dep.package} | {dep.current_version} | {dep.fixed_version} "
                f"| {cve_link} | {dep.severity} | {cvss} |"
            )
        lines.append("")

    lines.append("---")
    lines.append("*Generated by [ez-appsec](https://github.com/ez-appsec/ez-appsec) `fix-pr`*")
    return "\n".join(lines)


def build_branch_name(plans: List[EcosystemFixPlan]) -> str:
    """Generate a branch name from the fix plans."""
    ecosystems = sorted(set(p.ecosystem for p in plans))
    eco_slug = "-".join(ecosystems)
    cve_count = sum(len(p.fixes) for p in plans)
    return f"ez-appsec/fix-{eco_slug}-{cve_count}-cves"


def build_pr_title(plans: List[EcosystemFixPlan]) -> str:
    """Generate a concise PR title."""
    cve_count = sum(len(p.fixes) for p in plans)
    ecosystems = sorted(set(p.ecosystem for p in plans))
    eco_label = ", ".join(ecosystems)
    return f"fix(deps): bump {cve_count} vulnerable {eco_label} dependencies"


def create_github_pr(
    repo: str,
    repo_path: str,
    plans: List[EcosystemFixPlan],
    token: Optional[str] = None,
    dry_run: bool = False,
) -> Dict:
    """Create a GitHub PR with version bumps.

    Returns dict with keys: branch, pr_url, files_modified, dry_run.
    """
    env = os.environ.copy()
    if token:
        env["GH_TOKEN"] = token

    branch = build_branch_name(plans)
    title = build_pr_title(plans)
    body = build_pr_body(plans)

    all_modified = []
    for plan in plans:
        modified = apply_version_bump(plan, repo_path)
        all_modified.extend(modified)

    if not all_modified:
        return {"branch": branch, "pr_url": None, "files_modified": [], "dry_run": dry_run,
                "error": "No files were modified — version strings may not match manifest entries"}

    if dry_run:
        return {"branch": branch, "pr_url": None, "files_modified": all_modified, "dry_run": True}

    _run_git(["checkout", "-b", branch], cwd=repo_path, env=env)
    _run_git(["add"] + all_modified, cwd=repo_path, env=env)
    _run_git(["commit", "-m", title], cwd=repo_path, env=env)
    _run_git(["push", "-u", "origin", branch], cwd=repo_path, env=env)

    result = subprocess.run(
        ["gh", "pr", "create", "--repo", repo, "--title", title, "--body", body,
         "--head", branch],
        capture_output=True, text=True, cwd=repo_path, env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(f"gh pr create failed: {result.stderr}")

    pr_url = result.stdout.strip()
    return {"branch": branch, "pr_url": pr_url, "files_modified": all_modified, "dry_run": False}


def create_gitlab_mr(
    project_id: str,
    repo_path: str,
    plans: List[EcosystemFixPlan],
    token: Optional[str] = None,
    gitlab_url: str = "https://gitlab.com",
    dry_run: bool = False,
) -> Dict:
    """Create a GitLab MR with version bumps.

    Returns dict with keys: branch, mr_url, files_modified, dry_run.
    """
    env = os.environ.copy()
    if token:
        env["GITLAB_TOKEN"] = token

    branch = build_branch_name(plans)
    title = build_pr_title(plans)
    body = build_pr_body(plans)

    all_modified = []
    for plan in plans:
        modified = apply_version_bump(plan, repo_path)
        all_modified.extend(modified)

    if not all_modified:
        return {"branch": branch, "mr_url": None, "files_modified": [], "dry_run": dry_run,
                "error": "No files were modified"}

    if dry_run:
        return {"branch": branch, "mr_url": None, "files_modified": all_modified, "dry_run": True}

    _run_git(["checkout", "-b", branch], cwd=repo_path, env=env)
    _run_git(["add"] + all_modified, cwd=repo_path, env=env)
    _run_git(["commit", "-m", title], cwd=repo_path, env=env)
    _run_git(["push", "-u", "origin", branch], cwd=repo_path, env=env)

    result = subprocess.run(
        ["glab", "mr", "create", "--title", title, "--description", body,
         "--source-branch", branch, "--yes"],
        capture_output=True, text=True, cwd=repo_path, env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(f"glab mr create failed: {result.stderr}")

    mr_url = result.stdout.strip()
    return {"branch": branch, "mr_url": mr_url, "files_modified": all_modified, "dry_run": False}


def _run_git(args: List[str], cwd: str, env: Optional[Dict] = None) -> subprocess.CompletedProcess:
    """Run a git command, raising on failure."""
    result = subprocess.run(
        ["git"] + args,
        capture_output=True, text=True, cwd=cwd, env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr}")
    return result
