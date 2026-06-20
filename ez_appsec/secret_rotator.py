"""Secret rotation automation (PLAN-17)

Detects secret types from gitleaks rule IDs, rotates them via provider APIs
(AWS IAM, GitHub PATs, GitLab PATs), writes new values to a configured secret
store (GitHub Actions secrets, GitLab CI variables, HashiCorp Vault), and
produces PRs replacing hardcoded values with environment variable references.
"""

import json
import logging
import os
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DetectedSecret:
    rule_id: str
    secret_type: str
    file: str
    line: int
    match: str
    start_column: int = 0
    end_column: int = 0
    commit: str = ""


@dataclass
class RotationResult:
    secret: DetectedSecret
    rotated: bool
    env_var_name: str
    old_revoked: bool = False
    new_secret_stored: bool = False
    store_target: str = ""
    error: Optional[str] = None


RULE_ID_TO_SECRET_TYPE: Dict[str, str] = {
    "aws-access-key-id": "aws",
    "aws-secret-access-key": "aws",
    "aws-access-token": "aws",
    "github-pat": "github_pat",
    "github-fine-grained-pat": "github_pat",
    "github-oauth": "github_pat",
    "gitlab-pat": "gitlab_pat",
    "gitlab-ptt": "gitlab_pat",
    "gitlab-rrt": "gitlab_pat",
    "gitlab-pipetrigger-token": "gitlab_pat",
}


def classify_secret(rule_id: str) -> Optional[str]:
    """Map a gitleaks rule ID to a secret type for rotation dispatch."""
    return RULE_ID_TO_SECRET_TYPE.get(rule_id)


class SecretProvider(ABC):
    """Base class for secret rotation providers."""

    @abstractmethod
    def can_rotate(self, rule_id: str) -> bool:
        """Return True if this provider handles the given gitleaks rule ID."""

    @abstractmethod
    def rotate(self, secret_value: str, rule_id: str) -> Dict[str, Any]:
        """Revoke the old secret and issue a new one.

        Returns dict with keys:
            new_value: str - the replacement secret
            revoked: bool - whether the old secret was revoked
            details: str - human-readable summary
        """


class AWSKeyProvider(SecretProvider):
    """Rotate AWS IAM access keys."""

    # AWS can rotate by AccessKeyId. The secret access key half cannot be mapped
    # back to an IAM key via AWS APIs, so treating aws-secret-access-key as
    # rotatable would create an unrelated key and leave the leaked key active.
    _handled_rules = {"aws-access-key-id", "aws-access-token"}

    def can_rotate(self, rule_id: str) -> bool:
        return rule_id in self._handled_rules

    def rotate(self, secret_value: str, rule_id: str) -> Dict[str, Any]:
        try:
            result = subprocess.run(
                ["aws", "iam", "list-access-keys", "--output", "json"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return {"new_value": "", "revoked": False,
                        "details": f"AWS CLI error: {result.stderr.strip()}"}

            keys = json.loads(result.stdout).get("AccessKeyMetadata", [])
            target_key = None
            for key in keys:
                if key.get("AccessKeyId") == secret_value:
                    target_key = key
                    break

            if not target_key and rule_id == "aws-access-key-id":
                return {"new_value": "", "revoked": False,
                        "details": f"Access key {secret_value[:8]}... not found in IAM"}

            username = target_key["UserName"] if target_key else None

            create_args = ["aws", "iam", "create-access-key", "--output", "json"]
            if username:
                create_args.extend(["--user-name", username])

            create_result = subprocess.run(
                create_args, capture_output=True, text=True, timeout=30,
            )
            if create_result.returncode != 0:
                return {"new_value": "", "revoked": False,
                        "details": f"Failed to create new key: {create_result.stderr.strip()}"}

            new_key = json.loads(create_result.stdout).get("AccessKey", {})
            new_value = new_key.get("SecretAccessKey", "")
            new_key_id = new_key.get("AccessKeyId", "")

            revoked = False
            if target_key:
                deactivate_result = subprocess.run(
                    ["aws", "iam", "update-access-key",
                     "--access-key-id", target_key["AccessKeyId"],
                     "--status", "Inactive",
                     "--user-name", target_key["UserName"]],
                    capture_output=True, text=True, timeout=30,
                )
                revoked = deactivate_result.returncode == 0

            return {
                "new_value": new_value,
                "new_key_id": new_key_id,
                "revoked": revoked,
                "details": f"New key {new_key_id} created"
                           + (f", old key {secret_value[:8]}... deactivated" if revoked else ""),
            }

        except subprocess.TimeoutExpired:
            return {"new_value": "", "revoked": False, "details": "AWS CLI timed out"}
        except Exception as e:
            return {"new_value": "", "revoked": False, "details": f"AWS rotation failed: {e}"}


class GitHubPATProvider(SecretProvider):
    """Rotate GitHub personal access tokens."""

    _handled_rules = {"github-pat", "github-fine-grained-pat", "github-oauth"}

    def can_rotate(self, rule_id: str) -> bool:
        return rule_id in self._handled_rules

    def rotate(self, secret_value: str, rule_id: str) -> Dict[str, Any]:
        try:
            delete_result = subprocess.run(
                ["gh", "api", "-X", "DELETE", "/user/tokens",
                 "--input", "-"],
                input=json.dumps({"access_token": secret_value}),
                capture_output=True, text=True, timeout=30,
            )
            revoked = delete_result.returncode == 0

            return {
                "new_value": "",
                "revoked": revoked,
                "details": ("Old token revoked. " if revoked
                            else "Could not revoke old token (may require admin scope). ")
                           + "Generate a new PAT manually at "
                           "https://github.com/settings/tokens — automated PAT creation "
                           "is not supported via the GitHub API.",
            }

        except subprocess.TimeoutExpired:
            return {"new_value": "", "revoked": False, "details": "GitHub CLI timed out"}
        except Exception as e:
            return {"new_value": "", "revoked": False, "details": f"GitHub PAT rotation failed: {e}"}


class GitLabPATProvider(SecretProvider):
    """Rotate GitLab personal/project/group access tokens."""

    _handled_rules = {"gitlab-pat", "gitlab-ptt", "gitlab-rrt", "gitlab-pipetrigger-token"}

    def can_rotate(self, rule_id: str) -> bool:
        return rule_id in self._handled_rules

    def rotate(self, secret_value: str, rule_id: str) -> Dict[str, Any]:
        gitlab_url = os.environ.get("GITLAB_URL", "https://gitlab.com")
        gitlab_token = os.environ.get("GITLAB_ACCESS_TOKEN") or os.environ.get("GITLAB_TOKEN", "")

        if not gitlab_token:
            return {"new_value": "", "revoked": False,
                    "details": "GITLAB_ACCESS_TOKEN not set — cannot call GitLab API"}

        try:
            import requests

            headers = {"PRIVATE-TOKEN": gitlab_token}
            resp = requests.get(
                f"{gitlab_url}/api/v4/personal_access_tokens/self",
                headers=headers, timeout=15,
            )
            if resp.status_code != 200:
                return {"new_value": "", "revoked": False,
                        "details": f"GitLab API returned {resp.status_code}"}

            tokens_resp = requests.get(
                f"{gitlab_url}/api/v4/personal_access_tokens",
                headers=headers, params={"state": "active"}, timeout=15,
            )
            target_token_id = None
            if tokens_resp.status_code == 200:
                candidates = []
                for tok in tokens_resp.json():
                    prefix = tok.get("token", "")
                    if prefix and secret_value.startswith(prefix):
                        candidates.append(tok)
                if len(candidates) == 1:
                    target_token_id = candidates[0]["id"]
                elif len(candidates) > 1:
                    logger.warning(
                        "Multiple GitLab tokens match prefix — skipping revocation "
                        "to avoid revoking the wrong token (matched IDs: %s)",
                        [c["id"] for c in candidates],
                    )

            revoked = False
            if target_token_id:
                revoke_resp = requests.delete(
                    f"{gitlab_url}/api/v4/personal_access_tokens/{target_token_id}",
                    headers=headers, timeout=15,
                )
                revoked = revoke_resp.status_code in (200, 204)

            return {
                "new_value": "",
                "revoked": revoked,
                "details": ("Token revoked. " if revoked else "Could not identify token to revoke. ")
                           + "Generate a new token at "
                           f"{gitlab_url}/-/user_settings/personal_access_tokens",
            }

        except ImportError:
            return {"new_value": "", "revoked": False,
                    "details": "requests library required for GitLab API calls"}
        except Exception as e:
            return {"new_value": "", "revoked": False, "details": f"GitLab rotation failed: {e}"}


PROVIDERS: List[SecretProvider] = [
    AWSKeyProvider(),
    GitHubPATProvider(),
    GitLabPATProvider(),
]


def get_provider(rule_id: str) -> Optional[SecretProvider]:
    """Find the provider that handles a given gitleaks rule ID."""
    for provider in PROVIDERS:
        if provider.can_rotate(rule_id):
            return provider
    return None


class SecretStore(ABC):
    """Base class for secret store writers."""

    @abstractmethod
    def write(self, name: str, value: str) -> bool:
        """Write a secret value to the store. Returns True on success."""


class GitHubActionsSecretStore(SecretStore):
    """Write secrets to GitHub Actions repository secrets."""

    def __init__(self, repo: str, token: Optional[str] = None):
        self.repo = repo
        self.token = token

    def write(self, name: str, value: str) -> bool:
        env = os.environ.copy()
        if self.token:
            env["GH_TOKEN"] = self.token
        result = subprocess.run(
            ["gh", "secret", "set", name, "--repo", self.repo],
            input=value, capture_output=True, text=True, env=env, timeout=30,
        )
        return result.returncode == 0


class GitLabCIVariableStore(SecretStore):
    """Write secrets to GitLab CI/CD project variables."""

    def __init__(self, project_id: str, gitlab_url: str = "https://gitlab.com",
                 token: Optional[str] = None):
        self.project_id = project_id
        self.gitlab_url = gitlab_url
        self.token = token

    def write(self, name: str, value: str) -> bool:
        token = self.token or os.environ.get("GITLAB_ACCESS_TOKEN") or os.environ.get("GITLAB_TOKEN", "")
        if not token:
            return False
        try:
            import requests
            resp = requests.post(
                f"{self.gitlab_url}/api/v4/projects/{self.project_id}/variables",
                headers={"PRIVATE-TOKEN": token},
                json={"key": name, "value": value, "masked": True, "protected": True},
                timeout=15,
            )
            if resp.status_code == 409:
                resp = requests.put(
                    f"{self.gitlab_url}/api/v4/projects/{self.project_id}/variables/{name}",
                    headers={"PRIVATE-TOKEN": token},
                    json={"value": value, "masked": True, "protected": True},
                    timeout=15,
                )
            return resp.status_code in (200, 201)
        except Exception:
            return False


class VaultSecretStore(SecretStore):
    """Write secrets to HashiCorp Vault KV v2."""

    def __init__(self, vault_addr: Optional[str] = None, mount: str = "secret"):
        self.vault_addr = vault_addr or os.environ.get("VAULT_ADDR", "")
        self.mount = mount

    def write(self, name: str, value: str) -> bool:
        if not self.vault_addr:
            return False
        result = subprocess.run(
            ["vault", "kv", "put", f"{self.mount}/{name}", "-"],
            input=json.dumps({"value": value}),
            capture_output=True, text=True, timeout=30,
            env={**os.environ, "VAULT_ADDR": self.vault_addr},
        )
        return result.returncode == 0


def create_secret_store(
    store_type: str,
    repo: Optional[str] = None,
    project_id: Optional[str] = None,
    gitlab_url: str = "https://gitlab.com",
    token: Optional[str] = None,
) -> SecretStore:
    """Factory for secret stores."""
    if store_type == "github":
        if not repo:
            raise ValueError("--repo is required for GitHub Actions secret store")
        return GitHubActionsSecretStore(repo, token=token)
    elif store_type == "gitlab":
        if not project_id:
            raise ValueError("--repo (project ID) is required for GitLab CI variable store")
        return GitLabCIVariableStore(project_id, gitlab_url=gitlab_url, token=token)
    elif store_type == "vault":
        return VaultSecretStore()
    else:
        raise ValueError(f"Unknown secret store type: {store_type}")


def parse_gitleaks_findings(gitleaks_json_path: str) -> List[DetectedSecret]:
    """Parse raw gitleaks JSON output into a list of rotatable secrets."""
    with open(gitleaks_json_path) as f:
        data = json.load(f)

    if not isinstance(data, list):
        data = [data]

    secrets = []
    for match in data:
        rule_id = match.get("RuleID", "")
        secret_type = classify_secret(rule_id)
        if not secret_type:
            logger.debug(f"Skipping unsupported rule ID: {rule_id}")
            continue

        secrets.append(DetectedSecret(
            rule_id=rule_id,
            secret_type=secret_type,
            file=match.get("File", "unknown"),
            line=match.get("StartLine", 1),
            match=match.get("Match", ""),
            start_column=match.get("StartColumn", 0),
            end_column=match.get("EndColumn", 0),
            commit=match.get("Commit", ""),
        ))

    return secrets


def _build_env_var_names(secrets: List[DetectedSecret]) -> Dict[int, str]:
    """Generate unique environment variable names for a list of secrets."""
    counts: Dict[str, int] = {}
    names: Dict[int, str] = {}
    for i, secret in enumerate(secrets):
        base = secret.rule_id.upper().replace("-", "_")
        counts[base] = counts.get(base, 0) + 1

    seen: Dict[str, int] = {}
    for i, secret in enumerate(secrets):
        base = secret.rule_id.upper().replace("-", "_")
        if counts[base] > 1:
            seen[base] = seen.get(base, 0) + 1
            names[i] = f"{base}_{seen[base]}"
        else:
            names[i] = base
    return names


def rotate_secrets(
    secrets: List[DetectedSecret],
    store: Optional[SecretStore] = None,
    dry_run: bool = False,
) -> List[RotationResult]:
    """Rotate a list of detected secrets.

    For each secret:
    1. Find the provider that can handle its rule_id
    2. Call provider.rotate() to revoke old and issue new
    3. Write new secret to the store (if provided and not dry_run)
    4. Return a RotationResult for PR body generation
    """
    env_var_names = _build_env_var_names(secrets)
    results = []
    for i, secret in enumerate(secrets):
        env_var_name = env_var_names[i]
        provider = get_provider(secret.rule_id)

        if not provider:
            results.append(RotationResult(
                secret=secret, rotated=False, env_var_name=env_var_name,
                error=f"No provider for rule_id: {secret.rule_id}",
            ))
            continue

        if dry_run:
            results.append(RotationResult(
                secret=secret, rotated=False, env_var_name=env_var_name,
            ))
            continue

        rotation = provider.rotate(secret.match, secret.rule_id)

        stored = False
        store_error = ""
        if store and rotation.get("new_value"):
            stored = store.write(env_var_name, rotation["new_value"])
            if not stored:
                store_error = f"Failed to write {env_var_name} to {type(store).__name__}"
                logger.warning(store_error)

        error_msg = None
        if not rotation.get("new_value") and not rotation.get("revoked"):
            error_msg = rotation.get("details")
        elif store_error:
            error_msg = store_error

        results.append(RotationResult(
            secret=secret,
            rotated=bool(rotation.get("revoked")),
            env_var_name=env_var_name,
            old_revoked=rotation.get("revoked", False),
            new_secret_stored=stored,
            store_target=type(store).__name__ if store else "",
            error=error_msg,
        ))

    return results


def replace_hardcoded_secret(
    file_path: str,
    secret: DetectedSecret,
    env_var_name: str,
) -> bool:
    """Replace a hardcoded secret value with os.environ.get() in the source file.

    Returns True if the file was modified.
    """
    path = Path(file_path)
    if not path.exists():
        return False

    content = path.read_text()
    if secret.match not in content:
        return False

    ext = path.suffix.lower()
    if ext in (".py",):
        replacement = f'os.environ.get("{env_var_name}")'
    elif ext in (".js", ".ts", ".mjs", ".cjs"):
        replacement = f'process.env.{env_var_name}'
    elif ext in (".rb",):
        replacement = f"ENV['{env_var_name}']"
    elif ext in (".go",):
        replacement = f'os.Getenv("{env_var_name}")'
    elif ext in (".java", ".kt"):
        replacement = f'System.getenv("{env_var_name}")'
    elif ext in (".php",):
        replacement = f"getenv('{env_var_name}')"
    elif ext in (".yaml", ".yml", ".env", ".cfg", ".ini", ".conf", ".toml"):
        replacement = f"${{{env_var_name}}}"
    else:
        replacement = f'os.environ.get("{env_var_name}")'

    quoted_patterns = [
        (f'"{secret.match}"', replacement if ext not in (".yaml", ".yml", ".env", ".cfg", ".ini", ".conf", ".toml") else f'"{replacement}"'),
        (f"'{secret.match}'", replacement if ext not in (".yaml", ".yml", ".env", ".cfg", ".ini", ".conf", ".toml") else f"'{replacement}'"),
    ]

    modified = False
    for old, new in quoted_patterns:
        if old in content:
            content = content.replace(old, new, 1)
            modified = True
            break

    if not modified and secret.match in content:
        content = content.replace(secret.match, replacement, 1)
        modified = True

    if modified:
        path.write_text(content)

    return modified


def build_rotation_pr_body(results: List[RotationResult]) -> str:
    """Build PR body listing rotated secrets."""
    lines = [
        "## Automated Secret Rotation",
        "",
        "This PR replaces hardcoded secrets with environment variable references.",
        "",
        "| File | Rule | Env Var | Rotated | Old Revoked | Stored |",
        "|------|------|---------|---------|-------------|--------|",
    ]

    for r in results:
        rotated = "Yes" if r.rotated else "No"
        revoked = "Yes" if r.old_revoked else "No"
        stored = r.store_target if r.new_secret_stored else "N/A"
        error_note = f" ({r.error})" if r.error else ""
        lines.append(
            f"| `{r.secret.file}:{r.secret.line}` | {r.secret.rule_id} "
            f"| `{r.env_var_name}` | {rotated}{error_note} | {revoked} | {stored} |"
        )

    lines.append("")
    lines.append("### Action Required")
    lines.append("")

    needs_manual = [r for r in results if not r.new_secret_stored and r.rotated]
    if needs_manual:
        lines.append("The following secrets were rotated but need to be added to your secret store manually:")
        lines.append("")
        for r in needs_manual:
            lines.append(f"- `{r.env_var_name}` (from `{r.secret.file}`)")
        lines.append("")

    not_rotated = [r for r in results if not r.rotated and r.error]
    if not_rotated:
        lines.append("The following secrets could not be rotated automatically:")
        lines.append("")
        for r in not_rotated:
            lines.append(f"- `{r.secret.rule_id}` in `{r.secret.file}:{r.secret.line}`: {r.error}")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by [ez-appsec](https://github.com/ez-appsec/ez-appsec) `rotate-secrets`*")
    return "\n".join(lines)


def build_rotation_branch_name(results: List[RotationResult]) -> str:
    """Generate a branch name for a secret rotation PR."""
    types = sorted(set(r.secret.secret_type for r in results))
    type_slug = "-".join(types)
    return f"ez-appsec/rotate-{type_slug}-{len(results)}-secrets"


def build_rotation_pr_title(results: List[RotationResult]) -> str:
    """Generate a PR title for secret rotation."""
    count = len(results)
    types = sorted(set(r.secret.secret_type for r in results))
    type_label = ", ".join(types)
    return f"fix(secrets): rotate {count} exposed {type_label} secret(s)"


def create_rotation_pr(
    repo: str,
    repo_path: str,
    results: List[RotationResult],
    platform: str = "github",
    token: Optional[str] = None,
    gitlab_url: str = "https://gitlab.com",
    dry_run: bool = False,
) -> Dict:
    """Create a PR/MR with secret replacements.

    Returns dict with keys: branch, pr_url/mr_url, files_modified, dry_run, error.
    """
    files_modified = []
    for r in results:
        src_path = os.path.join(repo_path, r.secret.file)
        if replace_hardcoded_secret(src_path, r.secret, r.env_var_name):
            files_modified.append(r.secret.file)

    branch = build_rotation_branch_name(results)
    title = build_rotation_pr_title(results)
    body = build_rotation_pr_body(results)

    if not files_modified:
        return {"branch": branch, "pr_url": None, "mr_url": None,
                "files_modified": [], "dry_run": dry_run,
                "error": "No files were modified — secret strings may not match source content"}

    if dry_run:
        return {"branch": branch, "pr_url": None, "mr_url": None,
                "files_modified": files_modified, "dry_run": True}

    env = os.environ.copy()

    from ez_appsec.fix_pr import _run_git

    _run_git(["checkout", "-b", branch], cwd=repo_path, env=env)
    _run_git(["add"] + files_modified, cwd=repo_path, env=env)
    _run_git(["commit", "-m", title], cwd=repo_path, env=env)
    _run_git(["push", "-u", "origin", branch], cwd=repo_path, env=env)

    if platform == "github":
        if token:
            env["GH_TOKEN"] = token
        result = subprocess.run(
            ["gh", "pr", "create", "--repo", repo, "--title", title, "--body", body,
             "--head", branch],
            capture_output=True, text=True, cwd=repo_path, env=env,
        )
        if result.returncode != 0:
            raise RuntimeError(f"gh pr create failed: {result.stderr}")
        return {"branch": branch, "pr_url": result.stdout.strip(), "mr_url": None,
                "files_modified": files_modified, "dry_run": False}
    else:
        if token:
            env["GITLAB_TOKEN"] = token
        result = subprocess.run(
            ["glab", "mr", "create", "--title", title, "--description", body,
             "--source-branch", branch, "--yes"],
            capture_output=True, text=True, cwd=repo_path, env=env,
        )
        if result.returncode != 0:
            raise RuntimeError(f"glab mr create failed: {result.stderr}")
        return {"branch": branch, "pr_url": None, "mr_url": result.stdout.strip(),
                "files_modified": files_modified, "dry_run": False}
