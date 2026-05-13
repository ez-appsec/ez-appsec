"""Multi-tenant organization management for ez-appsec (PLAN-18)"""

import json
import logging
import os
import copy
from typing import Any, Dict, List, Optional
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"


class OrgManager:
    """Manage ez-appsec across all repositories in a GitHub organization.

    Supports org-level config inheritance, bulk workflow installation,
    and repo discovery.
    """

    def __init__(self, org: str, github_token: str, config_repo: Optional[str] = None):
        """
        Args:
            org: GitHub organization login name.
            github_token: Personal access token or GitHub App token with org read access.
            config_repo: Repository containing org-level .ez-appsec.yaml.
                         Defaults to ``<org>/.ez-appsec-config``.
        """
        self.org = org
        self.token = github_token
        self.config_repo = config_repo or f"{org}/.ez-appsec-config"

    def _github_get(self, url: str) -> Any:
        """Make an authenticated GET request to the GitHub API."""
        req = Request(url, headers={
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())

    def _github_get_paginated(self, url: str) -> List[Dict[str, Any]]:
        """Fetch all pages from a paginated GitHub API endpoint."""
        results: List[Dict[str, Any]] = []
        page = 1
        while True:
            sep = "&" if "?" in url else "?"
            page_url = f"{url}{sep}page={page}&per_page=100"
            data = self._github_get(page_url)
            if not data:
                break
            results.extend(data)
            if len(data) < 100:
                break
            page += 1
        return results

    def _github_put(self, url: str, body: bytes) -> Any:
        """Make an authenticated PUT request to the GitHub API."""
        req = Request(url, data=body, method="PUT", headers={
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())

    def discover_repos(self) -> List[str]:
        """List all non-archived, non-fork repositories in the organization.

        Returns:
            List of repository full names (e.g. ``["myorg/repo1", "myorg/repo2"]``).
        """
        url = f"{GITHUB_API}/orgs/{self.org}/repos?type=sources"
        repos = self._github_get_paginated(url)
        return [
            r["full_name"]
            for r in repos
            if not r.get("archived") and not r.get("fork")
        ]

    def get_org_config(self) -> Dict[str, Any]:
        """Fetch the org-level .ez-appsec.yaml from the config repo.

        Returns:
            Parsed YAML config as a dict, or empty dict if not found.
        """
        import yaml

        url = (
            f"{GITHUB_API}/repos/{self.config_repo}"
            f"/contents/.ez-appsec.yaml"
        )
        try:
            data = self._github_get(url)
        except HTTPError as exc:
            if exc.code == 404:
                logger.info(
                    "No org config found at %s/.ez-appsec.yaml", self.config_repo
                )
                return {}
            raise

        import base64
        content = base64.b64decode(data["content"]).decode()
        return yaml.safe_load(content) or {}

    def get_repo_config(self, repo: str) -> Dict[str, Any]:
        """Fetch the repo-level .ez-appsec.yaml for a single repo.

        Returns:
            Parsed YAML config as a dict, or empty dict if not found.
        """
        import yaml

        url = f"{GITHUB_API}/repos/{repo}/contents/.ez-appsec.yaml"
        try:
            data = self._github_get(url)
        except HTTPError as exc:
            if exc.code == 404:
                return {}
            raise

        import base64
        content = base64.b64decode(data["content"]).decode()
        return yaml.safe_load(content) or {}

    @staticmethod
    def merge_configs(org_config: Dict[str, Any], repo_config: Dict[str, Any]) -> Dict[str, Any]:
        """Merge org-level and repo-level configs. Repo keys take precedence.

        For top-level keys, repo values override org values.  If a key
        exists only in the org config, it is inherited.

        Args:
            org_config: Organization-level configuration.
            repo_config: Repository-level configuration.

        Returns:
            Merged configuration dictionary.
        """
        merged = copy.deepcopy(org_config)
        for key, value in repo_config.items():
            merged[key] = value
        return merged

    def install_repo(self, repo: str, dry_run: bool = False) -> Dict[str, Any]:
        """Install or update ez-appsec workflow and config in a repository.

        Creates ``.github/workflows/ez-appsec-scan.yml`` and sets the
        merged config as a repository action variable.

        Args:
            repo: Repository full name (e.g. ``myorg/myapp``).
            dry_run: If True, return the plan without making changes.

        Returns:
            Dict with ``repo``, ``actions`` list, and ``dry_run`` flag.
        """
        org_config = self.get_org_config()
        repo_config = self.get_repo_config(repo)
        merged = self.merge_configs(org_config, repo_config)

        workflow_content = _build_scan_workflow(merged)

        actions = []

        if dry_run:
            actions.append(f"would create/update .github/workflows/ez-appsec-scan.yml")
            if merged:
                actions.append(f"would set merged config ({len(merged)} keys)")
            return {"repo": repo, "actions": actions, "dry_run": True}

        import base64
        encoded = base64.b64encode(workflow_content.encode()).decode()

        existing_sha = None
        url = f"{GITHUB_API}/repos/{repo}/contents/.github/workflows/ez-appsec-scan.yml"
        try:
            existing = self._github_get(url)
            existing_sha = existing.get("sha")
        except HTTPError as exc:
            if exc.code != 404:
                raise

        body: Dict[str, Any] = {
            "message": "chore: install ez-appsec scan workflow",
            "content": encoded,
        }
        if existing_sha:
            body["sha"] = existing_sha
            body["message"] = "chore: update ez-appsec scan workflow"

        self._github_put(url, json.dumps(body).encode())
        actions.append("created/updated .github/workflows/ez-appsec-scan.yml")

        return {"repo": repo, "actions": actions, "dry_run": False}

    def dry_run(self) -> List[Dict[str, Any]]:
        """Return the list of repos that would be updated without making changes.

        Returns:
            List of dicts with ``repo`` and ``actions`` keys.
        """
        repos = self.discover_repos()
        results = []
        for repo in repos:
            result = self.install_repo(repo, dry_run=True)
            results.append(result)
        return results

    def sync_all(self, dry_run: bool = False) -> List[Dict[str, Any]]:
        """Discover all repos and install/update ez-appsec in each.

        Args:
            dry_run: If True, return plans without making changes.

        Returns:
            List of per-repo result dicts.
        """
        repos = self.discover_repos()
        results = []
        for repo in repos:
            try:
                result = self.install_repo(repo, dry_run=dry_run)
                results.append(result)
                logger.info("Synced %s: %s", repo, result["actions"])
            except Exception as exc:
                logger.error("Failed to sync %s: %s", repo, exc)
                results.append({"repo": repo, "actions": [], "error": str(exc)})
        return results


def _build_scan_workflow(config: Dict[str, Any]) -> str:
    """Generate a GitHub Actions workflow YAML for ez-appsec scanning."""
    severity = config.get("severity", "medium")
    return f"""name: ez-appsec Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Run ez-appsec scan
        uses: docker://ghcr.io/ez-appsec/ez-appsec:latest
        with:
          args: github-scan . --output results.sarif --severity {severity}

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: ez-appsec
"""
