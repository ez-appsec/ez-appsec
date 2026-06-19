"""Reads dashboard data from the ez-appsec-dashboard GitHub repo via the API."""

from __future__ import annotations

import json
import os
from typing import Any

import requests

_GITHUB_API = "https://api.github.com"
_DEFAULT_OWNER = "ez-appsec"
_DEFAULT_REPO = "ez-appsec-dashboard"
_DATA_PREFIX = "public/data"


def _owner_repo() -> tuple[str, str]:
    owner = os.environ.get("EZ_DASHBOARD_OWNER", _DEFAULT_OWNER)
    repo = os.environ.get("EZ_DASHBOARD_REPO", _DEFAULT_REPO)
    return owner, repo


def _headers() -> dict[str, str]:
    token = os.environ.get("GITHUB_TOKEN", "")
    h: dict[str, str] = {"Accept": "application/vnd.github.v3.raw"}
    if token:
        h["Authorization"] = f"token {token}"
    return h


def _get_file(path: str) -> Any:
    owner, repo = _owner_repo()
    url = f"{_GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
    resp = requests.get(url, headers=_headers(), timeout=15)
    resp.raise_for_status()
    return json.loads(resp.text)


def get_index() -> dict[str, Any]:
    return _get_file(f"{_DATA_PREFIX}/index.json")


def get_vulnerabilities(slug: str) -> dict[str, Any]:
    return _get_file(f"{_DATA_PREFIX}/projects/{slug}/vulnerabilities.json")


def get_history(slug: str) -> list[dict[str, Any]]:
    return _get_file(f"{_DATA_PREFIX}/projects/{slug}/history.json")
