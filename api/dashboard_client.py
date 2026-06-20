"""Reads dashboard data from the ez-appsec-dashboard GitHub repo via the API."""

from __future__ import annotations

import os
import time
from typing import Any

import requests

_GITHUB_API = "https://api.github.com"
_DEFAULT_OWNER = "ez-appsec"
_DEFAULT_REPO = "ez-appsec-dashboard"
_DATA_PREFIX = "public/data"

# Unauthenticated GitHub requests are capped at 60/hr; a small retry with
# exponential backoff absorbs transient 5xx and primary-rate-limit 403s.
_MAX_RETRIES = 3
_INITIAL_BACKOFF_SECONDS = 0.5


class DashboardUnavailable(Exception):
    """Raised when the dashboard backend cannot be reached or rate-limited."""


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
    backoff = _INITIAL_BACKOFF_SECONDS
    last_error: str = ""
    for attempt in range(_MAX_RETRIES):
        try:
            resp = requests.get(url, headers=_headers(), timeout=15)
        except requests.RequestException as exc:
            last_error = str(exc)
            if attempt + 1 < _MAX_RETRIES:
                time.sleep(backoff)
                backoff *= 2
                continue
            raise DashboardUnavailable(f"dashboard request failed: {last_error}") from exc

        # Retry on transient server errors and rate limiting.
        if resp.status_code in {429, 500, 502, 503, 504}:
            last_error = f"HTTP {resp.status_code}"
            if attempt + 1 < _MAX_RETRIES:
                time.sleep(backoff)
                backoff *= 2
                continue
            raise DashboardUnavailable(f"dashboard unavailable: {last_error}")

        if resp.status_code == 403 and "rate limit" in resp.text.lower():
            last_error = "GitHub rate limit exceeded"
            if attempt + 1 < _MAX_RETRIES:
                time.sleep(backoff)
                backoff *= 2
                continue
            raise DashboardUnavailable(last_error)

        try:
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise DashboardUnavailable(f"dashboard returned HTTP {resp.status_code}") from exc
        return resp.json()

    # Unreachable: loop either returns or raises on every path.
    raise DashboardUnavailable(f"dashboard unavailable: {last_error}")


def get_index() -> dict[str, Any]:
    return _get_file(f"{_DATA_PREFIX}/index.json")


def get_vulnerabilities(slug: str) -> dict[str, Any]:
    return _get_file(f"{_DATA_PREFIX}/projects/{slug}/vulnerabilities.json")


def get_history(slug: str) -> list[dict[str, Any]]:
    return _get_file(f"{_DATA_PREFIX}/projects/{slug}/history.json")
