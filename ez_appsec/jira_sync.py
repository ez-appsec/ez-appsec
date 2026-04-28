"""Jira integration for syncing security findings to Jira issues (PLAN-08).

Creates Jira issues for new critical/high findings, updates existing issues
when findings change, and closes tickets when findings are resolved.
Configurable via EZ_APPSEC_JIRA_URL, EZ_APPSEC_JIRA_TOKEN,
EZ_APPSEC_JIRA_PROJECT env vars.
"""

import hashlib
import json
import os
import urllib.error
import urllib.request
from base64 import b64encode
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _fingerprint(finding: Dict[str, Any]) -> str:
    rule_id = finding.get("rule_id", finding.get("ruleId", finding.get("id", "")))
    file_path = finding.get("file", finding.get("location", {}).get("file", ""))
    raw = f"{rule_id}:{file_path}"
    return hashlib.sha256(raw.encode()).hexdigest()


@dataclass
class JiraConfig:
    url: str
    email: str
    token: str
    project_key: str
    issue_type: str = "Bug"
    labels: List[str] = field(default_factory=lambda: ["security", "ez-appsec"])
    resolve_transition: str = "Done"

    @classmethod
    def from_env(cls) -> Optional["JiraConfig"]:
        url = os.environ.get("EZ_APPSEC_JIRA_URL", "").rstrip("/")
        email = os.environ.get("EZ_APPSEC_JIRA_EMAIL", "")
        token = os.environ.get("EZ_APPSEC_JIRA_TOKEN", "")
        project = os.environ.get("EZ_APPSEC_JIRA_PROJECT", "")
        if not all([url, email, token, project]):
            return None
        return cls(
            url=url,
            email=email,
            token=token,
            project_key=project,
            issue_type=os.environ.get("EZ_APPSEC_JIRA_ISSUE_TYPE", "Bug"),
        )


class JiraIssueMap:
    """Manages fingerprint → Jira issue key mapping for dedup."""

    def __init__(self, map_path: str):
        self.path = Path(map_path)
        self._data: Dict[str, str] = {}
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                with open(self.path) as f:
                    self._data = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(self._data, f, indent=2)

    def get(self, fingerprint: str) -> Optional[str]:
        return self._data.get(fingerprint)

    def set(self, fingerprint: str, issue_key: str):
        self._data[fingerprint] = issue_key

    def remove(self, fingerprint: str):
        self._data.pop(fingerprint, None)

    def all_fingerprints(self) -> set:
        return set(self._data.keys())

    def items(self) -> List[Tuple[str, str]]:
        return list(self._data.items())


class JiraClient:
    """Thin wrapper around Jira REST API v3."""

    def __init__(self, config: JiraConfig):
        self.config = config
        self._auth_header = self._build_auth(config.email, config.token)

    @staticmethod
    def _build_auth(email: str, token: str) -> str:
        creds = b64encode(f"{email}:{token}".encode()).decode()
        return f"Basic {creds}"

    def _request(
        self, method: str, path: str, body: Optional[Dict] = None
    ) -> Tuple[int, Dict[str, Any]]:
        url = f"{self.config.url}/rest/api/3/{path.lstrip('/')}"
        data = json.dumps(body).encode("utf-8") if body else None
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": self._auth_header,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp_body = resp.read().decode("utf-8")
                return resp.status, json.loads(resp_body) if resp_body else {}
        except urllib.error.HTTPError as e:
            resp_body = e.read().decode("utf-8") if e.fp else ""
            try:
                return e.code, json.loads(resp_body) if resp_body else {}
            except json.JSONDecodeError:
                return e.code, {"error": resp_body}
        except (urllib.error.URLError, OSError) as e:
            return 0, {"error": str(e)}

    def create_issue(
        self,
        summary: str,
        description: Dict[str, Any],
        labels: Optional[List[str]] = None,
        priority: Optional[str] = None,
    ) -> Tuple[bool, Dict[str, Any]]:
        fields: Dict[str, Any] = {
            "project": {"key": self.config.project_key},
            "issuetype": {"name": self.config.issue_type},
            "summary": summary,
            "description": description,
        }
        if labels:
            fields["labels"] = labels
        if priority:
            fields["priority"] = {"name": priority}

        status, data = self._request("POST", "issue", {"fields": fields})
        return 200 <= status < 300, data

    def get_issue(self, issue_key: str) -> Tuple[bool, Dict[str, Any]]:
        status, data = self._request("GET", f"issue/{issue_key}")
        return 200 <= status < 300, data

    def add_comment(
        self, issue_key: str, body: Dict[str, Any]
    ) -> Tuple[bool, Dict[str, Any]]:
        status, data = self._request(
            "POST", f"issue/{issue_key}/comment", {"body": body}
        )
        return 200 <= status < 300, data

    def transition_issue(
        self, issue_key: str, transition_name: str
    ) -> Tuple[bool, Dict[str, Any]]:
        ok, data = self._request("GET", f"issue/{issue_key}/transitions")
        if not ok:
            return False, data

        transitions = data.get("transitions", [])
        target = None
        for t in transitions:
            if t["name"].lower() == transition_name.lower():
                target = t
                break

        if not target:
            available = [t["name"] for t in transitions]
            return False, {
                "error": f"Transition '{transition_name}' not found. Available: {available}"
            }

        status, result = self._request(
            "POST",
            f"issue/{issue_key}/transitions",
            {"transition": {"id": target["id"]}},
        )
        return 200 <= status < 300, result


def _severity_to_priority(severity: str) -> str:
    mapping = {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }
    return mapping.get(severity.lower(), "Medium")


def _build_summary(finding: Dict[str, Any]) -> str:
    severity = (finding.get("severity") or "unknown").upper()
    title = finding.get("title", finding.get("name", finding.get("ruleId", "Security Finding")))
    file_path = finding.get("file", finding.get("location", {}).get("file", ""))
    if file_path:
        return f"[{severity}] {title} — {file_path}"
    return f"[{severity}] {title}"


def _build_description(
    finding: Dict[str, Any], dashboard_url: str = ""
) -> Dict[str, Any]:
    """Build ADF (Atlassian Document Format) description."""
    content: List[Dict[str, Any]] = []

    severity = (finding.get("severity") or "unknown").capitalize()
    scanner = finding.get("scanner", finding.get("source", "unknown"))
    rule_id = finding.get("rule_id", finding.get("ruleId", finding.get("id", "")))
    file_path = finding.get("file", finding.get("location", {}).get("file", ""))
    line = finding.get("line", finding.get("location", {}).get("start_line", ""))
    description_text = finding.get("description", finding.get("message", ""))
    remediation = finding.get("remediation", finding.get("fix", ""))

    # Details table
    rows = [
        ("Severity", severity),
        ("Scanner", scanner),
    ]
    if rule_id:
        rows.append(("Rule ID", rule_id))
    if file_path:
        loc = f"{file_path}:{line}" if line else file_path
        rows.append(("Location", loc))

    for label, value in rows:
        content.append(
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": f"{label}: ", "marks": [{"type": "strong"}]},
                    {"type": "text", "text": str(value)},
                ],
            }
        )

    if description_text:
        content.append(
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "Description: ", "marks": [{"type": "strong"}]},
                    {"type": "text", "text": description_text},
                ],
            }
        )

    if remediation:
        content.append(
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "Remediation: ", "marks": [{"type": "strong"}]},
                    {"type": "text", "text": remediation},
                ],
            }
        )

    if dashboard_url:
        content.append(
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "Dashboard: ", "marks": [{"type": "strong"}]},
                    {
                        "type": "text",
                        "text": dashboard_url,
                        "marks": [{"type": "link", "attrs": {"href": dashboard_url}}],
                    },
                ],
            }
        )

    return {"version": 1, "type": "doc", "content": content}


def _build_resolved_comment() -> Dict[str, Any]:
    return {
        "version": 1,
        "type": "doc",
        "content": [
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": "This finding is no longer detected by ez-appsec. Closing automatically.",
                    }
                ],
            }
        ],
    }


def should_sync(findings: List[Dict[str, Any]]) -> bool:
    for f in findings:
        sev = (f.get("severity") or "").lower()
        if sev in ("critical", "high"):
            return True
    return False


def sync_findings(
    findings: List[Dict[str, Any]],
    jira_config: JiraConfig,
    map_path: str,
    dashboard_url: str = "",
    close_resolved: bool = True,
) -> Dict[str, Any]:
    """Sync findings to Jira: create new issues, close resolved ones.

    Returns summary of actions taken.
    """
    client = JiraClient(jira_config)
    issue_map = JiraIssueMap(map_path)

    result: Dict[str, Any] = {
        "created": [],
        "skipped_existing": [],
        "closed": [],
        "errors": [],
    }

    current_fingerprints = set()

    for finding in findings:
        sev = (finding.get("severity") or "").lower()
        if sev not in ("critical", "high"):
            continue

        fp = _fingerprint(finding)
        current_fingerprints.add(fp)

        existing_key = issue_map.get(fp)
        if existing_key:
            result["skipped_existing"].append(existing_key)
            continue

        summary = _build_summary(finding)
        description = _build_description(finding, dashboard_url)
        priority = _severity_to_priority(sev)

        ok, data = client.create_issue(
            summary=summary,
            description=description,
            labels=jira_config.labels,
            priority=priority,
        )

        if ok:
            issue_key = data.get("key", "")
            issue_map.set(fp, issue_key)
            result["created"].append(issue_key)
        else:
            result["errors"].append(
                {"finding": summary, "error": data.get("error", str(data))}
            )

    if close_resolved:
        stale_fps = issue_map.all_fingerprints() - current_fingerprints
        for fp in stale_fps:
            issue_key = issue_map.get(fp)
            if not issue_key:
                continue

            comment_body = _build_resolved_comment()
            client.add_comment(issue_key, comment_body)

            ok, data = client.transition_issue(
                issue_key, jira_config.resolve_transition
            )
            if ok:
                result["closed"].append(issue_key)
                issue_map.remove(fp)
            else:
                result["errors"].append(
                    {"issue": issue_key, "error": data.get("error", str(data))}
                )

    issue_map.save()
    return result
