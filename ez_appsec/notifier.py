"""Webhook notifications for Slack and Teams (PLAN-07).

Sends notifications when scans produce new critical or high findings.
Configurable via EZ_APPSEC_SLACK_WEBHOOK / EZ_APPSEC_TEAMS_WEBHOOK env vars.
"""

import json
import os
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


@dataclass
class NotificationPayload:
    project_name: str
    total_new: int
    critical: int
    high: int
    medium: int
    low: int
    top_findings: List[Dict[str, Any]] = field(default_factory=list)
    dashboard_url: str = ""


def build_payload(
    findings: List[Dict[str, Any]],
    project_name: str = "unknown",
    dashboard_url: str = "",
    max_top: int = 3,
) -> NotificationPayload:
    """Build a notification payload from a list of new findings."""
    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = (f.get("severity") or "low").lower()
        if sev in counts:
            counts[sev] += 1

    top = findings[:max_top]
    top_findings = [
        {
            "severity": (f.get("severity") or "unknown").lower(),
            "title": f.get("title", f.get("name", f.get("ruleId", "untitled"))),
            "file": f.get("file", f.get("location", {}).get("file", "")),
        }
        for f in top
    ]

    return NotificationPayload(
        project_name=project_name,
        total_new=len(findings),
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        top_findings=top_findings,
        dashboard_url=dashboard_url,
    )


def should_notify(findings: List[Dict[str, Any]]) -> bool:
    """Only notify when there are new critical or high findings."""
    for f in findings:
        sev = (f.get("severity") or "").lower()
        if sev in ("critical", "high"):
            return True
    return False


class SlackNotifier:
    """Posts Block Kit messages to a Slack incoming webhook."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def format_message(self, payload: NotificationPayload) -> Dict[str, Any]:
        severity_line = []
        if payload.critical:
            severity_line.append(f"*Critical:* {payload.critical}")
        if payload.high:
            severity_line.append(f"*High:* {payload.high}")
        if payload.medium:
            severity_line.append(f"*Medium:* {payload.medium}")
        if payload.low:
            severity_line.append(f"*Low:* {payload.low}")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🔒 ez-appsec: {payload.total_new} new finding(s)",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Project:* {payload.project_name}\n"
                    + " | ".join(severity_line),
                },
            },
        ]

        if payload.top_findings:
            finding_lines = []
            for f in payload.top_findings:
                file_part = f" — `{f['file']}`" if f.get("file") else ""
                finding_lines.append(
                    f"• [{f['severity'].upper()}] {f['title']}{file_part}"
                )
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "\n".join(finding_lines),
                    },
                }
            )

        if payload.dashboard_url:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"<{payload.dashboard_url}|View Dashboard>",
                    },
                }
            )

        return {"blocks": blocks}

    def send(self, payload: NotificationPayload) -> bool:
        body = self.format_message(payload)
        return _post_json(self.webhook_url, body)


class TeamsNotifier:
    """Posts Adaptive Card messages to a Teams incoming webhook."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def format_message(self, payload: NotificationPayload) -> Dict[str, Any]:
        severity_parts = []
        if payload.critical:
            severity_parts.append(f"**Critical:** {payload.critical}")
        if payload.high:
            severity_parts.append(f"**High:** {payload.high}")
        if payload.medium:
            severity_parts.append(f"**Medium:** {payload.medium}")
        if payload.low:
            severity_parts.append(f"**Low:** {payload.low}")

        facts = [
            {"title": "Project", "value": payload.project_name},
            {"title": "New Findings", "value": str(payload.total_new)},
        ]

        body_items = [
            {
                "type": "TextBlock",
                "size": "Medium",
                "weight": "Bolder",
                "text": f"🔒 ez-appsec: {payload.total_new} new finding(s)",
            },
            {
                "type": "FactSet",
                "facts": facts,
            },
        ]

        if severity_parts:
            body_items.append(
                {
                    "type": "TextBlock",
                    "text": " | ".join(severity_parts),
                    "wrap": True,
                }
            )

        if payload.top_findings:
            finding_lines = []
            for f in payload.top_findings:
                file_part = f" — `{f['file']}`" if f.get("file") else ""
                finding_lines.append(
                    f"- [{f['severity'].upper()}] {f['title']}{file_part}"
                )
            body_items.append(
                {
                    "type": "TextBlock",
                    "text": "\n".join(finding_lines),
                    "wrap": True,
                }
            )

        actions = []
        if payload.dashboard_url:
            actions.append(
                {
                    "type": "Action.OpenUrl",
                    "title": "View Dashboard",
                    "url": payload.dashboard_url,
                }
            )

        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": body_items,
                        **({"actions": actions} if actions else {}),
                    },
                }
            ],
        }
        return card

    def send(self, payload: NotificationPayload) -> bool:
        body = self.format_message(payload)
        return _post_json(self.webhook_url, body)


def _post_json(url: str, body: Dict[str, Any]) -> bool:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        return False


def notify_on_new_findings(
    findings: List[Dict[str, Any]],
    project_name: str = "",
    dashboard_url: str = "",
    slack_webhook: Optional[str] = None,
    teams_webhook: Optional[str] = None,
) -> Dict[str, Any]:
    """Send notifications if there are new critical/high findings.

    Called at end of scan pipeline. Reads webhook URLs from parameters
    or from EZ_APPSEC_SLACK_WEBHOOK / EZ_APPSEC_TEAMS_WEBHOOK env vars.

    Returns dict with send results.
    """
    slack_url = slack_webhook or os.environ.get("EZ_APPSEC_SLACK_WEBHOOK", "")
    teams_url = teams_webhook or os.environ.get("EZ_APPSEC_TEAMS_WEBHOOK", "")

    result: Dict[str, Any] = {
        "notified": False,
        "slack": None,
        "teams": None,
        "reason": "",
    }

    if not slack_url and not teams_url:
        result["reason"] = "no webhook configured"
        return result

    if not findings:
        result["reason"] = "no new findings"
        return result

    if not should_notify(findings):
        result["reason"] = "no critical/high findings"
        return result

    proj = project_name or os.environ.get("EZ_APPSEC_PROJECT_NAME", "unknown")
    dash = dashboard_url or os.environ.get("EZ_APPSEC_DASHBOARD_URL", "")

    payload = build_payload(findings, project_name=proj, dashboard_url=dash)

    if slack_url:
        notifier = SlackNotifier(slack_url)
        result["slack"] = notifier.send(payload)

    if teams_url:
        notifier = TeamsNotifier(teams_url)
        result["teams"] = notifier.send(payload)

    result["notified"] = bool(result.get("slack") or result.get("teams"))
    return result
