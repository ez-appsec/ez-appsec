#!/usr/bin/env python3
"""Push a plan file to GitHub as ordered issues on a project board.

Usage:
    python3 scripts/push-plans.py <plan.json>
    python3 scripts/push-plans.py plans/data-arch-v2.json

Reads the plan JSON (see plan-template.json for schema), creates one GitHub
issue per task in order, adds each to the target project board with status
"Todo", and annotates dependency links in the issue body.

Requires:
    - ~/git/.env with GITHUB_ACCESS_TOKEN=ghp_...
    - gh CLI installed and the token must have repo + project scopes
"""
import json
import os
import subprocess
import sys
from pathlib import Path


ENV_FILE = Path.home() / "git" / ".env"


def load_env():
    """Load key=value pairs from ENV_FILE into os.environ (does not overwrite)."""
    if not ENV_FILE.exists():
        return
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        os.environ.setdefault(key.strip(), val.strip())


load_env()

PROJECT_OWNER = os.environ.get("GH_PROJECT_OWNER", "ez-appsec")
PROJECT_NUMBER = int(os.environ.get("GH_PROJECT_NUMBER", "2"))
STATUS_FIELD_ID = os.environ.get("GH_STATUS_FIELD_ID", "PVTSSF_lADOEEhvmM4BUnlNzhBuhsY")
TODO_OPTION_ID = os.environ.get("GH_TODO_OPTION_ID", "f75ad846")


def load_token():
    token = os.environ.get("GITHUB_ACCESS_TOKEN")
    if token:
        return token
    print("ERROR: GITHUB_ACCESS_TOKEN not found in environment or ~/git/.env", file=sys.stderr)
    sys.exit(1)


def gh(*args, token=None):
    env = os.environ.copy()
    if token:
        env["GH_TOKEN"] = token
    result = subprocess.run(
        ["gh"] + list(args),
        capture_output=True, text=True, env=env,
    )
    if result.returncode != 0:
        print(f"gh {' '.join(args[:3])}... failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip()


def gh_graphql(query, token):
    env = os.environ.copy()
    env["GH_TOKEN"] = token
    result = subprocess.run(
        ["gh", "api", "graphql", "-f", f"query={query}"],
        capture_output=True, text=True, env=env,
    )
    if result.returncode != 0:
        print(f"GraphQL failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout)


def get_project_id(token):
    data = gh_graphql(f'''
        query {{
            organization(login: "{PROJECT_OWNER}") {{
                projectV2(number: {PROJECT_NUMBER}) {{ id }}
            }}
        }}
    ''', token)
    return data["data"]["organization"]["projectV2"]["id"]


def create_issue(repo, title, body, labels, token):
    cmd = [
        "issue", "create",
        "--repo", repo,
        "--title", title,
        "--body", body,
    ]
    for label in labels:
        cmd.extend(["--label", label])
    output = gh(*cmd, token=token)
    url = output.strip().splitlines()[-1]
    issue_number = int(url.rstrip("/").split("/")[-1])
    return issue_number, url


def add_to_project(project_id, issue_url, token):
    output = gh(
        "project", "item-add", str(PROJECT_NUMBER),
        "--owner", PROJECT_OWNER,
        "--url", issue_url,
        "--format", "json",
        token=token,
    )
    data = json.loads(output)
    return data["id"]


def set_status_todo(project_id, item_id, token):
    mutation = f'''
        mutation {{
            updateProjectV2ItemFieldValue(input: {{
                projectId: "{project_id}"
                itemId: "{item_id}"
                fieldId: "{STATUS_FIELD_ID}"
                value: {{ singleSelectOptionId: "{TODO_OPTION_ID}" }}
            }}) {{ projectV2Item {{ id }} }}
        }}
    '''
    gh_graphql(mutation, token)


def build_issue_body(task, plan_name, repo, created_issues):
    depends_on = task.get("depends_on", [])
    body_parts = [
        f"**Plan:** {plan_name}",
        f"**Repository:** {repo}",
        "",
        task["description"],
    ]
    if depends_on:
        body_parts.append("")
        body_parts.append("---")
        body_parts.append("### Dependencies")
        body_parts.append("This task depends on the following tasks completing first:")
        body_parts.append("")
        for idx in depends_on:
            if idx < len(created_issues):
                dep_number, dep_title = created_issues[idx]
                body_parts.append(f"- [ ] #{dep_number} — {dep_title}")
            else:
                body_parts.append(f"- [ ] Task index {idx} (not yet created)")
    return "\n".join(body_parts)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <plan.json>", file=sys.stderr)
        sys.exit(1)

    plan_path = Path(sys.argv[1])
    if not plan_path.exists():
        print(f"ERROR: {plan_path} not found", file=sys.stderr)
        sys.exit(1)

    plan = json.loads(plan_path.read_text())

    required = ["plan_name", "project", "repository", "tasks"]
    missing = [k for k in required if k not in plan]
    if missing:
        print(f"ERROR: Plan missing required fields: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    if not plan["tasks"]:
        print("ERROR: Plan has no tasks", file=sys.stderr)
        sys.exit(1)

    plan_name = plan["plan_name"]
    repo = plan["repository"]
    tasks = plan["tasks"]

    print(f"Plan: {plan_name}")
    print(f"Repository: {repo}")
    print(f"Tasks: {len(tasks)}")
    print()

    token = load_token()
    project_id = get_project_id(token)

    # created_issues[i] = (issue_number, title) for dependency linking
    created_issues = []

    for i, task in enumerate(tasks):
        title = task["title"]
        labels = task.get("labels", [])

        body = build_issue_body(task, plan_name, repo, created_issues)

        print(f"[{i+1}/{len(tasks)}] Creating: {title} ...", end=" ", flush=True)

        issue_number, issue_url = create_issue(repo, title, body, labels, token)
        print(f"#{issue_number}", end=" ", flush=True)

        item_id = add_to_project(project_id, issue_url, token)
        set_status_todo(project_id, item_id, token)
        print("→ Todo ✓")

        created_issues.append((issue_number, title))

    print()
    print(f"Done. Created {len(created_issues)} issues on {repo}, all set to Todo.")
    print("Issue numbers:", ", ".join(f"#{n}" for n, _ in created_issues))


if __name__ == "__main__":
    main()
