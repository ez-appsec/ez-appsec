#!/usr/bin/env python3
"""Mark the current plan task as Done and push its branch.

Usage:
    python3 scripts/complete-plan.py
    python3 scripts/complete-plan.py --repo ez-appsec/ez-appsec

Reads .plan-context.md (written by pull-plan.py) to identify the current task.
Creates a branch named after the task, pushes it to the target repository,
and sets the project board item to Done.

Requires:
    - .plan-context.md in the current directory (from pull-plan.py)
    - ~/git/.env with GITHUB_ACCESS_TOKEN=ghp_...
    - gh CLI installed
    - git configured with user.name and user.email
"""
import json
import os
import re
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
DONE_OPTION_ID = os.environ.get("GH_DONE_OPTION_ID", "98236657")
CONTEXT_FILE = ".plan-context.md"


def load_token():
    token = os.environ.get("GITHUB_ACCESS_TOKEN")
    if token:
        return token
    print("ERROR: GITHUB_ACCESS_TOKEN not found in environment or ~/git/.env", file=sys.stderr)
    sys.exit(1)


def run(cmd, **kwargs):
    result = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    return result


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


def parse_context():
    path = Path(CONTEXT_FILE)
    if not path.exists():
        print(f"ERROR: {CONTEXT_FILE} not found. Run pull-plan.py first.", file=sys.stderr)
        sys.exit(1)

    text = path.read_text()
    context = {}

    match = re.search(r"# Issue: #(\d+)", text)
    if match:
        context["issue_number"] = int(match.group(1))

    match = re.search(r"# Repository: (\S+)", text)
    if match:
        context["repo"] = match.group(1)

    match = re.search(r"# Branch: (\S+)", text)
    if match:
        context["branch"] = match.group(1)

    match = re.search(r"# Plan: (.+)", text)
    if match:
        context["plan_name"] = match.group(1).strip()

    match = re.search(r"# Issue: #\d+ — (.+)", text)
    if match:
        context["title"] = match.group(1).strip()

    return context


def find_project_item_id(issue_number, token):
    output = gh(
        "project", "item-list", str(PROJECT_NUMBER),
        "--owner", PROJECT_OWNER,
        "--format", "json",
        token=token,
    )
    items = json.loads(output).get("items", [])
    for item in items:
        content = item.get("content", {})
        if content.get("number") == issue_number:
            return item["id"]
    return None


def set_status_done(project_id, item_id, token):
    mutation = f'''
        mutation {{
            updateProjectV2ItemFieldValue(input: {{
                projectId: "{project_id}"
                itemId: "{item_id}"
                fieldId: "{STATUS_FIELD_ID}"
                value: {{ singleSelectOptionId: "{DONE_OPTION_ID}" }}
            }}) {{ projectV2Item {{ id }} }}
        }}
    '''
    gh_graphql(mutation, token)


def main():
    repo_override = None
    if "--repo" in sys.argv:
        idx = sys.argv.index("--repo")
        if idx + 1 < len(sys.argv):
            repo_override = sys.argv[idx + 1]

    context = parse_context()
    issue_number = context.get("issue_number")
    branch = context.get("branch")
    repo = repo_override or context.get("repo", f"{PROJECT_OWNER}/ez-appsec")
    title = context.get("title", f"task-{issue_number}")

    if not issue_number:
        print("ERROR: Could not parse issue number from .plan-context.md", file=sys.stderr)
        sys.exit(1)

    if not branch:
        print("ERROR: Could not parse branch name from .plan-context.md", file=sys.stderr)
        sys.exit(1)

    print(f"Task: #{issue_number} — {title}")
    print(f"Branch: {branch}")
    print(f"Repository: {repo}")

    token = load_token()

    # Ensure we're on the right branch (or create it)
    current_branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    if current_branch.stdout.strip() != branch:
        check = run(["git", "show-ref", "--verify", f"refs/heads/{branch}"])
        if check.returncode == 0:
            print(f"Switching to existing branch: {branch}")
            result = run(["git", "checkout", branch])
            if result.returncode != 0:
                print(f"ERROR: git checkout failed:\n{result.stderr}", file=sys.stderr)
                sys.exit(1)
        else:
            print(f"Creating branch: {branch}")
            result = run(["git", "checkout", "-b", branch])
            if result.returncode != 0:
                print(f"ERROR: git checkout -b failed:\n{result.stderr}", file=sys.stderr)
                sys.exit(1)

    # Push the branch
    print(f"Pushing {branch} to origin...")
    env = os.environ.copy()
    env["GH_TOKEN"] = token
    result = run(["git", "push", "-u", "origin", branch], env=env)
    if result.returncode != 0:
        print(f"WARNING: git push failed:\n{result.stderr}", file=sys.stderr)
        print("Continuing to mark project item as Done...")
    else:
        print("Push successful.")

    # Mark project item as Done
    project_id = get_project_id(token)
    item_id = find_project_item_id(issue_number, token)

    if item_id:
        set_status_done(project_id, item_id, token)
        print(f"Project board: #{issue_number} → Done")
    else:
        print(f"WARNING: Issue #{issue_number} not found on project board", file=sys.stderr)

    # Clean up context file
    Path(CONTEXT_FILE).unlink(missing_ok=True)
    print(f"Cleaned up {CONTEXT_FILE}")
    print()
    print("Task complete.")


if __name__ == "__main__":
    main()
