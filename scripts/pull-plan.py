#!/usr/bin/env python3
"""Pull the next actionable task from a plan on the GitHub project board.

Usage:
    python3 scripts/pull-plan.py <plan-name>
    python3 scripts/pull-plan.py "Widget Refactor"

Scans the project board for Todo items whose body contains "**Plan:** <plan-name>".
Picks the first task whose dependencies are all Done. Marks it In Progress and
writes its details to .plan-context.md for the executing agent.

Exit codes:
    0  Task claimed successfully — details in .plan-context.md
    1  Error (missing args, API failure, etc.)
    2  No actionable tasks — all tasks are either done, in progress, or blocked

Requires:
    - ~/git/.env with GITHUB_ACCESS_TOKEN=ghp_...
    - gh CLI installed
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
IN_PROGRESS_OPTION_ID = os.environ.get("GH_IN_PROGRESS_OPTION_ID", "47fc9ee4")
CONTEXT_FILE = ".plan-context.md"


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


def get_project_items(token):
    output = gh(
        "project", "item-list", str(PROJECT_NUMBER),
        "--owner", PROJECT_OWNER,
        "--format", "json",
        token=token,
    )
    return json.loads(output).get("items", [])


def get_issue_body(repo, issue_number, token):
    output = gh(
        "issue", "view", str(issue_number),
        "--repo", repo,
        "--json", "body,title,url,labels",
        token=token,
    )
    return json.loads(output)


def extract_repo_from_body(body):
    match = re.search(r"\*\*Repository:\*\*\s*(\S+)", body)
    return match.group(1) if match else None


def extract_dependencies(body):
    deps = []
    for match in re.finditer(r"- \[[ x]\] #(\d+)", body):
        deps.append(int(match.group(1)))
    return deps


def are_dependencies_done(dep_numbers, done_numbers):
    return all(n in done_numbers for n in dep_numbers)


def set_status_in_progress(project_id, item_id, token):
    mutation = f'''
        mutation {{
            updateProjectV2ItemFieldValue(input: {{
                projectId: "{project_id}"
                itemId: "{item_id}"
                fieldId: "{STATUS_FIELD_ID}"
                value: {{ singleSelectOptionId: "{IN_PROGRESS_OPTION_ID}" }}
            }}) {{ projectV2Item {{ id }} }}
        }}
    '''
    gh_graphql(mutation, token)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <plan-name>", file=sys.stderr)
        sys.exit(1)

    plan_name = sys.argv[1]
    token = load_token()

    print(f"Scanning project for plan: {plan_name}")

    items = get_project_items(token)

    # Categorize items by status
    done_numbers = set()
    todo_candidates = []

    for item in items:
        content = item.get("content", {})
        issue_number = content.get("number")
        status = item.get("status", "")

        if issue_number is None:
            continue

        if status == "Done":
            done_numbers.add(issue_number)

    # Find Todo items that belong to this plan
    for item in items:
        content = item.get("content", {})
        issue_number = content.get("number")
        issue_title = content.get("title", "")
        status = item.get("status", "")
        repo = content.get("repository", "")

        if issue_number is None or status != "Todo":
            continue

        # Need to fetch the issue body to check if it belongs to this plan
        if not repo:
            repo = f"{PROJECT_OWNER}/ez-appsec"

        try:
            issue_data = get_issue_body(repo, issue_number, token)
        except SystemExit:
            continue

        body = issue_data.get("body", "")
        if f"**Plan:** {plan_name}" not in body:
            continue

        dep_numbers = extract_dependencies(body)
        target_repo = extract_repo_from_body(body) or repo

        todo_candidates.append({
            "item_id": item["id"],
            "issue_number": issue_number,
            "title": issue_title,
            "body": body,
            "url": issue_data.get("url", ""),
            "labels": issue_data.get("labels", []),
            "dep_numbers": dep_numbers,
            "repo": target_repo,
        })

    if not todo_candidates:
        print(f"No Todo tasks found for plan '{plan_name}'.")
        in_progress = sum(1 for item in items if item.get("status") == "In Progress")
        done = len(done_numbers)
        print(f"Board status: {done} done, {in_progress} in progress")
        sys.exit(2)

    # Pick the first task whose dependencies are all done
    actionable = None
    blocked = []
    for candidate in todo_candidates:
        if are_dependencies_done(candidate["dep_numbers"], done_numbers):
            actionable = candidate
            break
        else:
            missing = [n for n in candidate["dep_numbers"] if n not in done_numbers]
            blocked.append((candidate, missing))

    if actionable is None:
        print(f"All {len(todo_candidates)} remaining tasks are blocked on dependencies:")
        for candidate, missing in blocked:
            missing_str = ", ".join(f"#{n}" for n in missing)
            print(f"  #{candidate['issue_number']} {candidate['title']} — waiting on {missing_str}")
        sys.exit(2)

    # Claim it
    project_id = get_project_id(token)
    print(f"Claiming: #{actionable['issue_number']} {actionable['title']}")
    set_status_in_progress(project_id, actionable["item_id"], token)

    # Assign to current user
    try:
        gh_user = gh("api", "user", "--jq", ".login", token=token)
        gh(
            "issue", "edit", str(actionable["issue_number"]),
            "--repo", actionable["repo"],
            "--add-assignee", gh_user,
            token=token,
        )
    except SystemExit:
        pass  # Non-fatal

    # Derive branch name
    branch_slug = re.sub(r'[^a-z0-9]+', '-', actionable["title"].lower()).strip('-')[:60]
    branch_name = f"feat/{branch_slug}"

    # Write context file
    context = f"""# Plan Task Context
# Plan: {plan_name}
# Issue: #{actionable['issue_number']} — {actionable['title']}
# URL: {actionable['url']}
# Repository: {actionable['repo']}
# Branch: {branch_name}
# DO NOT COMMIT this file — it is gitignored.

{actionable['body']}
"""
    Path(CONTEXT_FILE).write_text(context)

    print(f"Status: In Progress")
    print(f"Branch: {branch_name}")
    print(f"Context: {CONTEXT_FILE}")
    print()
    print(f"Task #{actionable['issue_number']}: {actionable['title']}")
    if actionable["dep_numbers"]:
        dep_str = ", ".join(f"#{n}" for n in actionable["dep_numbers"])
        print(f"Dependencies (all done): {dep_str}")


if __name__ == "__main__":
    main()
