# gsd-to-github

Scripts for managing task plans on GitHub Projects V2 boards. Supports a full push-pull-complete cycle: create issues from a plan file, claim the next unblocked task, and mark it done — all with dependency-aware ordering.

Also includes infrastructure scripts for provisioning security scan workflows, minting GitHub App tokens, and managing LXC containers.

## Plan Workflow

```
plan.json ──► push-plans.py ──► GitHub Issues + Project Board (all "Todo")
                                        │
                                        ▼
                              pull-plan.py ──► claims next unblocked task
                                   │           sets "In Progress"
                                   │           writes .plan-context.md
                                   ▼
                           [agent implements]
                                   │
                                   ▼
                           complete-plan.py ──► pushes branch
                                                sets "Done"
                                                cleans up context
                                   │
                                   ▼
                           pull-plan.py ──► next task (deps now satisfied)
```

### push-plans.py

Creates GitHub issues from a plan JSON file, adds them to the project board, and sets all to "Todo".

```bash
python3 push-plans.py plans/data-arch-v2.json
```

### pull-plan.py

Scans the project board for the next actionable task in a plan (all dependencies Done), marks it "In Progress", assigns it to you, and writes `.plan-context.md`.

```bash
python3 pull-plan.py "Widget Refactor"
```

Exit codes: `0` = task claimed, `1` = error, `2` = no actionable tasks (all done or blocked).

### complete-plan.py

Reads `.plan-context.md`, pushes the feature branch, marks the board item "Done", and cleans up.

```bash
python3 complete-plan.py
python3 complete-plan.py --repo ez-appsec/ez-appsec
```

### claim-plan.sh

User-friendly wrapper for claiming a specific issue. Validates prerequisites (gh CLI, token scopes, git identity, Python 3.10+, Docker), fetches the issue, creates a branch, and prints a copy-paste prompt for your AI assistant.

```bash
bash claim-plan.sh 21
```

### plan-template.json

JSON Schema for plan files. See the `_example` field for a complete sample.

## Infrastructure Scripts

### provision.py

Idempotent provisioner — pushes the ez-appsec scan workflow and sets secrets/variables in target repos. Uses Libsodium encryption (PyNaCl) for secrets.

```bash
python3 provision.py \
  --token <installation_token> \
  --repos owner/repo1,owner/repo2 \
  --app-id 123456 \
  --private-key /path/to/key.pem
```

### mint-token.py

Generates a short-lived GitHub App installation token (~1 hour TTL).

```bash
python3 mint-token.py <app_id> <private_key_pem_or_path> <installation_id>
```

### update-index.py / aggregate-index.py

CI helpers for maintaining the vulnerability dashboard index (`public/data/index.json`). `update-index.py` upserts a single project from CI scan results; `aggregate-index.py` rebuilds the full index from all project data on disk.

### resize-lxc-disk.sh

Proxmox LXC container disk resizer. Detects storage backend (LVM/ZFS/directory) and resizes containers 102-105 from 20G to 100G.

```bash
./resize-lxc-disk.sh [--dry-run]
```

## Configuration

All plan scripts read configuration from environment variables, with fallback defaults for the `ez-appsec` org. Set these in `~/git/.env` or export them directly:

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_ACCESS_TOKEN` | *(required)* | GitHub PAT with `repo`, `project`, `read:org` scopes |
| `GH_PROJECT_OWNER` | `ez-appsec` | GitHub org that owns the project board |
| `GH_PROJECT_NUMBER` | `2` | Project board number |
| `GH_STATUS_FIELD_ID` | `PVTSSF_lADO...` | ProjectV2 Status field ID |
| `GH_TODO_OPTION_ID` | `f75ad846` | Status option ID for "Todo" |
| `GH_IN_PROGRESS_OPTION_ID` | `47fc9ee4` | Status option ID for "In Progress" |
| `GH_DONE_OPTION_ID` | `98236657` | Status option ID for "Done" |
| `GH_REPO` | `ez-appsec/ez-appsec` | `owner/repo` slug for `gh issue` commands (used by `claim-plan.sh`) |

To discover field IDs for a different org/project, query the ProjectV2 via GraphQL:

```bash
gh api graphql -f query='
  query {
    organization(login: "YOUR_ORG") {
      projectV2(number: YOUR_NUMBER) {
        id
        field(name: "Status") {
          ... on ProjectV2SingleSelectField {
            id
            options { id name }
          }
        }
      }
    }
  }
'
```

## Requirements

- Python 3.10+
- [gh CLI](https://cli.github.com) authenticated with `repo`, `project`, `read:org` scopes
- `~/git/.env` with `GITHUB_ACCESS_TOKEN`
- PyNaCl (auto-installed by `provision.py`)
- PyJWT[crypto] (auto-installed by `mint-token.py`)
