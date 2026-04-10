ez-appsec slash command dispatcher. Routes to the correct subcommand based on the first word of `$ARGUMENTS`.

## Usage

```
/ez-appsec install [path]                    — install ez-appsec into a GitLab project
/ez-appsec uninstall [path]                 — remove ez-appsec from a GitLab project
/ez-appsec install-app [owner/repo]         — install via GitHub App (provisions workflow + secrets automatically)
/ez-appsec uninstall-app [owner/repo]       — remove ez-appsec from a GitHub repo and dashboard
/ez-appsec update-dashboard [owner/repo]    — update dashboard web assets to the latest ez-appsec release
/ez-appsec scan [path]                      — run a security scan
/ez-appsec help                             — show available subcommands
```

## Dispatch

Parse `$ARGUMENTS`: the first word is the subcommand, the remainder is passed as the argument to that subcommand.

### `install`

Follow all steps in the `ez-appsec-install` skill using the remainder of `$ARGUMENTS` as the target path.

### `uninstall`

Follow all steps in the `ez-appsec-uninstall` skill using the remainder of `$ARGUMENTS` as the target path.

### `install-app`

Follow all steps in the `ez-appsec-install-app` skill using the remainder of `$ARGUMENTS` as the target repo (`owner/repo`).

### `uninstall-app`

Follow all steps in the `ez-appsec-uninstall-app` skill using the remainder of `$ARGUMENTS` as the target repo (`owner/repo`).

### `update-dashboard`

Follow all steps in the `ez-appsec-update-dashboard` skill using the remainder of `$ARGUMENTS` as the optional target dashboard repo (`owner/repo`).

### `scan`

Follow all steps in the `ez-appsec-scan` skill using the remainder of `$ARGUMENTS` as the target path.

### `help` or no subcommand

Print:
```
Usage: /ez-appsec <subcommand> [args]

Subcommands:
  install [path]                    Add ez-appsec scanning to a GitLab project via scan.yml include + MR
  uninstall [path]                  Remove ez-appsec from a GitLab project via MR
  install-app [owner/repo]          Install via GitHub App — provisions workflow, secrets, and triggers scan
  uninstall-app [owner/repo]        Remove ez-appsec from a GitHub repo and prune its dashboard data
  update-dashboard [owner/repo]     Update dashboard web assets to the latest ez-appsec release
  scan [path]                       Run a security scan using the ez-appsec Docker image
  help                              Show this message
```
