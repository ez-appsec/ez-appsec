<!-- ez-appsec-skills: %%VERSION%% -->

ez-appsec slash command dispatcher. Routes to the correct subcommand based on the first word of `$ARGUMENTS`.

## Usage

```
/ez-appsec install [path]                    — install ez-appsec into a GitLab project
/ez-appsec uninstall [path]                 — remove ez-appsec from a GitLab project
/ez-appsec install-app [owner/repo]         — install via GitHub App (provisions workflow + secrets automatically)
/ez-appsec uninstall-app [owner/repo]       — remove ez-appsec from a GitHub repo and dashboard
/ez-appsec install-dashboard [owner/repo]   — create/configure the GitHub dashboard repo (assets + App secrets + Pages)
/ez-appsec update-dashboard [owner/repo]    — provision App secrets + update dashboard web assets to the latest release
/ez-appsec scan [path]                      — scan with Docker and load findings into context
/ez-appsec load [project]                   — load a project's vulnerabilities from the dashboard into context
/ez-appsec remediate [filter]               — prioritized remediation plan + apply fixes (balances severity vs risk)
/ez-appsec test [suite ...]                 — run the command test harness (smoke scan load github gitlab dashboard all)
/ez-appsec update [tag]                     — reinstall skills from latest release (or pinned tag)
/ez-appsec version                          — show the installed skill version
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

### `install-dashboard`

Follow all steps in the `ez-appsec-install-dashboard` command using the remainder of `$ARGUMENTS` as the optional target dashboard repo (`owner/repo`, default `ez-appsec/ez-appsec-dashboard`).

### `update-dashboard`

Follow all steps in the `ez-appsec-update-dashboard` skill using the remainder of `$ARGUMENTS` as the optional target dashboard repo (`owner/repo`).

### `scan`

Follow all steps in the `ez-appsec-scan` skill using the remainder of `$ARGUMENTS` as the target path.

### `remediate`

Follow all steps in the `ez-appsec-remediate` skill using the remainder of `$ARGUMENTS` as the optional filter.

### `load`

Follow all steps in the `ez-appsec-load-vulns` skill using the remainder of `$ARGUMENTS` as the project slug or `owner/repo`.

### `test`

Follow all steps in the `ez-appsec-test` skill using the remainder of `$ARGUMENTS` as the suite list.

### `update`

Follow all steps in the `ez-appsec-update` skill using the remainder of `$ARGUMENTS` as the optional tag.

### `version`

Read the `<!-- ez-appsec-skills: ... -->` comment at the top of this file and print:

```
ez-appsec skills  <version>
```

If the version reads `%%VERSION%%` (placeholder not stamped), print:
```
ez-appsec skills  (development — not stamped by installer)
```

### `help` or no subcommand

Print:
```
Usage: /ez-appsec <subcommand> [args]

Subcommands:
  install [path]                    Add ez-appsec scanning to a GitLab project via scan.yml include + MR
  uninstall [path]                  Remove ez-appsec from a GitLab project via MR
  install-app [owner/repo]          Install via GitHub App — provisions workflow, secrets, and triggers scan
  uninstall-app [owner/repo]        Remove ez-appsec from a GitHub repo and prune its dashboard data
  install-dashboard [owner/repo]    Create/configure GitHub dashboard repo (assets + App secrets + GitHub Pages)
  update-dashboard [owner/repo]     Provision App secrets + update dashboard web assets to latest release
  scan [path]                       Scan with Docker and load findings into context for analysis
  load [project]                    Load a project's vulnerabilities from the dashboard into context
  remediate [filter]                Prioritized fix plan — balances severity vs risk, minimal prompting
  test [suite ...]                  Run the command test harness (smoke scan load github gitlab dashboard all)
  update [tag]                      Reinstall skills from latest release (or pinned tag)
  version                           Show installed skill version
  help                              Show this message
```
