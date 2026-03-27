ez-appsec slash command dispatcher. Routes to the correct subcommand based on the first word of `$ARGUMENTS`.

## Usage

```
/ez-appsec install [path]   — install ez-appsec into a GitLab project
/ez-appsec scan [path]      — run a security scan
/ez-appsec help             — show available subcommands
```

## Dispatch

Parse `$ARGUMENTS`: the first word is the subcommand, the remainder is passed as the argument to that subcommand.

### `install`

Follow all steps in the `ez-appsec-install` skill using the remainder of `$ARGUMENTS` as the target path.

### `scan`

Follow all steps in the `ez-appsec-scan` skill using the remainder of `$ARGUMENTS` as the target path.

### `help` or no subcommand

Print:
```
Usage: /ez-appsec <subcommand> [path]

Subcommands:
  install [path]   Add ez-appsec scanning to a GitLab project via scan.yml include + MR
  scan [path]      Run a security scan using the ez-appsec Docker image
  help             Show this message
```
