# ez-appsec VS Code Extension

Inline security vulnerability diagnostics for VS Code, powered by ez-appsec.

## Requirements

- **Docker** must be installed and running. The extension uses the ez-appsec Docker image to scan your workspace.
- VS Code 1.85.0 or later.

## Installation

Install from a VSIX file:

```bash
cd vscode-extension
npm install
npm run compile
npx vsce package
code --install-extension ez-appsec-0.1.0.vsix
```

## Available Commands

Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) and search for:

| Command | Description |
|---------|-------------|
| `ez-appsec: Scan Workspace` | Run a full security scan of the current workspace |
| `ez-appsec: Clear Findings` | Remove all diagnostic squiggles |

## Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `ez-appsec.scanOnSave` | boolean | `false` | Automatically scan the saved file when a file is saved |
| `ez-appsec.scanOnSaveDelay` | number | `2000` | Debounce delay (ms) before triggering scan after save — prevents rapid repeated scans |
| `ez-appsec.dockerImage` | string | `ghcr.io/ez-appsec/ez-appsec:latest` | Docker image to use for scanning |

## How It Works

1. The extension runs `docker run ... ez-appsec scan` against your workspace (mounted read-only).
2. Scan results are parsed from the standard `vulnerabilities.json` output format.
3. Findings are displayed as inline diagnostics:
   - **Critical/High** → Red squiggles (Error)
   - **Medium** → Yellow squiggles (Warning)
   - **Low/Info** → Blue squiggles (Information)
4. Hover over a squiggle to see severity, rule name, fix suggestion, and AI remediation hint (when available).

### Scan on Save

When `scanOnSave` is enabled, saving a file triggers a **single-file scan** — only the saved file is scanned, not the entire workspace. This keeps the editor responsive on large projects.

Rapid saves are debounced: only the last save within the `scanOnSaveDelay` window triggers a scan. Diagnostics for other files are preserved.

## Docker Not Available

If Docker is not running, the extension shows a clear error message:

> "Docker is not available. Please ensure Docker is installed and running."

Start Docker Desktop (or the Docker daemon) and retry the scan.

## Documentation

See [docs/vscode.md](../docs/vscode.md) for the full feature guide including architecture, scan-on-save design, and troubleshooting.

## Development

```bash
cd vscode-extension
npm install
npm run compile    # TypeScript compilation
npm test           # Run unit tests
npm run watch      # Watch mode for development
```
