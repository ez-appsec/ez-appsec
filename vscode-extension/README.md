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

| Setting | Default | Description |
|---------|---------|-------------|
| `ez-appsec.scanOnSave` | `false` | Automatically scan when any file is saved |
| `ez-appsec.dockerImage` | `ghcr.io/ez-appsec/ez-appsec:latest` | Docker image to use for scanning |

## How It Works

1. The extension runs `docker run ... ez-appsec scan` against your workspace (mounted read-only).
2. Scan results are parsed from the standard `vulnerabilities.json` output format.
3. Findings are displayed as inline diagnostics:
   - **Critical/High** → Red squiggles (Error)
   - **Medium** → Yellow squiggles (Warning)
   - **Low/Info** → Blue squiggles (Information)
4. Hover over a squiggle to see severity, rule name, fix suggestion, and AI remediation hint (when available).

## Docker Not Available

If Docker is not running, the extension shows a clear error message:

> "Docker is not available. Please ensure Docker is installed and running."

Start Docker Desktop (or the Docker daemon) and retry the scan.

## Development

```bash
cd vscode-extension
npm install
npm run compile    # TypeScript compilation
npm test           # Run unit tests
npm run watch      # Watch mode for development
```
