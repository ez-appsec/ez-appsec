# VS Code Extension

Inline security vulnerability diagnostics for VS Code, powered by ez-appsec. Findings appear as editor squiggles on the exact lines where issues were detected — no context-switching to a terminal or browser.

---

## Prerequisites

- **Docker** installed and running (the extension runs scans inside the ez-appsec Docker image)
- **VS Code** 1.85.0 or later

---

## Installation

Build and install from source:

```bash
cd vscode-extension
npm install
npm run compile
npx vsce package
code --install-extension ez-appsec-0.1.0.vsix
```

---

## Commands

Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):

| Command | Description |
|---------|-------------|
| `ez-appsec: Scan Workspace` | Run a full security scan of the entire workspace |
| `ez-appsec: Clear Findings` | Remove all diagnostic squiggles |

---

## Settings

Configure in **Settings** (`Ctrl+,` / `Cmd+,`) or `.vscode/settings.json`:

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `ez-appsec.scanOnSave` | boolean | `false` | Automatically scan the saved file when any file is saved |
| `ez-appsec.scanOnSaveDelay` | number | `2000` | Debounce delay (ms) before triggering scan-on-save — prevents rapid repeated scans during burst saves |
| `ez-appsec.dockerImage` | string | `ghcr.io/ez-appsec/ez-appsec:latest` | Docker image to use for scanning |

### Example `.vscode/settings.json`

```json
{
  "ez-appsec.scanOnSave": true,
  "ez-appsec.scanOnSaveDelay": 3000,
  "ez-appsec.dockerImage": "ghcr.io/ez-appsec/ez-appsec:v1.2.0"
}
```

---

## How It Works

### Full workspace scan

1. Run **ez-appsec: Scan Workspace** from the Command Palette.
2. The extension mounts your workspace read-only into the Docker container and runs `ez-appsec scan /src`.
3. Results are written to a temporary `vulnerabilities.json`, parsed, and displayed as inline diagnostics across all files.
4. A notification shows the total finding count when the scan completes.

### Scan on save (single-file)

When `ez-appsec.scanOnSave` is enabled:

1. Saving a file triggers a **single-file scan** — only the saved file is scanned, not the entire workspace.
2. The scan is debounced: rapid saves within `scanOnSaveDelay` milliseconds are coalesced into one scan.
3. Diagnostics for the saved file are updated without clearing findings for other files.

This keeps the editor responsive even on large projects where a full workspace scan might take 30+ seconds.

### Diagnostic display

Findings map to VS Code diagnostic severities:

| Finding severity | VS Code display |
|-----------------|-----------------|
| Critical | Red squiggle (Error) |
| High | Red squiggle (Error) |
| Medium | Yellow squiggle (Warning) |
| Low | Blue squiggle (Information) |
| Info | Blue squiggle (Information) |

Hover over a squiggle to see:

- **Severity** and **message** — what was found
- **Rule name** — the scanner rule that triggered the finding
- **Fix suggestion** — recommended remediation
- **AI hint** — AI-generated remediation guidance (when available)

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│  VS Code                                        │
│                                                 │
│  extension.ts                                   │
│  ├── registers commands (scan, clear)           │
│  ├── sets up scan-on-save with debounce         │
│  └── wires scanner → diagnostics                │
│                                                 │
│  scanner.ts                                     │
│  ├── scan(workspacePath)       → full scan      │
│  ├── scanFile(file, workspace) → single-file    │
│  ├── checkDockerAvailable()                     │
│  └── parseResults(jsonPath)                     │
│                                                 │
│  diagnostics.ts                                 │
│  ├── setFindings()       → replace all          │
│  ├── updateFileFindings() → update one file     │
│  ├── clear()                                    │
│  └── toDiagnostic()      → severity mapping     │
│                                                 │
└──────────────┬──────────────────────────────────┘
               │ docker run --rm -v workspace:/src:ro
               ▼
┌─────────────────────────────────────────────────┐
│  ez-appsec Docker container                     │
│  scan /src (or /src/path/to/file.py)            │
│  → /output/vulnerabilities.json                 │
└─────────────────────────────────────────────────┘
```

### Key modules

| File | Responsibility |
|------|---------------|
| `src/extension.ts` | Activation, command registration, scan-on-save setup with debounce, configuration change listener |
| `src/scanner.ts` | Docker invocation for full-workspace and single-file scans, result parsing, temp directory lifecycle |
| `src/diagnostics.ts` | Manages the `ez-appsec` diagnostic collection — severity mapping, tooltip construction, per-file and bulk updates |

---

## Scan-on-Save Design

The scan-on-save feature is designed to avoid blocking the editor:

1. **Single-file scope** — only the saved file is scanned via `docker run ... scan /src/relative/path`, not the entire `/src` mount. This reduces scan time from tens of seconds to a few seconds.

2. **Debounced** — rapid saves (e.g., auto-save or saving multiple files quickly) are coalesced. Only the last save within the `scanOnSaveDelay` window triggers a scan.

3. **Non-destructive updates** — `updateFileFindings()` sets diagnostics for the saved file only, preserving existing diagnostics for all other files. A full workspace scan still clears and replaces everything.

4. **Path validation** — files outside the workspace root are silently skipped (the relative path check rejects `..` traversals and absolute paths).

---

## Docker Image

The extension defaults to `ghcr.io/ez-appsec/ez-appsec:latest`. Override this to pin a specific version or use a custom image:

```json
{
  "ez-appsec.dockerImage": "ghcr.io/ez-appsec/ez-appsec:v1.2.0"
}
```

The workspace is always mounted **read-only** (`:ro`). Scan output is written to a temporary directory that is cleaned up after each scan.

If Docker is not running, the extension shows:

> "Docker is not available. Please ensure Docker is installed and running."

---

## Development

```bash
cd vscode-extension
npm install
npm run compile    # TypeScript → JavaScript
npm test           # Run unit tests (vitest)
npm run watch      # Watch mode for development
npm run package    # Build .vsix for distribution
```

### Tests

The test suite covers:

| Test file | Coverage |
|-----------|----------|
| `test/extension.test.ts` | Command registration, activation, error handling for missing workspace |
| `test/scanner.test.ts` | Result parsing, missing files, empty results, malformed JSON, filtering findings without locations |
| `test/diagnostics.test.ts` | Severity mapping (critical/high/medium/low), line number conversion, file grouping, AI hint display, `updateFileFindings` single-file updates |

Run tests:

```bash
npm test
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Docker is not available" error | Docker daemon not running | Start Docker Desktop or `sudo systemctl start docker` |
| No squiggles after scan | Scan found 0 findings, or findings lack location data | Check the notification message for finding count; dependency-only findings (no file/line) are filtered out |
| Stale squiggles after editing | Diagnostics are only updated on scan, not on edit | Re-save the file (with scan-on-save enabled) or re-run **Scan Workspace** |
| Scan-on-save feels slow | Large file or slow Docker startup | Increase `scanOnSaveDelay` to batch saves; ensure Docker has adequate resources |
| Squiggles on wrong lines | File was edited after the scan | Re-scan to refresh line numbers |
