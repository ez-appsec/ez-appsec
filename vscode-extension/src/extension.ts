import * as vscode from "vscode";
import { Scanner } from "./scanner";
import { DiagnosticsManager } from "./diagnostics";

let scanner: Scanner;
let diagnosticsManager: DiagnosticsManager;
let statusBarItem: vscode.StatusBarItem;
let onSaveDisposable: vscode.Disposable | undefined;
let debounceTimer: ReturnType<typeof setTimeout> | undefined;
let lastErrorTime = 0;

const ERROR_THROTTLE_MS = 30000;

export function activate(context: vscode.ExtensionContext): void {
  diagnosticsManager = new DiagnosticsManager();
  scanner = new Scanner();

  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    0
  );
  statusBarItem.command = "ez-appsec.scanWorkspace";
  updateStatusBar(0, false);
  statusBarItem.show();

  const scanCommand = vscode.commands.registerCommand(
    "ez-appsec.scanWorkspace",
    async () => {
      const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
      if (!workspaceFolder) {
        vscode.window.showErrorMessage(
          "ez-appsec: No workspace folder open."
        );
        return;
      }

      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "ez-appsec: Scanning workspace...",
          cancellable: true,
        },
        async (_progress, token) => {
          updateStatusBar(0, true);
          try {
            const findings = await scanner.scan(
              workspaceFolder.uri.fsPath,
              token
            );
            diagnosticsManager.setFindings(findings, workspaceFolder.uri.fsPath);
            updateStatusBar(findings.length, false);
            vscode.window.showInformationMessage(
              `ez-appsec: Scan complete — ${findings.length} finding(s).`
            );
          } catch (err) {
            updateStatusBar(0, false);
            if (err instanceof Error) {
              if (err.message === "Scan cancelled") {
                vscode.window.showInformationMessage(
                  "ez-appsec: Scan cancelled."
                );
              } else {
                vscode.window.showErrorMessage(`ez-appsec: ${err.message}`);
              }
            }
          }
        }
      );
    }
  );

  const clearCommand = vscode.commands.registerCommand(
    "ez-appsec.clearFindings",
    () => {
      diagnosticsManager.clear();
      updateStatusBar(0, false);
      vscode.window.showInformationMessage("ez-appsec: Findings cleared.");
    }
  );

  context.subscriptions.push(
    scanCommand,
    clearCommand,
    diagnosticsManager,
    statusBarItem
  );

  setupScanOnSave(context);

  vscode.workspace.onDidChangeConfiguration((e) => {
    if (e.affectsConfiguration("ez-appsec.scanOnSave")) {
      setupScanOnSave(context);
    }
  });
}

function updateStatusBar(findingCount: number, scanning: boolean): void {
  if (scanning) {
    statusBarItem.text = "$(sync~spin) ez-appsec: scanning…";
    statusBarItem.tooltip = "Security scan in progress";
  } else if (findingCount > 0) {
    statusBarItem.text = `$(shield) ez-appsec: ${findingCount} finding(s)`;
    statusBarItem.tooltip = "Click to re-scan workspace";
  } else {
    statusBarItem.text = "$(shield) ez-appsec";
    statusBarItem.tooltip = "Click to scan workspace";
  }
}

function setupScanOnSave(context: vscode.ExtensionContext): void {
  const config = vscode.workspace.getConfiguration("ez-appsec");
  const scanOnSave = config.get<boolean>("scanOnSave", false);

  if (onSaveDisposable) {
    onSaveDisposable.dispose();
    onSaveDisposable = undefined;
  }

  if (scanOnSave) {
    const debounceMs = vscode.workspace
      .getConfiguration("ez-appsec")
      .get<number>("scanOnSaveDelay", 2000);

    onSaveDisposable = vscode.workspace.onDidSaveTextDocument((document) => {
      if (debounceTimer) {
        clearTimeout(debounceTimer);
      }
      debounceTimer = setTimeout(async () => {
        debounceTimer = undefined;
        const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
        if (!workspaceFolder) {
          return;
        }
        updateStatusBar(0, true);
        try {
          const findings = await scanner.scanFile(
            document.uri.fsPath,
            workspaceFolder.uri.fsPath
          );
          diagnosticsManager.updateFileFindings(
            document.uri.fsPath,
            findings,
            workspaceFolder.uri.fsPath
          );
          updateStatusBar(diagnosticsManager.totalFindings(), false);
        } catch (err) {
          updateStatusBar(diagnosticsManager.totalFindings(), false);
          if (err instanceof Error) {
            const now = Date.now();
            if (now - lastErrorTime >= ERROR_THROTTLE_MS) {
              lastErrorTime = now;
              vscode.window.showErrorMessage(`ez-appsec: ${err.message}`);
            }
          }
        }
      }, debounceMs);
    });
    context.subscriptions.push(onSaveDisposable);
  }
}

export function deactivate(): void {
  if (debounceTimer) {
    clearTimeout(debounceTimer);
  }
  if (onSaveDisposable) {
    onSaveDisposable.dispose();
  }
}
