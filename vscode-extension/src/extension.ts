import * as vscode from "vscode";
import { Scanner } from "./scanner";
import { DiagnosticsManager } from "./diagnostics";

let scanner: Scanner;
let diagnosticsManager: DiagnosticsManager;
let onSaveDisposable: vscode.Disposable | undefined;
let debounceTimer: ReturnType<typeof setTimeout> | undefined;

export function activate(context: vscode.ExtensionContext): void {
  diagnosticsManager = new DiagnosticsManager();
  scanner = new Scanner();

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
          cancellable: false,
        },
        async () => {
          try {
            const findings = await scanner.scan(workspaceFolder.uri.fsPath);
            diagnosticsManager.setFindings(findings, workspaceFolder.uri.fsPath);
            vscode.window.showInformationMessage(
              `ez-appsec: Scan complete — ${findings.length} finding(s).`
            );
          } catch (err) {
            if (err instanceof Error) {
              vscode.window.showErrorMessage(`ez-appsec: ${err.message}`);
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
      vscode.window.showInformationMessage("ez-appsec: Findings cleared.");
    }
  );

  context.subscriptions.push(scanCommand, clearCommand, diagnosticsManager);

  setupScanOnSave(context);

  vscode.workspace.onDidChangeConfiguration((e) => {
    if (e.affectsConfiguration("ez-appsec.scanOnSave")) {
      setupScanOnSave(context);
    }
  });
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

    onSaveDisposable = vscode.workspace.onDidSaveTextDocument(() => {
      if (debounceTimer) {
        clearTimeout(debounceTimer);
      }
      debounceTimer = setTimeout(() => {
        debounceTimer = undefined;
        vscode.commands.executeCommand("ez-appsec.scanWorkspace");
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
