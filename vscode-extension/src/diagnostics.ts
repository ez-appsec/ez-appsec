import * as vscode from "vscode";
import * as path from "path";
import { Finding } from "./scanner";

export class DiagnosticsManager implements vscode.Disposable {
  private collection: vscode.DiagnosticCollection;

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection("ez-appsec");
  }

  setFindings(findings: Finding[], workspacePath: string): void {
    this.collection.clear();

    const grouped = new Map<string, vscode.Diagnostic[]>();

    for (const finding of findings) {
      const filePath = path.isAbsolute(finding.location.file)
        ? finding.location.file
        : path.join(workspacePath, finding.location.file);

      const uri = vscode.Uri.file(filePath).toString();

      if (!grouped.has(uri)) {
        grouped.set(uri, []);
      }

      grouped.get(uri)!.push(this.toDiagnostic(finding));
    }

    for (const [uriStr, diagnostics] of grouped) {
      this.collection.set(vscode.Uri.parse(uriStr), diagnostics);
    }
  }

  clear(): void {
    this.collection.clear();
  }

  dispose(): void {
    this.collection.dispose();
  }

  private toDiagnostic(finding: Finding): vscode.Diagnostic {
    const startLine = Math.max(0, finding.location.start_line - 1);
    const endLine = Math.max(startLine, (finding.location.end_line || finding.location.start_line) - 1);

    const range = new vscode.Range(startLine, 0, endLine, Number.MAX_SAFE_INTEGER);
    const severity = this.mapSeverity(finding.severity);

    const diagnostic = new vscode.Diagnostic(range, finding.message, severity);
    diagnostic.source = "ez-appsec";
    diagnostic.code = finding.name;

    const tooltip = this.buildTooltip(finding);
    diagnostic.message = tooltip;

    return diagnostic;
  }

  private mapSeverity(severity: string): vscode.DiagnosticSeverity {
    switch (severity.toLowerCase()) {
      case "critical":
      case "high":
        return vscode.DiagnosticSeverity.Error;
      case "medium":
        return vscode.DiagnosticSeverity.Warning;
      case "low":
      case "info":
        return vscode.DiagnosticSeverity.Information;
      default:
        return vscode.DiagnosticSeverity.Warning;
    }
  }

  private buildTooltip(finding: Finding): string {
    const parts = [
      `[${finding.severity.toUpperCase()}] ${finding.message}`,
      `Rule: ${finding.name}`,
    ];

    if (finding.solution) {
      parts.push(`Fix: ${finding.solution}`);
    }

    if (finding.ai_remediation) {
      parts.push(`AI Hint: ${finding.ai_remediation}`);
    }

    return parts.join("\n");
  }
}
