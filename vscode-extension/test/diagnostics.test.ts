import { describe, it, expect, vi, beforeEach } from "vitest";

const storedDiagnostics = new Map<string, any[]>();
const mockDiagnosticCollection = {
  set: vi.fn((uri: any, diags: any[]) => {
    const key = typeof uri === "string" ? uri : uri.toString?.() ?? String(uri);
    storedDiagnostics.set(key, diags);
  }),
  clear: vi.fn(() => storedDiagnostics.clear()),
  dispose: vi.fn(),
  forEach: vi.fn((cb: (uri: any, diags: any[]) => void) => {
    for (const [uri, diags] of storedDiagnostics) {
      cb(uri, diags);
    }
  }),
};

vi.mock("vscode", () => ({
  languages: {
    createDiagnosticCollection: vi.fn(() => mockDiagnosticCollection),
  },
  DiagnosticSeverity: {
    Error: 0,
    Warning: 1,
    Information: 2,
    Hint: 3,
  },
  Diagnostic: class MockDiagnostic {
    range: any;
    message: string;
    severity: number;
    source?: string;
    code?: string;
    relatedInformation?: any[];
    constructor(range: any, message: string, severity: number) {
      this.range = range;
      this.message = message;
      this.severity = severity;
    }
  },
  DiagnosticRelatedInformation: class MockRelatedInfo {
    location: any;
    message: string;
    constructor(location: any, message: string) {
      this.location = location;
      this.message = message;
    }
  },
  Location: class MockLocation {
    uri: any;
    range: any;
    constructor(uri: any, range: any) {
      this.uri = uri;
      this.range = range;
    }
  },
  Range: class MockRange {
    start: { line: number; character: number };
    end: { line: number; character: number };
    constructor(
      startLine: number,
      startChar: number,
      endLine: number,
      endChar: number
    ) {
      this.start = { line: startLine, character: startChar };
      this.end = { line: endLine, character: endChar };
    }
  },
  Uri: {
    file: (p: string) => ({ toString: () => `file://${p}`, fsPath: p }),
    parse: (s: string) => ({ toString: () => s, fsPath: s.replace("file://", "") }),
  },
}));

import { DiagnosticsManager } from "../src/diagnostics";
import { Finding } from "../src/scanner";

describe("DiagnosticsManager", () => {
  let manager: DiagnosticsManager;

  beforeEach(() => {
    vi.clearAllMocks();
    storedDiagnostics.clear();
    manager = new DiagnosticsManager();
  });

  it("maps critical severity to Error", () => {
    const findings: Finding[] = [
      {
        id: "1",
        category: "sast",
        name: "SQL Injection",
        message: "Unsanitized input",
        description: "desc",
        severity: "critical",
        confidence: "high",
        solution: "Use parameterized queries",
        scanner: { id: "semgrep", name: "Semgrep" },
        location: { file: "app.py", start_line: 10, end_line: 10 },
      },
    ];

    manager.setFindings(findings, "/workspace");

    expect(mockDiagnosticCollection.set).toHaveBeenCalled();
    const [, diagnostics] = mockDiagnosticCollection.set.mock.calls[0];
    expect(diagnostics[0].severity).toBe(0); // Error
  });

  it("maps high severity to Error", () => {
    const findings: Finding[] = [
      {
        id: "1",
        category: "sast",
        name: "XSS",
        message: "Cross-site scripting",
        description: "desc",
        severity: "high",
        confidence: "high",
        solution: "Escape output",
        scanner: { id: "semgrep", name: "Semgrep" },
        location: { file: "app.js", start_line: 5, end_line: 5 },
      },
    ];

    manager.setFindings(findings, "/workspace");

    const [, diagnostics] = mockDiagnosticCollection.set.mock.calls[0];
    expect(diagnostics[0].severity).toBe(0); // Error
  });

  it("maps medium severity to Warning", () => {
    const findings: Finding[] = [
      {
        id: "1",
        category: "sast",
        name: "Weak Hash",
        message: "MD5 usage",
        description: "desc",
        severity: "medium",
        confidence: "medium",
        solution: "Use SHA-256",
        scanner: { id: "semgrep", name: "Semgrep" },
        location: { file: "crypto.py", start_line: 20, end_line: 20 },
      },
    ];

    manager.setFindings(findings, "/workspace");

    const [, diagnostics] = mockDiagnosticCollection.set.mock.calls[0];
    expect(diagnostics[0].severity).toBe(1); // Warning
  });

  it("maps low severity to Information", () => {
    const findings: Finding[] = [
      {
        id: "1",
        category: "sast",
        name: "Info Disclosure",
        message: "Debug enabled",
        description: "desc",
        severity: "low",
        confidence: "low",
        solution: "Disable debug",
        scanner: { id: "semgrep", name: "Semgrep" },
        location: { file: "config.py", start_line: 3, end_line: 3 },
      },
    ];

    manager.setFindings(findings, "/workspace");

    const [, diagnostics] = mockDiagnosticCollection.set.mock.calls[0];
    expect(diagnostics[0].severity).toBe(2); // Information
  });

  it("converts 1-based line numbers to 0-based range", () => {
    const findings: Finding[] = [
      {
        id: "1",
        category: "sast",
        name: "Bug",
        message: "Issue on line 15",
        description: "desc",
        severity: "high",
        confidence: "high",
        solution: "Fix it",
        scanner: { id: "semgrep", name: "Semgrep" },
        location: { file: "app.py", start_line: 15, end_line: 17 },
      },
    ];

    manager.setFindings(findings, "/workspace");

    const [, diagnostics] = mockDiagnosticCollection.set.mock.calls[0];
    expect(diagnostics[0].range.start.line).toBe(14); // 0-based
    expect(diagnostics[0].range.end.line).toBe(16); // 0-based
  });

  it("groups findings by file", () => {
    const findings: Finding[] = [
      {
        id: "1",
        category: "sast",
        name: "Bug A",
        message: "Issue A",
        description: "desc",
        severity: "high",
        confidence: "high",
        solution: "Fix A",
        scanner: { id: "semgrep", name: "Semgrep" },
        location: { file: "app.py", start_line: 10, end_line: 10 },
      },
      {
        id: "2",
        category: "sast",
        name: "Bug B",
        message: "Issue B",
        description: "desc",
        severity: "medium",
        confidence: "medium",
        solution: "Fix B",
        scanner: { id: "semgrep", name: "Semgrep" },
        location: { file: "app.py", start_line: 20, end_line: 20 },
      },
      {
        id: "3",
        category: "sast",
        name: "Bug C",
        message: "Issue C",
        description: "desc",
        severity: "low",
        confidence: "low",
        solution: "Fix C",
        scanner: { id: "semgrep", name: "Semgrep" },
        location: { file: "other.py", start_line: 5, end_line: 5 },
      },
    ];

    manager.setFindings(findings, "/workspace");

    expect(mockDiagnosticCollection.set).toHaveBeenCalledTimes(2);
  });

  it("includes ai_remediation in relatedInformation when present", () => {
    const findings: Finding[] = [
      {
        id: "1",
        category: "sast",
        name: "SQL Injection",
        message: "Unsanitized input",
        description: "desc",
        severity: "critical",
        confidence: "high",
        solution: "Use parameterized queries",
        scanner: { id: "semgrep", name: "Semgrep" },
        location: { file: "app.py", start_line: 10, end_line: 10 },
        ai_remediation: "Replace string concatenation with query parameters",
      },
    ];

    manager.setFindings(findings, "/workspace");

    const [, diagnostics] = mockDiagnosticCollection.set.mock.calls[0];
    expect(diagnostics[0].message).toBe("[CRITICAL] Unsanitized input");
    expect(diagnostics[0].relatedInformation).toBeDefined();
    expect(diagnostics[0].relatedInformation[0].message).toContain("AI Hint:");
    expect(diagnostics[0].relatedInformation[0].message).toContain(
      "Replace string concatenation with query parameters"
    );
  });

  it("clear() clears the diagnostic collection", () => {
    manager.clear();
    expect(mockDiagnosticCollection.clear).toHaveBeenCalled();
  });

  it("dispose() disposes the diagnostic collection", () => {
    manager.dispose();
    expect(mockDiagnosticCollection.dispose).toHaveBeenCalled();
  });

  it("updateFileFindings sets diagnostics for a single file", () => {
    const findings: Finding[] = [
      {
        id: "1",
        category: "sast",
        name: "SQL Injection",
        message: "Unsanitized input",
        description: "desc",
        severity: "critical",
        confidence: "high",
        solution: "Use parameterized queries",
        scanner: { id: "semgrep", name: "Semgrep" },
        location: { file: "app.py", start_line: 10, end_line: 10 },
      },
    ];

    manager.updateFileFindings("/workspace/app.py", findings, "/workspace");

    expect(mockDiagnosticCollection.set).toHaveBeenCalledTimes(1);
    const [uri, diagnostics] = mockDiagnosticCollection.set.mock.calls[0];
    expect(uri.fsPath).toBe("/workspace/app.py");
    expect(diagnostics).toHaveLength(1);
  });

  it("updateFileFindings filters out findings for other files", () => {
    const findings: Finding[] = [
      {
        id: "1",
        category: "sast",
        name: "Bug A",
        message: "msg",
        description: "desc",
        severity: "high",
        confidence: "high",
        solution: "fix",
        scanner: { id: "semgrep", name: "Semgrep" },
        location: { file: "app.py", start_line: 10, end_line: 10 },
      },
      {
        id: "2",
        category: "sast",
        name: "Bug B",
        message: "msg",
        description: "desc",
        severity: "high",
        confidence: "high",
        solution: "fix",
        scanner: { id: "semgrep", name: "Semgrep" },
        location: { file: "other.py", start_line: 5, end_line: 5 },
      },
    ];

    manager.updateFileFindings("/workspace/app.py", findings, "/workspace");

    const [, diagnostics] = mockDiagnosticCollection.set.mock.calls[0];
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0].code).toBe("Bug A:app.py:10");
  });

  it("updateFileFindings clears diagnostics when no findings match", () => {
    manager.updateFileFindings("/workspace/clean.py", [], "/workspace");

    expect(mockDiagnosticCollection.set).toHaveBeenCalledTimes(1);
    const [uri, diagnostics] = mockDiagnosticCollection.set.mock.calls[0];
    expect(uri.fsPath).toBe("/workspace/clean.py");
    expect(diagnostics).toHaveLength(0);
  });

  it("totalFindings returns sum of all diagnostics across files", () => {
    const findings: Finding[] = [
      {
        id: "1",
        category: "sast",
        name: "Bug A",
        message: "Issue A",
        description: "desc",
        severity: "high",
        confidence: "high",
        solution: "Fix A",
        scanner: { id: "semgrep", name: "Semgrep" },
        location: { file: "app.py", start_line: 10, end_line: 10 },
      },
      {
        id: "2",
        category: "sast",
        name: "Bug B",
        message: "Issue B",
        description: "desc",
        severity: "medium",
        confidence: "medium",
        solution: "Fix B",
        scanner: { id: "semgrep", name: "Semgrep" },
        location: { file: "other.py", start_line: 5, end_line: 5 },
      },
    ];

    manager.setFindings(findings, "/workspace");
    expect(manager.totalFindings()).toBe(2);
  });

  it("totalFindings returns 0 when no diagnostics exist", () => {
    expect(manager.totalFindings()).toBe(0);
  });

  it("diagnostic message is short severity + message format", () => {
    const findings: Finding[] = [
      {
        id: "1",
        category: "sast",
        name: "SQL Injection",
        message: "Unsanitized input",
        description: "desc",
        severity: "critical",
        confidence: "high",
        solution: "Use parameterized queries",
        scanner: { id: "semgrep", name: "Semgrep" },
        location: { file: "app.py", start_line: 10, end_line: 10 },
      },
    ];

    manager.setFindings(findings, "/workspace");

    const [, diagnostics] = mockDiagnosticCollection.set.mock.calls[0];
    expect(diagnostics[0].message).toBe("[CRITICAL] Unsanitized input");
    expect(diagnostics[0].relatedInformation).toBeDefined();
    expect(diagnostics[0].relatedInformation[0].message).toContain("Rule: SQL Injection");
    expect(diagnostics[0].relatedInformation[0].message).toContain("Fix: Use parameterized queries");
  });
});
