import { describe, it, expect, vi, beforeEach } from "vitest";

const mockCommands: Record<string, (...args: any[]) => any> = {};
const mockSubscriptions: any[] = [];

vi.mock("vscode", () => ({
  commands: {
    registerCommand: vi.fn((id: string, handler: (...args: any[]) => any) => {
      mockCommands[id] = handler;
      return { dispose: vi.fn() };
    }),
    executeCommand: vi.fn((id: string) => {
      if (mockCommands[id]) return mockCommands[id]();
    }),
  },
  workspace: {
    workspaceFolders: [{ uri: { fsPath: "/test/workspace" } }],
    getConfiguration: vi.fn(() => ({
      get: vi.fn((key: string, defaultVal: any) => defaultVal),
    })),
    onDidSaveTextDocument: vi.fn(() => ({ dispose: vi.fn() })),
    onDidChangeConfiguration: vi.fn(() => ({ dispose: vi.fn() })),
  },
  window: {
    showInformationMessage: vi.fn(),
    showErrorMessage: vi.fn(),
    withProgress: vi.fn(async (_opts: any, task: () => Promise<void>) => task()),
  },
  languages: {
    createDiagnosticCollection: vi.fn(() => ({
      set: vi.fn(),
      clear: vi.fn(),
      dispose: vi.fn(),
    })),
  },
  ProgressLocation: { Notification: 15 },
  DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
  Diagnostic: class {
    range: any;
    message: string;
    severity: number;
    source?: string;
    code?: string;
    constructor(range: any, message: string, severity: number) {
      this.range = range;
      this.message = message;
      this.severity = severity;
    }
  },
  Range: class {
    constructor(
      public startLine: number,
      public startChar: number,
      public endLine: number,
      public endChar: number
    ) {}
  },
  Uri: {
    file: (p: string) => ({ toString: () => `file://${p}`, fsPath: p }),
    parse: (s: string) => ({ toString: () => s, fsPath: s.replace("file://", "") }),
  },
}));

import * as vscode from "vscode";

describe("Extension activation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    Object.keys(mockCommands).forEach((k) => delete mockCommands[k]);
  });

  it("registers scanWorkspace command", async () => {
    const { activate } = await import("../src/extension");
    const context = { subscriptions: mockSubscriptions } as any;
    activate(context);

    expect(vscode.commands.registerCommand).toHaveBeenCalledWith(
      "ez-appsec.scanWorkspace",
      expect.any(Function)
    );
  });

  it("registers clearFindings command", async () => {
    const { activate } = await import("../src/extension");
    const context = { subscriptions: mockSubscriptions } as any;
    activate(context);

    expect(vscode.commands.registerCommand).toHaveBeenCalledWith(
      "ez-appsec.clearFindings",
      expect.any(Function)
    );
  });

  it("shows error when no workspace folder is open", async () => {
    const vscodeMock = await import("vscode");
    (vscodeMock.workspace as any).workspaceFolders = undefined;

    const { activate } = await import("../src/extension");
    const context = { subscriptions: mockSubscriptions } as any;
    activate(context);

    await mockCommands["ez-appsec.scanWorkspace"]();

    expect(vscode.window.showErrorMessage).toHaveBeenCalledWith(
      "ez-appsec: No workspace folder open."
    );

    // Restore
    (vscodeMock.workspace as any).workspaceFolders = [
      { uri: { fsPath: "/test/workspace" } },
    ];
  });
});
