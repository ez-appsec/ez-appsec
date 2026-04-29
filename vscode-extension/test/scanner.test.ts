import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

vi.mock("vscode", () => ({
  workspace: {
    getConfiguration: vi.fn(() => ({
      get: vi.fn((_key: string, defaultVal: any) => defaultVal),
    })),
  },
}));

import { Scanner, Finding } from "../src/scanner";

describe("Scanner.parseResults", () => {
  let scanner: Scanner;
  let tmpDir: string;

  beforeEach(() => {
    scanner = new Scanner();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ez-appsec-test-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("parses valid vulnerabilities.json", () => {
    const data = {
      version: "15.0.0",
      vulnerabilities: [
        {
          id: "test-001",
          category: "sast",
          name: "SQL Injection",
          message: "Unsanitized input in query",
          description: "SQL injection vulnerability",
          severity: "critical",
          confidence: "high",
          solution: "Use parameterized queries",
          scanner: { id: "semgrep", name: "Semgrep" },
          location: { file: "app/db.py", start_line: 42, end_line: 42 },
        },
      ],
    };

    const filePath = path.join(tmpDir, "vulnerabilities.json");
    fs.writeFileSync(filePath, JSON.stringify(data));

    const results = scanner.parseResults(filePath);
    expect(results).toHaveLength(1);
    expect(results[0].name).toBe("SQL Injection");
    expect(results[0].severity).toBe("critical");
    expect(results[0].location.file).toBe("app/db.py");
    expect(results[0].location.start_line).toBe(42);
  });

  it("returns empty array for missing file", () => {
    const results = scanner.parseResults("/nonexistent/path.json");
    expect(results).toHaveLength(0);
  });

  it("returns empty array for empty vulnerabilities", () => {
    const data = { version: "15.0.0", vulnerabilities: [] };
    const filePath = path.join(tmpDir, "vulnerabilities.json");
    fs.writeFileSync(filePath, JSON.stringify(data));

    const results = scanner.parseResults(filePath);
    expect(results).toHaveLength(0);
  });

  it("filters findings without location data", () => {
    const data = {
      version: "15.0.0",
      vulnerabilities: [
        {
          id: "test-001",
          category: "sast",
          name: "Has Location",
          message: "msg",
          description: "desc",
          severity: "high",
          confidence: "high",
          solution: "fix",
          scanner: { id: "semgrep", name: "Semgrep" },
          location: { file: "app.py", start_line: 10, end_line: 10 },
        },
        {
          id: "test-002",
          category: "dependency",
          name: "No Location",
          message: "msg",
          description: "desc",
          severity: "medium",
          confidence: "high",
          solution: "upgrade",
          scanner: { id: "trivy", name: "Trivy" },
          location: { file: "", start_line: 0, end_line: 0 },
        },
      ],
    };

    const filePath = path.join(tmpDir, "vulnerabilities.json");
    fs.writeFileSync(filePath, JSON.stringify(data));

    const results = scanner.parseResults(filePath);
    expect(results).toHaveLength(1);
    expect(results[0].name).toBe("Has Location");
  });

  it("handles malformed JSON gracefully", () => {
    const filePath = path.join(tmpDir, "vulnerabilities.json");
    fs.writeFileSync(filePath, "not valid json");

    expect(() => scanner.parseResults(filePath)).toThrow();
  });

  it("handles missing vulnerabilities key", () => {
    const data = { version: "15.0.0" };
    const filePath = path.join(tmpDir, "vulnerabilities.json");
    fs.writeFileSync(filePath, JSON.stringify(data));

    const results = scanner.parseResults(filePath);
    expect(results).toHaveLength(0);
  });
});
