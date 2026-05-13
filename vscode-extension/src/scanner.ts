import { execFile } from "child_process";
import { promisify } from "util";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as vscode from "vscode";

const execFileAsync = promisify(execFile);

export interface Finding {
  id: string;
  category: string;
  name: string;
  message: string;
  description: string;
  severity: string;
  confidence: string;
  solution: string;
  scanner: { id: string; name: string };
  location: {
    file: string;
    start_line: number;
    end_line: number;
  };
  ai_remediation?: string;
}

export interface ScanResults {
  vulnerabilities: Finding[];
}

export class Scanner {
  async scan(workspacePath: string): Promise<Finding[]> {
    await this.checkDockerAvailable();

    const config = vscode.workspace.getConfiguration("ez-appsec");
    const image = config.get<string>(
      "dockerImage",
      "ghcr.io/ez-appsec/ez-appsec:latest"
    );

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ez-appsec-"));
    const outputFile = path.join(tmpDir, "vulnerabilities.json");

    try {
      await execFileAsync("docker", [
        "run",
        "--rm",
        "-v",
        `${workspacePath}:/src:ro`,
        "-v",
        `${tmpDir}:/output`,
        image,
        "scan",
        "/src",
        "--output",
        "/output/vulnerabilities.json",
      ]);

      return this.parseResults(outputFile);
    } finally {
      this.cleanup(tmpDir);
    }
  }

  async scanFile(filePath: string, workspacePath: string): Promise<Finding[]> {
    await this.checkDockerAvailable();

    const config = vscode.workspace.getConfiguration("ez-appsec");
    const image = config.get<string>(
      "dockerImage",
      "ghcr.io/ez-appsec/ez-appsec:latest"
    );

    const relativePath = path.relative(workspacePath, filePath);
    if (relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
      return [];
    }

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ez-appsec-"));
    const outputFile = path.join(tmpDir, "vulnerabilities.json");

    try {
      const containerTarget = `/src/${relativePath.split(path.sep).join("/")}`;
      await execFileAsync("docker", [
        "run",
        "--rm",
        "-v",
        `${workspacePath}:/src:ro`,
        "-v",
        `${tmpDir}:/output`,
        image,
        "scan",
        containerTarget,
        "--output",
        "/output/vulnerabilities.json",
      ]);

      return this.parseResults(outputFile);
    } finally {
      this.cleanup(tmpDir);
    }
  }

  async checkDockerAvailable(): Promise<void> {
    try {
      await execFileAsync("docker", ["info"], { timeout: 10000 });
    } catch {
      throw new Error(
        "Docker is not available. Please ensure Docker is installed and running."
      );
    }
  }

  parseResults(filePath: string): Finding[] {
    if (!fs.existsSync(filePath)) {
      return [];
    }

    const content = fs.readFileSync(filePath, "utf-8");
    const data: ScanResults = JSON.parse(content);

    if (!data.vulnerabilities || !Array.isArray(data.vulnerabilities)) {
      return [];
    }

    return data.vulnerabilities.filter(
      (v) => v.location && v.location.file && v.location.start_line
    );
  }

  private cleanup(tmpDir: string): void {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // best-effort cleanup
    }
  }
}
