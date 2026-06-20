"""Regression tests for dashboard finding normalization."""

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which("node") is None, reason="node is required for dashboard JS tests")
def test_grype_image_finding_normalizes_visible_dashboard_fields():
    """Image/package findings should not render blank or object-shaped fields."""
    app_js = Path("github/dashboard/public/app-github.js").read_text()
    finding = {
        "id": "CVE-2024-0001",
        "name": "Vulnerable package: openssl",
        "message": "openssl 3.0.0 has a known vulnerability",
        "severity": "HIGH",
        "scanner": {"id": "grype", "name": "Grype"},
        "location": {
            "file": {"file_name": "docker.io/library/alpine:3.18"},
            "dependency": {
                "package": {"name": "openssl"},
                "version": "3.0.0",
            },
        },
    }
    dashboard_source = json.dumps(app_js + "\n" + "globalThis.GitHubDashboard = GitHubDashboard;")
    finding_json = json.dumps(finding)
    script = textwrap.dedent(
        """
        const vm = require('vm');
        const source = __DASHBOARD_SOURCE__;
        const context = {
          console,
          document: {
            addEventListener: () => {},
            createElement: () => ({
              set textContent(value) {
                this.innerHTML = String(value)
                  .replace(/&/g, '&amp;')
                  .replace(/</g, '&lt;')
                  .replace(/>/g, '&gt;')
                  .replace(/"/g, '&quot;');
              },
              innerHTML: '',
            }),
          },
          window: { location: { href: 'http://localhost/' } },
          URL,
          URLSearchParams,
          Blob: function() {},
        };
        vm.createContext(context);
        vm.runInContext(source, context);
        const dashboard = Object.create(context.GitHubDashboard.prototype);
        dashboard.ownershipCache = {};
        const normalized = dashboard.normalizeVulnerability(__FINDING_JSON__);
        const card = dashboard.createVulnerabilityCard(normalized);
        if (normalized.file !== 'docker.io/library/alpine:3.18') throw new Error(`bad file: ${normalized.file}`);
        if (normalized.scanner !== 'Grype') throw new Error(`bad scanner: ${normalized.scanner}`);
        if (!card.includes('docker.io/library/alpine:3.18')) throw new Error('card missing image location');
        if (!card.includes('Grype')) throw new Error('card missing scanner');
        if (card.includes('[object Object]')) throw new Error('card rendered object placeholder');
        """
    ).replace("__DASHBOARD_SOURCE__", dashboard_source).replace("__FINDING_JSON__", finding_json)

    result = subprocess.run(["node", "-e", script], text=True, capture_output=True)

    assert result.returncode == 0, result.stderr
