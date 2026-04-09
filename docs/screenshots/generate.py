#!/usr/bin/env python3
"""
Generate dashboard screenshots for ez-appsec README documentation.

Usage:
    python3 docs/screenshots/generate.py

Requirements:
    pip install playwright
    playwright install chromium

The script:
  1. Serves the dashboard locally (dashboard/github/public/) with mock data
  2. Uses a headless Chromium browser to render each UI state
  3. Saves PNGs to docs/screenshots/

Re-run any time the dashboard UI changes to refresh the screenshots.
"""

import http.server
import json
import os
import shutil
import socketserver
import sys
import threading
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_DIR = REPO_ROOT / "github" / "dashboard" / "public"
MOCK_DIR = Path(__file__).parent
OUT_DIR = Path(__file__).parent
MOCK_VULNS = MOCK_DIR / "mock-vulnerabilities.json"
MOCK_INDEX = MOCK_DIR / "mock-index.json"

PORT = 18765
BASE_URL = f"http://localhost:{PORT}"

# ---------------------------------------------------------------------------
# HTTP server (serves DASHBOARD_DIR with mock data injected under data/)
# ---------------------------------------------------------------------------

class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    """Serves the dashboard directory, intercepting /data/ requests to
    return mock data instead of whatever (possibly empty) files are on disk."""

    # Populated before the server starts
    vulns_json: bytes = b"{}"
    index_json: bytes = b"{}"

    def do_GET(self):
        if self.path in ("/data/vulnerabilities.json",
                         "/data/projects/juice-shop-public/vulnerabilities.json"):
            self._serve_bytes(self.vulns_json, "application/json")
        elif self.path == "/data/index.json":
            self._serve_bytes(self.index_json, "application/json")
        else:
            super().do_GET()

    def _serve_bytes(self, data: bytes, content_type: str):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):  # silence request logs
        pass

    def translate_path(self, path):
        # Serve from DASHBOARD_DIR
        rel = path.split("?")[0].lstrip("/")
        candidate = DASHBOARD_DIR / rel
        if candidate.is_dir():
            candidate = candidate / "index.html"
        return str(candidate)


def start_server(vulns_json: bytes, index_json: bytes) -> socketserver.TCPServer:
    DashboardHandler.vulns_json = vulns_json
    DashboardHandler.index_json = index_json
    # Allow port reuse so repeated runs don't hit "address in use"
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("", PORT), DashboardHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# ---------------------------------------------------------------------------
# Screenshot logic
# ---------------------------------------------------------------------------

def take_screenshots(vulns_json: bytes, index_json: bytes):
    from playwright.sync_api import sync_playwright, expect

    server = start_server(vulns_json, index_json)
    time.sleep(0.3)  # let server bind

    VIEWPORT = {"width": 1400, "height": 900}

    try:
        with sync_playwright() as p:
            # --no-sandbox is required in GitHub Actions / Docker environments
            launch_args = ["--no-sandbox", "--disable-setuid-sandbox"] if os.getenv("CI") else []
            browser = p.chromium.launch(args=launch_args)
            ctx = browser.new_context(viewport=VIEWPORT)
            page = ctx.new_page()

            # ------------------------------------------------------------------
            # 1. Overview — stat cards + severity chart
            # ------------------------------------------------------------------
            print("  [1/8] dashboard-overview.png")
            page.goto(f"{BASE_URL}/index.html", wait_until="networkidle")
            # Wait for counts to populate
            page.wait_for_function(
                "document.getElementById('critical-count')?.textContent?.trim() !== '—'"
            )
            page.screenshot(path=str(OUT_DIR / "dashboard-overview.png"),
                            full_page=False)

            # ------------------------------------------------------------------
            # 2. Multi-project sidebar
            # ------------------------------------------------------------------
            print("  [2/8] dashboard-multi-project.png")
            # Sidebar should be visible (index.json has 2 projects)
            sidebar = page.locator("#sidebar")
            sidebar.wait_for(state="visible")
            page.screenshot(path=str(OUT_DIR / "dashboard-multi-project.png"),
                            full_page=False)

            # ------------------------------------------------------------------
            # 3. Vulnerability list
            # ------------------------------------------------------------------
            print("  [3/8] dashboard-vuln-list.png")
            # Wait for at least one row
            page.wait_for_selector(".vuln-row")
            # Scroll the list into view
            page.locator(".vuln-table").scroll_into_view_if_needed()
            page.screenshot(path=str(OUT_DIR / "dashboard-vuln-list.png"),
                            full_page=False)

            # ------------------------------------------------------------------
            # 4. Filters — with severity filter active
            # ------------------------------------------------------------------
            print("  [4/8] dashboard-filters.png")
            page.select_option("#severity-filter", "critical")
            page.wait_for_timeout(400)
            page.locator(".filter-bar").scroll_into_view_if_needed()
            page.screenshot(path=str(OUT_DIR / "dashboard-filters.png"),
                            full_page=False)
            # Reset filters for subsequent screenshots
            page.select_option("#severity-filter", "")
            page.wait_for_timeout(300)

            # ------------------------------------------------------------------
            # 5. Finding detail modal
            # ------------------------------------------------------------------
            print("  [5/8] dashboard-finding-detail.png")
            page.wait_for_selector(".vuln-row")
            first_row = page.locator(".vuln-row").first
            first_row.click()
            modal = page.locator("#vuln-modal")
            modal.wait_for(state="visible")
            page.screenshot(path=str(OUT_DIR / "dashboard-finding-detail.png"),
                            full_page=False)

            # Close modal
            page.locator("#modal-close").click()
            page.wait_for_timeout(300)

            # ------------------------------------------------------------------
            # 6. AI remediation modal
            # ------------------------------------------------------------------
            print("  [6/8] dashboard-ai-remediation.png")
            # Hover over first row to make remediate button appear
            page.locator(".vuln-row").first.hover()
            page.wait_for_timeout(200)
            remediate_btn = page.locator(".btn-remediate").first
            remediate_btn.wait_for(state="visible")
            remediate_btn.click()
            rem_modal = page.locator("#remediation-modal")
            rem_modal.wait_for(state="visible")
            page.screenshot(path=str(OUT_DIR / "dashboard-ai-remediation.png"),
                            full_page=False)

            # Close remediation modal
            close_btn = page.locator("#remediation-modal-close")
            if close_btn.count() > 0:
                close_btn.click()
            else:
                page.keyboard.press("Escape")
            page.wait_for_timeout(300)

            # ------------------------------------------------------------------
            # 7. GitHub Security tab mockup — just the overview with a note
            #    (We can't render the real GitHub UI, so screenshot the SARIF
            #    section of the dashboard at a narrower crop.)
            # ------------------------------------------------------------------
            print("  [7/8] github-security-tab.png")
            # Re-load without index.json (single-project mode) to get a clean view
            # that resembles what GitHub Security tab would show
            page.goto(f"{BASE_URL}/index.html", wait_until="networkidle")
            page.wait_for_function(
                "document.getElementById('critical-count')?.textContent?.trim() !== '—'"
            )
            page.screenshot(path=str(OUT_DIR / "github-security-tab.png"),
                            full_page=False)

            # ------------------------------------------------------------------
            # 8. PR comment — show a representative overview screenshot
            #    (the actual PR comment is rendered by GitHub, not the dashboard)
            # ------------------------------------------------------------------
            print("  [8/8] github-pr-comment.png")
            # Show the stat-cards section clipped to simulate a compact PR badge
            page.set_viewport_size({"width": 800, "height": 300})
            page.goto(f"{BASE_URL}/index.html", wait_until="networkidle")
            page.wait_for_function(
                "document.getElementById('critical-count')?.textContent?.trim() !== '—'"
            )
            stat_cards = page.locator(".stat-cards")
            stat_cards.scroll_into_view_if_needed()
            page.screenshot(path=str(OUT_DIR / "github-pr-comment.png"),
                            clip={"x": 0, "y": 0, "width": 800, "height": 300})

            browser.close()

    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    print(f"Dashboard dir : {DASHBOARD_DIR}")
    print(f"Output dir    : {OUT_DIR}")
    print()

    if not DASHBOARD_DIR.exists():
        print(f"ERROR: dashboard not found at {DASHBOARD_DIR}", file=sys.stderr)
        sys.exit(1)

    if not MOCK_VULNS.exists() or not MOCK_INDEX.exists():
        print("ERROR: mock data files missing", file=sys.stderr)
        sys.exit(1)

    vulns_json = MOCK_VULNS.read_bytes()
    index_json = MOCK_INDEX.read_bytes()

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Generating screenshots…")
    take_screenshots(vulns_json, index_json)

    screenshots = sorted(OUT_DIR.glob("*.png"))
    print(f"\nDone — {len(screenshots)} screenshots saved to {OUT_DIR.relative_to(REPO_ROOT)}/")
    for s in screenshots:
        print(f"  {s.name}")


if __name__ == "__main__":
    main()
