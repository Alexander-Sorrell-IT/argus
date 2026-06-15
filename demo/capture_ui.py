"""capture_ui.py — capture REAL Argus Splunk UI for the demo trailer (headless, playwright).

Logs into the local Splunk Web, opens the omni_guard dashboard, waits for the panels to
render against live data, and screenshots them. Output → demo/shots/. Real UI, not a mock-up.

    SPLUNK_USER=admin SPLUNK_PASS=... python3 demo/capture_ui.py
"""
import os, sys, time
from pathlib import Path
from playwright.sync_api import sync_playwright

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
try:
    from dotenv import load_dotenv; load_dotenv(REPO / ".env")
except Exception:
    pass

WEB = os.getenv("SPLUNK_WEB", "http://localhost:8000")
USER = os.getenv("SPLUNK_USER", "admin")
PASS = os.getenv("SPLUNK_PASS", "")
APP = "omni_guard"
OUT = REPO / "demo" / "shots"
OUT.mkdir(parents=True, exist_ok=True)


def main():
    with sync_playwright() as p:
        br = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-gpu"])
        pg = br.new_page(viewport={"width": 1920, "height": 1080})

        # 1. login
        pg.goto(f"{WEB}/en-US/account/login", wait_until="networkidle", timeout=60000)
        pg.fill("input[name='username']", USER)
        pg.fill("input[name='password']", PASS)
        pg.click("input[type='submit'], button[type='submit']")
        pg.wait_for_load_state("networkidle", timeout=60000)
        if "/account/login" in pg.url:
            raise SystemExit("login FAILED — check SPLUNK_USER / SPLUNK_PASS (would otherwise screenshot the login page)")
        print("  logged in:", pg.url)

        # 2. open the dashboard and let the panels run their searches
        pg.goto(f"{WEB}/en-US/app/{APP}/{APP}", wait_until="networkidle", timeout=90000)
        print("  dashboard:", pg.url)
        # Splunk panels load via AJAX after the page settles — give the searches time.
        for s in range(8):
            time.sleep(5)
            done = pg.evaluate("document.querySelectorAll('.dashboard-panel, .panel-body').length")
            print(f"    waited {(s+1)*5}s, panels in DOM: {done}")
        time.sleep(5)

        # 3. capture: full dashboard + the top (KPIs) viewport
        pg.screenshot(path=str(OUT / "dashboard_full.png"), full_page=True)
        pg.screenshot(path=str(OUT / "dashboard_top.png"))  # the shipped trailer asset (KPI row + log)
        br.close()
    for f in OUT.glob("dashboard_*.png"):
        print(f"  wrote {f.relative_to(REPO)} ({f.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
