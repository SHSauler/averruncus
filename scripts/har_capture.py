#!/usr/bin/env python3
"""har_capture.py — Playwright/Chromium: log in (generic button+inputs flow),
visit HAR_EXTRA_URLS, save full HAR for DalFox. Env-driven, no site source needed."""
import os
from playwright.sync_api import sync_playwright

BASE = os.environ["TARGET_URL"].rstrip("/")
OUT = os.environ.get("HAR_PATH", os.path.join(os.environ.get("OUT_DIR", "."), "capture.har"))
CHROMIUM = os.environ.get("CHROMIUM_BIN", "/usr/bin/chromium")

with sync_playwright() as p:
    b = p.chromium.launch(executable_path=CHROMIUM, args=["--no-sandbox"])
    ctx = b.new_context(record_har_path=OUT, record_har_mode="full")
    pg = ctx.new_page()
    pg.goto(BASE + "/")
    pg.wait_for_timeout(1500)
    if os.environ.get("LOGIN_USER"):
        pg.click(f'button:has-text("{os.environ.get("LOGIN_BUTTON_TEXT", "Log in")}")')
        pg.wait_for_timeout(800)
        ins = pg.query_selector_all("input")
        ins[0].fill(os.environ["LOGIN_USER"])
        ins[1].fill(os.environ.get("LOGIN_PASS", ""))
        pg.click('button[type="submit"]')
        pg.wait_for_timeout(4000)
    for u in os.environ.get("HAR_EXTRA_URLS", "").split():
        try:
            pg.goto(u if u.startswith("http") else BASE + u)
            pg.wait_for_timeout(1500)
        except Exception as e:
            print("visit failed:", u, e)
    ctx.close()
    b.close()
print("HAR:", OUT)
