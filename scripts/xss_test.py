#!/usr/bin/env python3
"""xss_test.py — generic stored-XSS + upload-serving check (starting point).
Attacker context posts PAYLOADS to XSS_COMPOSER_SELECTOR and uploads payload
files; victim context renders them in real Chromium. Any executed payload sets a
window.__ax* flag. Site-specific selectors/URLs come from config.env.
Exit 0 = clean, 1 = executed payload found."""
import json
import os
import sys
from playwright.sync_api import sync_playwright

BASE = os.environ["TARGET_URL"].rstrip("/")
OUT = os.environ.get("OUT_DIR", ".")
CHROMIUM = os.environ.get("CHROMIUM_BIN", "/usr/bin/chromium")
COMPOSER = os.environ.get("XSS_COMPOSER_SELECTOR", "textarea")
FILE_INPUT = os.environ.get("XSS_FILE_INPUT", 'input[type="file"]')
FILE_SUBSTR = os.environ.get("XSS_FILE_LINK_SUBSTR", "/files/")
A_USER, A_PASS = os.environ.get("LOGIN_USER", ""), os.environ.get("LOGIN_PASS", "")
V_USER, V_PASS = os.environ.get("XSS_VICTIM_USER", A_USER), os.environ.get("XSS_VICTIM_PASS", A_PASS)

PAYLOADS = [
    '<img src=x onerror="window.__ax1=1">',
    '<svg onload="window.__ax2=2">',
    '[evil](javascript:window.__ax3=3)',
    '<a href="javascript:window.__ax4=4">clickme</a>',
    '<details open ontoggle="window.__ax5=6">x</details>',
    '<iframe src="javascript:window.__ax6=6"></iframe>',
]
SVG = '<svg xmlns="http://www.w3.org/2000/svg" onload="window.__axsvg=1"><rect width="10" height="10"/></svg>'
HTML = '<!doctype html><script>window.__axhtml=1</script><img src=x onerror="window.__axhtml2=2">'


def login(pg, name, pw):
    pg.goto(BASE + "/")
    pg.wait_for_timeout(1500)
    pg.click(f'button:has-text("{os.environ.get("LOGIN_BUTTON_TEXT", "Log in")}")')
    pg.wait_for_timeout(800)
    ins = pg.query_selector_all("input")
    ins[0].fill(name)
    ins[1].fill(pw)
    pg.click('button[type="submit"]')
    pg.wait_for_selector(COMPOSER, timeout=15000)


results = {"payload_flags": [], "dom": {}, "files": {}}
with sync_playwright() as p:
    b = p.chromium.launch(executable_path=CHROMIUM, args=["--no-sandbox"])
    a = b.new_page()
    if A_USER:
        login(a, A_USER, A_PASS)
    for i, pl in enumerate(PAYLOADS):
        box = a.query_selector(COMPOSER)
        box.fill(f"ax{i} {pl}")
        box.press("Enter")
        a.wait_for_timeout(700)
    if a.query_selector(FILE_INPUT):
        open("/tmp/axevil.svg", "w").write(SVG)
        open("/tmp/axevil.html", "w").write(HTML)
        for f in ("/tmp/axevil.svg", "/tmp/axevil.html"):
            a.set_input_files(FILE_INPUT, f)
            a.wait_for_timeout(2500)
            box = a.query_selector(COMPOSER)
            if box:
                box.fill("uploaded")
                box.press("Enter")
                a.wait_for_timeout(700)
    links = a.eval_on_selector_all(
        f'a[href*="{FILE_SUBSTR}"]', "els => els.map(e => e.href)"
    )
    v = b.new_page()
    if V_USER:
        login(v, V_USER, V_PASS)
    else:
        v.goto(BASE + "/")
    v.wait_for_timeout(6000)
    results["payload_flags"] = v.evaluate(
        "Object.keys(window).filter(k => k.startsWith('__ax'))"
    )
    results["dom"]["script_tags"] = v.evaluate("document.querySelectorAll('script').length")
    results["dom"]["event_handlers"] = v.evaluate(
        "document.querySelectorAll('[onerror],[onload],[ontoggle]').length"
    )
    results["dom"]["javascript_hrefs"] = v.evaluate(
        "Array.from(document.querySelectorAll('a[href]')).filter(a=>a.href.startsWith('javascript:')).length"
    )
    for url in sorted(set(links)):
        resp = v.request.get(url)
        hdrs = resp.headers
        entry = {
            "status": resp.status,
            "content_type": hdrs.get("content-type"),
            "content_disposition": hdrs.get("content-disposition"),
            "x_content_type_options": hdrs.get("x-content-type-options"),
            "navigated": False,
            "executed_flags": [],
        }
        if "attachment" not in (hdrs.get("content-disposition") or ""):
            v.goto(url)
            entry["navigated"] = True
            v.wait_for_timeout(1500)
            entry["executed_flags"] = v.evaluate(
                "['__axsvg','__axhtml','__axhtml2'].filter(k => window[k] !== undefined)"
            )
        results["files"][url] = entry
    b.close()

open(os.path.join(OUT, "xss.json"), "w").write(json.dumps(results, indent=2))
fails = (
    results["payload_flags"]
    or results["dom"]["event_handlers"]
    or results["dom"]["javascript_hrefs"]
    or [u for u, f in results["files"].items() if f.get("executed_flags")]
)
print(json.dumps(results, indent=2)[:2000])
print("VERDICT:", "VULNERABLE — " + str(fails) if fails else "CLEAN")
sys.exit(1 if fails else 0)
