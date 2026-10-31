#!/usr/bin/env python3
"""report.py — unify Averruncus scan outputs into one panoptic view.

Reads (any subset may be missing):
  full-unauth.json auth-user.json  (ZAP traditional JSON)
  nuclei.jsonl                     (Nuclei JSONL)
  dalfox.jsonl                     (DalFox v3 JSONL envelope)
  xss.json                         (xss_test.py verdict file)
Writes:
  findings.json   normalized list [{tool,check,severity,confidence,url,detail}]
  findings.sarif  SARIF 2.1.0
  SUMMARY.md      severity rollup + deduped finding list
  dashboard.html  offline single-file sortable/filterable table
Usage: report.py OUT_DIR [--baseline PREV_FINDINGS_JSON]
"""
import glob
import html
import json
import os
import sys
from collections import Counter

OUT = sys.argv[1]
BASE = None
if "--baseline" in sys.argv:
    BASE = sys.argv[sys.argv.index("--baseline") + 1]

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def norm_sev(s):
    s = str(s or "").lower().split()[0]
    return {"informational": "info", "note": "info"}.get(s, s if s in SEV_ORDER else "info")


def add(store, tool, check, severity, confidence, url, detail=""):
    store.append(
        {
            "tool": tool,
            "check": check,
            "severity": norm_sev(severity),
            "confidence": str(confidence or ""),
            "url": url or "",
            "detail": detail or "",
        }
    )


F = []


def load(p):
    with open(p) as f:
        return json.load(f)


# --- ZAP ---
for p in glob.glob(os.path.join(OUT, "*.json")):
    if os.path.basename(p) not in ("full-unauth.json", "auth-user.json"):
        continue
    try:
        d = load(p)
    except Exception as e:
        print("skip", p, e)
        continue
    tag = "zap-unauth" if "unauth" in p else "zap-auth"
    for site in d.get("site", []):
        for a in site.get("alerts", []):
            inst = a.get("instances", []) or [{}]
            for i in inst:
                add(F, tag, a.get("name", "?"), a.get("riskdesc", "?"),
                    a.get("confidence", ""), i.get("uri", ""), f"plugin {a.get('pluginid','?')}")

# --- Nuclei ---
np_ = os.path.join(OUT, "nuclei.jsonl")
if os.path.exists(np_):
    for line in open(np_):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        add(F, "nuclei", f"{r.get('template-id','?')} {r.get('info',{}).get('name','')}",
            r.get("info", {}).get("severity", "?"), "", r.get("host", r.get("matched-at", "")),
            str(r.get("matcher-name", "")))

# --- DalFox v3 ---
dp = os.path.join(OUT, "dalfox.jsonl")
if os.path.exists(dp):
    for line in open(dp):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        meta = r.get("meta", r)
        for t in meta.get("target_summary", []):
            if t.get("status") not in ("clean", "skipped"):
                add(F, "dalfox", f"target {t.get('status')}", "medium", "",
                    f"{t.get('method','')} {t.get('target','')}", "")
        for f_ in r.get("findings", []):
            add(F, "dalfox", f_.get("type", f_.get("title", "?")), f_.get("severity", "high"),
                f_.get("confidence", ""), f_.get("url", ""), json.dumps(f_)[:300])

# --- XSS test ---
xp = os.path.join(OUT, "xss.json")
if os.path.exists(xp):
    try:
        x = load(xp)
        bad_flags = x.get("payload_flags", [])
        bad_files = [u for u, f in x.get("files", {}).items() if f.get("executed_flags")]
        dom = x.get("dom", {})
        if bad_flags or bad_files or dom.get("event_handlers") or dom.get("javascript_hrefs"):
            add(F, "xss", "stored XSS executed", "high", "high", "",
                json.dumps({"flags": bad_flags, "files": bad_files})[:300])
        else:
            add(F, "xss", "stored XSS + upload suite: clean", "info", "high", "",
                f"{len(x.get('files', {}))} uploads served safe")
    except Exception as e:
        print("skip xss.json", e)

# --- Diff vs baseline ---
prev_keys = set()
if BASE and os.path.exists(BASE):
    for f_ in load(BASE):
        prev_keys.add((f_["tool"], f_["check"], f_.get("url", "").split("?")[0]))
for f_ in F:
    f_["status"] = "new" if (f_["tool"], f_["check"], f_.get("url", "").split("?")[0]) not in prev_keys else "persisting"
if BASE:
    prev_now = {(f_["tool"], f_["check"], f_.get("url", "").split("?")[0]) for f_ in F}
    fixed = [k for k in prev_keys - prev_now]
else:
    fixed = []

json.dump(F, open(os.path.join(OUT, "findings.json"), "w"), indent=1)

# --- SARIF ---
rules, rule_idx = [], {}
sarif_results = []
for f_ in F:
    key = (f_["tool"], f_["check"])
    if key not in rule_idx:
        rule_idx[key] = len(rules)
        rules.append({"id": f"{f_['tool']}/{f_['check']}",
                      "name": f_["check"], "shortDescription": {"text": f_["check"]}})
    level = {"critical": "error", "high": "error", "medium": "warning",
             "low": "note", "info": "note"}[f_["severity"]]
    sarif_results.append({
        "ruleId": f"{f_['tool']}/{f_['check']}", "level": level,
        "message": {"text": f"{f_['check']} [{f_['tool']}] {f_['detail']}"[:1000]},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f_["url"] or "(no url)"}}}],
        "properties": {"confidence": f_["confidence"], "status": f_["status"]}})
sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
         "runs": [{"tool": {"driver": {"name": "Averruncus", "rules": rules}},
                   "results": sarif_results}]}
json.dump(sarif, open(os.path.join(OUT, "findings.sarif"), "w"), indent=1)

# --- SUMMARY.md ---
counts = Counter((f_["tool"], f_["severity"]) for f_ in F)
tools = sorted({f_["tool"] for f_ in F})
lines = ["# Averruncus unified findings", "",
         "| tool | critical | high | medium | low | info |",
         "|---|---|---|---|---|---|"]
for t in tools:
    lines.append("| " + t + " | " + " | ".join(
        str(counts.get((t, s), 0)) for s in ("critical", "high", "medium", "low", "info")) + " |")
lines += ["", f"Total normalized findings: {len(F)}",
          f"New vs baseline: {sum(1 for f in F if f['status']=='new')}" if BASE else "",
          f"Fixed vs baseline: {len(fixed)}" if BASE else "", "",
          "## Deduped list (tool / severity / check / url)", ""]
seen = set()
for f_ in sorted(F, key=lambda f: (SEV_ORDER[f_["severity"]], f_["tool"], f_["check"])):
    key = (f_["tool"], f_["check"], f_.get("url", "").split("?")[0])
    if key in seen:
        continue
    seen.add(key)
    lines.append(f"- [{f_['severity']}] `{f_['tool']}` {f_['check']} — {f_['url'] or '(no url)'}"
                 + (f" ({f_['status']})" if BASE else ""))
open(os.path.join(OUT, "SUMMARY.md"), "w").write("\n".join(l for l in lines if l != "") + "\n")

# --- dashboard.html (offline, no CDN) ---
rows = "\n".join(
    "<tr><td>{tool}</td><td><span class='sev-{sev}'>{sev}</span></td>"
    "<td>{check}</td><td class='url'>{url}</td><td>{conf}</td><td>{status}</td></tr>".format(
        tool=html.escape(f_["tool"]), sev=f_["severity"], check=html.escape(f_["check"]),
        url=html.escape(f_["url"]), conf=html.escape(f_["confidence"]), status=f_["status"])
    for f_ in sorted(F, key=lambda f: (SEV_ORDER[f_["severity"]], f_["tool"])))
cards = "".join(
    f"<div class='card {s}'><b>{sum(1 for f in F if f['severity']==s)}</b>{s}</div>"
    for s in ("critical", "high", "medium", "low", "info"))
dash = f"""<!doctype html><html><head><meta charset=utf-8><title>Averruncus dashboard</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2em auto;padding:0 1em}}
.cards{{display:flex;gap:.6em}}.card{{border:1px solid #ccc;border-radius:6px;padding:.6em 1em;text-align:center}}
.card b{{display:block;font-size:1.6em}}.critical{{background:#fdd}}.high{{background:#fee6d5}}
.medium{{background:#fff3cd}}.low{{background:#e2f0ff}}.info{{background:#eee}}
table{{border-collapse:collapse;width:100%;margin-top:1em}}td,th{{border:1px solid #ddd;padding:.35em .6em;font-size:.9em}}
.url{{word-break:break-all}}input,select{{margin:.4em .4em .4em 0;padding:.3em}}</style></head><body>
<h1>Averruncus findings ({len(F)})</h1><div class=cards>{cards}</div>
<input id=q placeholder="filter…"> <select id=sev><option value="">all severities</option>
<option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select>
<table><thead><tr><th>tool</th><th>severity</th><th>check</th><th>url</th><th>conf</th><th>status</th></tr></thead>
<tbody id=rows>{rows}</tbody></table>
<script>const q=document.getElementById('q'),s=document.getElementById('sev'),r=[...document.querySelectorAll('#rows tr')];
function f(){{r.forEach(t=>{{const okT=t.textContent.toLowerCase().includes(q.value.toLowerCase());const c=t.cells[1].textContent;const okS=!s.value||c===s.value;t.style.display=okT&&okS?'':'none'}})}};
q.oninput=f;s.onchange=f;</script></body></html>"""
open(os.path.join(OUT, "dashboard.html"), "w").write(dash)

print(f"findings={len(F)} sarif={len(sarif_results)} tools={tools}")
print("counts:", dict(counts))
