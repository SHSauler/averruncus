#!/usr/bin/env python3
"""Summarize a ZAP traditional-json(-plus) report: alerts grouped by risk,
with instance counts and example URLs. Usage: zap_summary.py <report.json>"""
import json
import sys
from collections import defaultdict

path = sys.argv[1]
with open(path) as f:
    data = json.load(f)

print(f"Site(s): {[s.get('name') for s in data.get('site', [])]}")
rows = []
for site in data.get("site", []):
    for alert in site.get("alerts", []):
        inst = alert.get("instances", [])
        urls = sorted({i.get("uri", "") for i in inst})
        rows.append(
            {
                "risk": alert.get("riskdesc", "?"),
                "conf": alert.get("confidence", "?"),
                "name": alert.get("name", "?"),
                "plugin": alert.get("pluginid", "?"),
                "count": len(inst),
                "urls": urls[:5],
            }
        )

order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
rows.sort(key=lambda r: (order.get(r["risk"].split()[0], 9), r["name"]))
for r in rows:
    print(f"\n[{r['risk']} | conf:{r['conf']} | plugin:{r['plugin']}] {r['name']} x{r['count']}")
    for u in r["urls"]:
        print(f"    {u}")
    if r["count"] > len(r["urls"]):
        print(f"    ... and {r['count'] - len(r['urls'])} more")
print(f"\nTotal distinct alert types: {len(rows)}")
