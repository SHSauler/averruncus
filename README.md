# Averruncus

Generic dynamic web-application security testing harness. Drives FOSS scanners
from Podman against a live target — no source code required.

## Tools orchestrated

- **ZAP** (`zaproxy/zap-stable`): baseline + full active scan (unauth), Automation
  Framework authenticated scans (JSON-login + cookie sessions + poll verification).
- **Nuclei** (`projectdiscovery/nuclei`): exposures / misconfiguration / vuln templates.
- **DalFox v3** (built from source): XSS over a Playwright-captured authenticated HAR.
- **Playwright + system Chromium**: HAR capture and stored-XSS/upload rendering tests.

## Quickstart

```sh
cp config.env.example config.env   # edit TARGET_URL (and auth if needed)
source config.env
make setup        # pull scanner images, build venv + dalfox (once)
make new-run      # creates reports/<name>/<run-id>/, prints OUT_DIR
make zap-full     # unauthenticated ZAP full active scan
make zap-auth     # authenticated ZAP scan (needs AUTH_MODE=json)
make nuclei       # nuclei template scan
make har          # capture authenticated HAR via Chromium
make dalfox       # dalfox XSS scan over the HAR
make xss          # generic stored-XSS + upload rendering test
```

All scanners run with `--network host`, so `TARGET_URL=http://127.0.0.1:8080`
(loopback-published Podman targets) works. Reports land in `$OUT_DIR`.

## Unified reporting

```sh
make report                          # OUT_DIR -> findings.json/sarif, SUMMARY.md, dashboard.html
BASELINE=/path/to/prev/findings.json make report   # marks new/persisting, counts fixed
```

`scripts/report.py` normalizes ZAP + Nuclei + DalFox + XSS outputs into one
finding model (tool/check/severity/confidence/url), emits SARIF 2.1.0 for
CI ingestion, a severity rollup (`SUMMARY.md`), and an offline single-file
`dashboard.html` (sortable, severity filter, no CDN). Findings are keyed by
(tool, check, URL-path) so reruns diff cleanly against a baseline.

## Layout

- `config.env.example` — every knob: target, auth, scan bounds, exclusions.
- `scripts/` — one script per scan step + `common.sh` (env/preflight) + triage helpers.
- `templates/zap-auth.yaml.tmpl` — Automation Framework plan template.
- `reports/` — per-target run artifacts (git-ignored except `.gitkeep`).
