#!/bin/bash
# dalfox_har.sh — DalFox v3 XSS scan over a captured HAR (authenticated session replay).
# Usage: scripts/dalfox_har.sh [har-file]  (default: $OUT_DIR/capture.har)
# Requires the dalfox binary: set DALFOX_BIN or build it (see README).
set -u
. "$(dirname "$0")/common.sh"
: "${DALFOX_BIN:?set DALFOX_BIN to a dalfox v3 binary (cargo build --release)}"
HAR="${1:-$OUT_DIR/capture.har}"
[ -f "$HAR" ] || { echo "HAR not found: $HAR (run make har)" >&2; exit 1; }
"$DALFOX_BIN" scan -i har "$HAR" -f jsonl -o "$OUT_DIR/dalfox.jsonl" --no-color
