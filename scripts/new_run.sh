#!/bin/bash
# new_run.sh — create reports/<RUN_NAME>/<run-id>/ and remember it.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
if [ -f "$ROOT/config.env" ]; then set -a; . "$ROOT/config.env"; set +a; fi
: "${RUN_NAME:=target}"
RID="$(date +%Y%m%d-%H%M%S)"
OUT="$ROOT/reports/$RUN_NAME/$RID"
mkdir -p "$OUT"
chmod 777 "$OUT"  # rootless podman maps container UIDs to subuids
if [ -f "$ROOT/config.env" ]; then
  grep -q '^OUT_DIR=' "$ROOT/config.env" \
    && sed -i "s|^OUT_DIR=.*|OUT_DIR=$OUT|" "$ROOT/config.env" \
    || echo "OUT_DIR=$OUT" >> "$ROOT/config.env"
else
  cp "$ROOT/config.env.example" "$ROOT/config.env"
  sed -i "s|^OUT_DIR=.*|OUT_DIR=$OUT|" "$ROOT/config.env"
fi
echo "OUT_DIR=$OUT"
