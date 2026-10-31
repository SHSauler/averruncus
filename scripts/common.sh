#!/bin/bash
# common.sh — sourced by every scan script. Loads config.env, validates OUT_DIR/target.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
if [ -f "$ROOT/config.env" ]; then set -a; . "$ROOT/config.env"; set +a; fi
: "${TARGET_URL:?set TARGET_URL in config.env (copy config.env.example)}"
: "${OUT_DIR:?run 'make new-run' first (sets OUT_DIR)}"
mkdir -p "$OUT_DIR"
command -v podman >/dev/null || { echo "podman required" >&2; exit 1; }
if ! curl -s -o /dev/null --max-time 10 "$TARGET_URL/"; then
  echo "target unreachable: $TARGET_URL" >&2; exit 1
fi
echo "target OK: $TARGET_URL  out: $OUT_DIR"
