#!/bin/bash
# zap_full.sh — unauthenticated ZAP full active scan (traditional + AJAX/client spider).
set -u
. "$(dirname "$0")/common.sh"
podman run --rm --name averruncus-zap --network host \
  -v "$OUT_DIR:/zap/wrk:rw" docker.io/zaproxy/zap-stable \
  zap-full-scan.py -t "$TARGET_URL" -j -m 10 -T 15 -I \
  -r full-unauth.html -w full-unauth.md -x full-unauth.xml -J full-unauth.json
