#!/bin/bash
# nuclei.sh — Nuclei exposures/misconfiguration/vuln templates against TARGET_URL.
# Uses bundled templates in the image; override with NUCLEI_TEMPLATES_DIR (local clone).
set -u
. "$(dirname "$0")/common.sh"
ARGS=(-target "$TARGET_URL" -severity "${NUCLEI_SEVERITY:-medium,high,critical,unknown}"
  -exclude-tags intrusive,dos,fuzz -rate-limit "${NUCLEI_RATE_LIMIT:-50}"
  -bulk-size 10 -jsonl -o /out/nuclei.jsonl)
if [ -n "${NUCLEI_TEMPLATES_DIR:-}" ]; then
  TARGS=()
  IFS=',' read -ra G <<< "${NUCLEI_TEMPLATES:-http/exposures/}"
  for g in "${G[@]}"; do TARGS+=(-t "/templates/$g"); done
  podman run --rm --name averruncus-nuclei --network host \
    -v "$NUCLEI_TEMPLATES_DIR:/templates:ro" -v "$OUT_DIR:/out:rw" \
    docker.io/projectdiscovery/nuclei:latest "${TARGS[@]}" "${ARGS[@]}"
else
  podman run --rm --name averruncus-nuclei --network host \
    -v "$OUT_DIR:/out:rw" docker.io/projectdiscovery/nuclei:latest \
    -t http/exposures/ -t http/misconfiguration/ -t http/vulnerabilities/other/ "${ARGS[@]}"
fi
