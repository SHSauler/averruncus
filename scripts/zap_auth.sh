#!/bin/bash
# zap_auth.sh — authenticated ZAP Automation Framework scan (JSON login + cookie sessions).
# Requires AUTH_MODE=json in config.env.
set -u
. "$(dirname "$0")/common.sh"
[ "${AUTH_MODE:-none}" = "json" ] || { echo "AUTH_MODE=json required" >&2; exit 1; }
for v in LOGIN_URL AUTH_USER AUTH_PASS VERIFY_URL; do : "${!v:?set $v in config.env}"; done
PLAN="$OUT_DIR/zap-auth.yaml"
# Render the plan with python (handles braces/quotes in bodies and regexes):
python3 - "$ROOT/templates/zap-auth.yaml.tmpl" "$PLAN" <<EOF
import sys
t = open(sys.argv[1]).read()
import os
ex = [f"        - {os.environ['TARGET_URL'].rstrip('/')}{p}.*" for p in os.environ.get('EXCLUDE_PATHS','/logout').split('|')]
t = t.replace('{{TARGET}}', os.environ['TARGET_URL'].rstrip('/'))
t = t.replace('{{LOGIN_URL}}', os.environ['LOGIN_URL'])
t = t.replace('{{LOGIN_BODY}}', os.environ.get('LOGIN_BODY','{"name":"{%username%}","password":"{%password%}"}'))
t = t.replace('{{VERIFY_URL}}', os.environ['VERIFY_URL'])
t = t.replace('{{AUTH_USER}}', os.environ['AUTH_USER'])
t = t.replace('{{AUTH_PASS}}', os.environ['AUTH_PASS'])
t = t.replace('{{LOGGED_IN}}', os.environ.get('LOGGED_IN_REGEX',''))
t = t.replace('{{LOGGED_OUT}}', os.environ.get('LOGGED_OUT_REGEX',''))
t = t.replace('{{EXCLUDES}}', '\n'.join(ex))
open(sys.argv[2],'w').write(t)
EOF
podman run --rm --name averruncus-zap-auth --network host \
  -v "$OUT_DIR:/zap/wrk:rw" docker.io/zaproxy/zap-stable \
  zap.sh -cmd -port "${ZAP_PROXY_PORT:-8090}" -autorun /zap/wrk/zap-auth.yaml
