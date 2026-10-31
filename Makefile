ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
 -include $(ROOT)config.env
export

.PHONY: setup new-run zap-baseline zap-full zap-auth nuclei har dalfox xss venv dalfox-build clean help

help:
	@echo "setup | new-run | zap-baseline | zap-full | zap-auth | nuclei | har | dalfox | xss"

setup: venv
	podman pull docker.io/zaproxy/zap-stable:latest
	podman pull docker.io/projectdiscovery/nuclei:latest
	@echo "Optional: clone nuclei-templates, set NUCLEI_TEMPLATES_DIR; build dalfox (make dalfox-build)."

venv:
	python3 -m venv $(ROOT).venv
	$(ROOT).venv/bin/pip install -q playwright
	@echo "Playwright ready. It uses system Chromium via CHROMIUM_BIN (default /usr/bin/chromium)."

new-run:
	bash $(ROOT)scripts/new_run.sh

zap-baseline:
	bash -c 'set -a; . $(ROOT)config.env; set +a; podman run --rm --network host -v "$$OUT_DIR:/zap/wrk:rw" docker.io/zaproxy/zap-stable zap-baseline.py -t "$$TARGET_URL" -I -r baseline.html -J baseline.json -w baseline.md'

zap-full:
	bash $(ROOT)scripts/zap_full.sh

zap-auth:
	bash $(ROOT)scripts/zap_auth.sh

nuclei:
	bash $(ROOT)scripts/nuclei.sh

har:
	bash -c 'set -a; . $(ROOT)config.env; set +a; PATH="$(ROOT).venv/bin:$$PATH" python3 $(ROOT)scripts/har_capture.py'

dalfox:
	bash $(ROOT)scripts/dalfox_har.sh

xss:
	bash -c 'set -a; . $(ROOT)config.env; set +a; PATH="$(ROOT).venv/bin:$$PATH" python3 $(ROOT)scripts/xss_test.py'

triage:
	python3 $(ROOT)scripts/zap_summary.py "$(OUT_DIR)/full-unauth.json" 2>/dev/null || true
	python3 $(ROOT)scripts/zap_summary.py "$(OUT_DIR)/auth-user.json" 2>/dev/null || true

dalfox-build:
	@if [ -d "$(DALFOX_SRC)" ]; then cargo build --release --manifest-path "$(DALFOX_SRC)/Cargo.toml"; else echo "set DALFOX_SRC=/path/to/dalfox"; exit 1; fi

clean:
	rm -rf $(ROOT).venv
