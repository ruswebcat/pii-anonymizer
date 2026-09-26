#!/usr/bin/env bash
# Dictionary export job (M-DICT-EXPORT).
#
# Runs without an LLM and therefore without tokens: it is a plain script that
# reads the client list from CRM and atomically replaces the dictionary the
# running proxy hot-reloads. Scheduled weekly (see deploy/README.md).
set -euo pipefail

REPO_DIR="/opt/pii-proxy"
PYTHON="/opt/pii-proxy/venv/bin/python3"
STATE_DIR="/var/lib/pii-proxy"

cd "${REPO_DIR}"
exec "${PYTHON}" src/dict_export.py \
  --out "${STATE_DIR}/pii_dict.json" \
  --key-file "${STATE_DIR}/dict.key" \
  --name-layer "${STATE_DIR}/name_layer.json.gz" \
  --max-pages 700
