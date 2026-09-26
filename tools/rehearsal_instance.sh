#!/usr/bin/env bash
# Run a second, rehearsal-only proxy instance on port 8799 (dry_run) while the
# main instance keeps its own mode. Used for the Phase-4 rehearsal.
set -euo pipefail
REPO="$HOME/workspace/cursor/development/pii-proxy"
ENV_FILE="$HOME/.config/pii-proxy/pii-proxy.env"

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

export PII_PROXY_DRY_RUN=true
export PII_PROXY_PORT=8799
export PII_PROXY_HOST=127.0.0.1
cd "$REPO"
exec "${PII_PROXY_PYTHON:-$HOME/pii-proxy/venv/bin/python3}" -m src.router
