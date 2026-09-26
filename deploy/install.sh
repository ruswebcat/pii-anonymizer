#!/usr/bin/env bash
# Deployment installer for the PII anonymization proxy.
#
# Two modes:
#   sudo bash deploy/install.sh [system|user] [--start]
#
#   system - classic unit in /etc/systemd/system, state in /var/lib (needs root)
#   user   - unit in ~/.config/systemd/user, state in ~/.local/state (no root);
#            user mode needs no root and is the default
#
# Idempotent: re-running is safe. The service starts only with --start, because
# switching traffic to the proxy is a separate, owner-approved step.
set -euo pipefail

MODE="${1:-user}"
if [[ "${MODE}" != "user" && "${MODE}" != "system" ]]; then
  if [[ "${MODE}" == "--start" ]]; then
    MODE="user"
  else
    echo "usage: $0 [user|system] [--start]" >&2
    exit 64
  fi
fi
START=0
for arg in "$@"; do
  [[ "${arg}" == "--start" ]] && START=1
done

REPO_DIR="/opt/pii-proxy"
PYTHON="/opt/pii-proxy/venv/bin/python3"
HOME_DIR="/opt/pii-proxy"

if [[ "${MODE}" == "system" ]]; then
  STATE_DIR="/var/lib/pii-proxy"
  LOG_DIR="/var/log/pii-proxy"
  CONF_DIR="/etc/pii-proxy"
  UNIT_SRC="${REPO_DIR}/deploy/pii-proxy.service"
  UNIT_DST="/etc/systemd/system/pii-proxy.service"
  SUDO="sudo"
  SYSTEMCTL="sudo systemctl"
else
  STATE_DIR="${HOME_DIR}/.local/state/pii-proxy"
  LOG_DIR="${HOME_DIR}/.local/state/pii-proxy/log"
  CONF_DIR="${HOME_DIR}/.config/pii-proxy"
  UNIT_SRC="${REPO_DIR}/deploy/pii-proxy.user.service"
  UNIT_DST="${HOME_DIR}/.config/systemd/user/pii-proxy.service"
  SUDO=""
  SYSTEMCTL="systemctl --user"
fi

echo "== 1/5 directories (${MODE} mode)"
mkdir -p "${STATE_DIR}" "${LOG_DIR}" "${CONF_DIR}"
chmod 0700 "${STATE_DIR}"
chmod 0700 "${LOG_DIR}"

echo "== 2/5 keys (created once, never rotated implicitly)"
"${PYTHON}" - "${STATE_DIR}" <<'PY'
import os
import secrets
import sys

state = sys.argv[1]
# Three separate secrets: token key for anonymization, Fernet key for the
# correspondence table, and a dedicated dictionary key. The dictionary key is
# separate on purpose: sharing the token key would let anyone holding the
# dictionary compute the token of a known client and find it in a request.
for name in ("token.key", "fernet.key", "dict.key"):
    path = os.path.join(state, name)
    if os.path.exists(path):
        continue
    with open(path, "wb") as handle:
        handle.write(secrets.token_bytes(32))
    os.chmod(path, 0o600)
    print(f"   generated {name}")
PY

echo "== 3/5 environment file"
if [[ ! -f "${CONF_DIR}/pii-proxy.env" ]]; then
  install -m 0600 "${REPO_DIR}/deploy/pii-proxy.env.example" "${CONF_DIR}/pii-proxy.env"
  # The template uses system paths; a user instance must point at its own
  # directories, otherwise the service cannot read its keys or write its store.
  "${PYTHON}" - "${CONF_DIR}/pii-proxy.env" "${STATE_DIR}" "${LOG_DIR}" <<'PY'
import sys

path, state_dir, log_dir = sys.argv[1:4]
with open(path, encoding="utf-8") as handle:
    text = handle.read()
text = text.replace("/var/lib/pii-proxy", state_dir)
text = text.replace("/var/log/pii-proxy", log_dir)
with open(path, "w", encoding="utf-8") as handle:
    handle.write(text)
print(f"   paths rewritten for {state_dir}")
PY
  echo "   created ${CONF_DIR}/pii-proxy.env - fill in provider keys before starting"
else
  echo "   ${CONF_DIR}/pii-proxy.env already exists, left untouched"
fi

echo "== 4/5 systemd unit"
mkdir -p "$(dirname "${UNIT_DST}")"
install -m 0644 "${UNIT_SRC}" "${UNIT_DST}"
${SYSTEMCTL} daemon-reload
${SYSTEMCTL} enable pii-proxy.service >/dev/null
if [[ "${MODE}" == "user" ]]; then
  loginctl enable-linger "${USER:-hermes}" >/dev/null 2>&1 || \
    echo "   note: could not enable linger; the unit will run only while logged in"
fi

echo "== 5/5 state check"
"${PYTHON}" - "${STATE_DIR}" <<'PY'
import os
import sys

state = sys.argv[1]
for name in ("token.key", "fernet.key", "dict.key"):
    path = os.path.join(state, name)
    print(f"   {name}: {'ok' if os.path.exists(path) else 'MISSING'}")
for name in ("pii_map.db", "pii_dict.json"):
    path = os.path.join(state, name)
    print(f"   {name}: {'present' if os.path.exists(path) else 'will be created / export first'}")
PY

if [[ "${START}" == "1" ]]; then
  ${SYSTEMCTL} restart pii-proxy.service
  sleep 2
  ${SYSTEMCTL} --no-pager --lines=8 status pii-proxy.service || true
  curl -s --max-time 5 http://127.0.0.1:8791/healthz | head -c 800 || true
  echo
else
  echo "service enabled but not started; run with --start to bring it up"
fi
