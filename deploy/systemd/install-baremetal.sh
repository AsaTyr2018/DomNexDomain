#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

BIN_SRC="${1:-${REPO_ROOT}/build/domnexdomain}"
BIN_DST="/usr/bin/domnexdomain"
SVC_FILE="/etc/systemd/system/domnexdomain.service"
ENV_FILE="/etc/domnexdomain/domnexdomain.env"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

if [[ ! -f "$BIN_SRC" ]]; then
  echo "Binary not found: $BIN_SRC" >&2
  exit 1
fi

echo "[1/7] Create service user and directories"
id -u domnexdomain >/dev/null 2>&1 || useradd --system --home /var/lib/domnexdomain --shell /usr/sbin/nologin domnexdomain
mkdir -p /etc/domnexdomain /var/lib/domnexdomain /var/log/domnexdomain
chown -R domnexdomain:domnexdomain /var/lib/domnexdomain /var/log/domnexdomain
chmod 0750 /etc/domnexdomain /var/lib/domnexdomain /var/log/domnexdomain

echo "[2/7] Install binary"
install -m 0755 "$BIN_SRC" "$BIN_DST"

echo "[3/7] Install environment template"
if [[ ! -f "$ENV_FILE" ]]; then
  install -m 0640 "${REPO_ROOT}/config/domnexdomain.env.example" "$ENV_FILE"
fi

if [[ -f "$ENV_FILE" ]]; then
  sed -i 's/^DOMNEX_BOOTSTRAP_PASSWORD=.*/DOMNEX_BOOTSTRAP_PASSWORD=/' "$ENV_FILE" || true
fi

echo "[4/7] Install systemd unit"
install -m 0644 "${REPO_ROOT}/deploy/systemd/domnexdomain.service" "$SVC_FILE"

echo "[5/7] Reload and start service"
systemctl daemon-reload
systemctl enable domnexdomain
systemctl restart domnexdomain

echo "[6/7] Wait for startup"
sleep 2

echo "[7/7] Fetch OTS from journal"
OTS_LINE=$(journalctl -u domnexdomain -n 200 --no-pager | grep -E 'initial setup locked: one-time setup code generated' | tail -n 1 || true)
if [[ -n "$OTS_LINE" ]]; then
  echo
  echo "Setup unlock info:"
  echo "$OTS_LINE"
  echo "Open: https://<server-ip>:8443"
else
  echo "No OTS line found in recent logs. Check: journalctl -u domnexdomain -n 200 --no-pager"
fi
