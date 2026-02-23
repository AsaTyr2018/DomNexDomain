#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

BIN_SRC="${1:-${REPO_ROOT}/build/domnexdomain}"
BIN_DST="/usr/bin/domnexdomain"
SVC_FILE="/etc/systemd/system/domnexdomain.service"
ENV_FILE="/etc/domnexdomain/domnexdomain.env"
APPLY_UFW="${DOMNEX_APPLY_UFW:-1}"
LAN_CIDRS_RAW="${DOMNEX_LAN_CIDRS:-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

if [[ ! -f "$BIN_SRC" ]]; then
  echo "Binary not found: $BIN_SRC" >&2
  exit 1
fi

echo "[1/8] Create service user and directories"
id -u domnexdomain >/dev/null 2>&1 || useradd --system --home /var/lib/domnexdomain --shell /usr/sbin/nologin domnexdomain
mkdir -p /etc/domnexdomain /var/lib/domnexdomain /var/log/domnexdomain
chown -R domnexdomain:domnexdomain /var/lib/domnexdomain /var/log/domnexdomain
chmod 0750 /etc/domnexdomain /var/lib/domnexdomain /var/log/domnexdomain

echo "[2/8] Install binary"
install -m 0755 "$BIN_SRC" "$BIN_DST"

echo "[3/8] Install environment template"
if [[ ! -f "$ENV_FILE" ]]; then
  install -m 0640 "${REPO_ROOT}/config/domnexdomain.env.example" "$ENV_FILE"
fi

if [[ -f "$ENV_FILE" ]]; then
  sed -i 's/^DOMNEX_BOOTSTRAP_PASSWORD=.*/DOMNEX_BOOTSTRAP_PASSWORD=/' "$ENV_FILE" || true
fi

echo "[4/8] Install systemd unit"
install -m 0644 "${REPO_ROOT}/deploy/systemd/domnexdomain.service" "$SVC_FILE"

echo "[5/8] Configure host firewall policy"
if [[ "$APPLY_UFW" == "1" ]]; then
  if command -v ufw >/dev/null 2>&1; then
    IFS=',' read -r -a LAN_CIDRS <<< "$LAN_CIDRS_RAW"

    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    # WAN-facing edge ports
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 2222/tcp

    # LAN-only control plane + SSH management (configurable CIDRs)
    for cidr in "${LAN_CIDRS[@]}"; do
      cidr="$(echo "$cidr" | xargs)"
      [[ -z "$cidr" ]] && continue
      if ! ufw allow proto tcp from "$cidr" to any port 8443; then
        echo "Warning: invalid or unsupported LAN CIDR for 8443: $cidr" >&2
      fi
      if ! ufw allow proto tcp from "$cidr" to any port 22; then
        echo "Warning: invalid or unsupported LAN CIDR for 22: $cidr" >&2
      fi
    done

    ufw --force enable
  else
    echo "Warning: ufw is not installed. Skipping firewall policy setup." >&2
  fi
else
  echo "Skipping firewall policy setup (DOMNEX_APPLY_UFW=${APPLY_UFW})."
fi

echo "[6/8] Reload and start service"
systemctl daemon-reload
systemctl enable domnexdomain
systemctl restart domnexdomain

echo "[7/8] Wait for startup"
sleep 2

echo "[8/8] Fetch OTS from journal"
OTS_LINE=$(journalctl -u domnexdomain -n 200 --no-pager | grep -E 'initial setup locked: one-time setup code generated' | tail -n 1 || true)
if [[ -n "$OTS_LINE" ]]; then
  echo
  echo "Setup unlock info:"
  echo "$OTS_LINE"
  echo "Open: https://<server-ip>:8443"
else
  echo "No OTS line found in recent logs. Check: journalctl -u domnexdomain -n 200 --no-pager"
fi
