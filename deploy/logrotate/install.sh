#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this installer as root on the production host." >&2
  exit 1
fi
if ! command -v logrotate >/dev/null; then
  echo "Install logrotate first: apt-get update && apt-get install -y logrotate" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Validate before replacing an installed configuration. Debug mode is read-only.
logrotate --debug --state /dev/null "${SCRIPT_DIR}/scanmalware-mcp.conf"
systemd-analyze verify "${SCRIPT_DIR}/scanmalware-logrotate.service" "${SCRIPT_DIR}/scanmalware-logrotate.timer"

install -d -m 0755 /etc/scanmalware-mcp /var/lib/logrotate
install -m 0644 "${SCRIPT_DIR}/scanmalware-mcp.conf" /etc/scanmalware-mcp/logrotate.conf
install -m 0644 "${SCRIPT_DIR}/scanmalware-logrotate.service" /etc/systemd/system/
install -m 0644 "${SCRIPT_DIR}/scanmalware-logrotate.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now scanmalware-logrotate.timer
systemctl start scanmalware-logrotate.service
