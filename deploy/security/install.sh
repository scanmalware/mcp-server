#!/usr/bin/env bash
# Install the daily security report timer. Idempotent.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install -m 0644 "${SCRIPT_DIR}/scanmalware-security-report.service" /etc/systemd/system/
install -m 0644 "${SCRIPT_DIR}/scanmalware-security-report.timer" /etc/systemd/system/
install -d -m 0755 /etc/scanmalware-mcp
systemctl daemon-reload
systemctl enable --now scanmalware-security-report.timer
systemctl list-timers scanmalware-security-report.timer --no-pager
