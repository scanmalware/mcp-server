#!/usr/bin/env bash
# Install auditd and the ScanMalware MCP audit rules. Idempotent.
# The droplet has 2 GB and no swap: check `free -m` first (see docs/OPERATIONS.md).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v auditctl >/dev/null 2>&1; then
  apt-get install -y --no-install-recommends auditd
fi

install -m 0640 "${SCRIPT_DIR}/scanmalware-mcp.rules" /etc/audit/rules.d/scanmalware-mcp.rules
systemctl enable --now auditd
augenrules --load
auditctl -l | grep -E "scanmalware|ssh|docker_config"
