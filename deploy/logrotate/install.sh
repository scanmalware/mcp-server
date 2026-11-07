#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this installer as root on the production host." >&2
  exit 1
fi
for tool in logrotate zstd python3; do
  if ! command -v "${tool}" >/dev/null; then
    echo "Install ${tool} first: apt-get update && apt-get install -y ${tool}" >&2
    exit 1
  fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Validate before replacing an installed configuration. Debug mode is read-only.
# Check a 0644 copy: git archive extracts files as 0664, and logrotate skips a
# group-writable config with only an error line, so the check would pass unread.
CHECK_CONF="$(mktemp)"
trap 'rm -f "${CHECK_CONF}"' EXIT
install -m 0644 "${SCRIPT_DIR}/scanmalware-mcp.conf" "${CHECK_CONF}"
if logrotate --debug --state /dev/null "${CHECK_CONF}" 2>&1 | grep -E '^error:'; then
  echo "logrotate rejected scanmalware-mcp.conf; nothing installed" >&2
  exit 1
fi
# Parse only: py_compile would leave a __pycache__ in the release tree.
python3 -c 'import ast, sys; ast.parse(open(sys.argv[1]).read())' "${SCRIPT_DIR}/archive_logs.py"
# verify resolves ExecStart paths, so check the archive units once the script is in place.
systemd-analyze verify "${SCRIPT_DIR}/scanmalware-logrotate.service" "${SCRIPT_DIR}/scanmalware-logrotate.timer"

install -d -m 0755 /etc/scanmalware-mcp /var/lib/logrotate
install -m 0644 "${SCRIPT_DIR}/scanmalware-mcp.conf" /etc/scanmalware-mcp/logrotate.conf
install -m 0644 "${SCRIPT_DIR}/scanmalware-logrotate.service" /etc/systemd/system/
install -m 0644 "${SCRIPT_DIR}/scanmalware-logrotate.timer" /etc/systemd/system/

# Long-term archive. The script is copied out of the release tree so a redeploy
# never leaves the timer pointing at a missing file. The archive lives outside
# /opt/scanmalware-mcp and outside every container mount.
install -m 0755 "${SCRIPT_DIR}/archive_logs.py" /usr/local/sbin/scanmalware-archive-logs
install -d -m 0750 -o root -g adm /var/log/scanmalware-mcp-archive
install -m 0644 "${SCRIPT_DIR}/scanmalware-log-archive.service" /etc/systemd/system/
install -m 0644 "${SCRIPT_DIR}/scanmalware-log-archive.timer" /etc/systemd/system/
systemd-analyze verify /etc/systemd/system/scanmalware-log-archive.service /etc/systemd/system/scanmalware-log-archive.timer

systemctl daemon-reload
systemctl enable --now scanmalware-logrotate.timer scanmalware-log-archive.timer
systemctl start scanmalware-logrotate.service
# The first run archives every backup already on disk; later runs take seconds.
systemctl start scanmalware-log-archive.service
