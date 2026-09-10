#!/usr/bin/env bash
set -euo pipefail

ARCHIVE_PATH="${1:-/tmp/scanmalware-mcp.tar.gz}"
ROOT_DIR="${ROOT_DIR:-/opt/scanmalware-mcp}"
COMPOSE_FILE="${ROOT_DIR}/deploy/docker-compose.yml"

if [[ ! -f "${ARCHIVE_PATH}" ]]; then
  echo "Archive not found: ${ARCHIVE_PATH}" >&2
  exit 1
fi

if [[ ! -f "${COMPOSE_FILE}" ]]; then
  echo "Compose file not found: ${COMPOSE_FILE}" >&2
  exit 1
fi

STATE_DIR="${ROOT_DIR}/deploy/mitmproxy/state"

echo "Stopping containers to avoid bind-mount inode issues..."
docker-compose -f "${COMPOSE_FILE}" down

# The mitmproxy CA lives in deploy/mitmproxy/state and is gitignored, so it is
# NOT in the uploaded archive - only a .gitkeep is. The wipe below would destroy
# it, and the MCP container would then fail TLS verification against the proxy
# until a new CA was generated and every container restarted in the right order.
# Preserve it across the swap.
STATE_BACKUP=""
if [[ -d "${STATE_DIR}" ]] && [[ -n "$(ls -A "${STATE_DIR}" 2>/dev/null)" ]]; then
  STATE_BACKUP="$(mktemp -d)"
  cp -a "${STATE_DIR}/." "${STATE_BACKUP}/"
  echo "Preserved mitmproxy CA state -> ${STATE_BACKUP}"
fi

echo "Updating files from ${ARCHIVE_PATH}..."
mkdir -p "${ROOT_DIR}"
find "${ROOT_DIR}" -mindepth 1 -maxdepth 1 -not -name logs -exec rm -rf {} +
tar -xzf "${ARCHIVE_PATH}" -C "${ROOT_DIR}" --no-same-owner
find "${ROOT_DIR}" -name '._*' -delete

if [[ -n "${STATE_BACKUP}" ]]; then
  echo "Restoring mitmproxy CA state..."
  mkdir -p "${STATE_DIR}"
  cp -a "${STATE_BACKUP}/." "${STATE_DIR}/"
  rm -rf "${STATE_BACKUP}"
fi

if [[ ! -f "${STATE_DIR}/mitmproxy-ca-cert.pem" ]]; then
  echo "WARNING: no mitmproxy CA at ${STATE_DIR}/mitmproxy-ca-cert.pem." >&2
  echo "         Start 'proxy' alone and wait for it to generate one before" >&2
  echo "         starting 'mcp', or mcp will fail TLS to the proxy." >&2
  echo "         See docs/OPERATIONS.md - 'TLS inspection (mitmproxy)'." >&2
fi

echo "Starting containers..."
docker-compose -f "${COMPOSE_FILE}" up -d --build

echo "Done."
