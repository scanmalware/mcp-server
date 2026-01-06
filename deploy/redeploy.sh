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

echo "Stopping containers to avoid bind-mount inode issues..."
docker-compose -f "${COMPOSE_FILE}" down

echo "Updating files from ${ARCHIVE_PATH}..."
mkdir -p "${ROOT_DIR}"
find "${ROOT_DIR}" -mindepth 1 -maxdepth 1 -not -name logs -exec rm -rf {} +
tar -xzf "${ARCHIVE_PATH}" -C "${ROOT_DIR}" --no-same-owner
find "${ROOT_DIR}" -name '._*' -delete

echo "Starting containers..."
docker-compose -f "${COMPOSE_FILE}" up -d --build

echo "Done."
