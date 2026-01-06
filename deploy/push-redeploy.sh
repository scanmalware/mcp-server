#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <user@host> [ssh_key_path] [archive_path]" >&2
  exit 1
fi

TARGET="$1"
SSH_KEY="${2:-}"
ARCHIVE_PATH="${3:-/tmp/scanmalware-mcp.tar.gz}"
REMOTE_ARCHIVE="/tmp/scanmalware-mcp.tar.gz"
ROOT_DIR="${ROOT_DIR:-/opt/scanmalware-mcp}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKDIR="${WORKDIR:-${REPO_ROOT}}"

EXCLUDES=(
  --exclude .git
  --exclude .venv
  --exclude __pycache__
  --exclude .mypy_cache
  --exclude .pytest_cache
  --exclude .ruff_cache
  --exclude logs
  --exclude .DS_Store
  --exclude '._*'
  --exclude '__MACOSX'
)

SSH_OPTS=()
SCP_OPTS=()
if [[ -n "${SSH_KEY}" ]]; then
  SSH_OPTS=(-i "${SSH_KEY}")
  SCP_OPTS=(-i "${SSH_KEY}")
fi

echo "Creating archive at ${ARCHIVE_PATH}..."
tar -czf "${ARCHIVE_PATH}" "${EXCLUDES[@]}" -C "${WORKDIR}" .

echo "Uploading to ${TARGET}:${REMOTE_ARCHIVE}..."
if [[ ${#SCP_OPTS[@]} -gt 0 ]]; then
  scp "${SCP_OPTS[@]}" "${ARCHIVE_PATH}" "${TARGET}:${REMOTE_ARCHIVE}"
else
  scp "${ARCHIVE_PATH}" "${TARGET}:${REMOTE_ARCHIVE}"
fi

echo "Running remote redeploy..."
if [[ ${#SSH_OPTS[@]} -gt 0 ]]; then
  ssh "${SSH_OPTS[@]}" "${TARGET}" \
    "if [ ! -x \"${ROOT_DIR}/deploy/redeploy.sh\" ]; then \
       mkdir -p \"${ROOT_DIR}\"; \
       tar -xzf \"${REMOTE_ARCHIVE}\" -C \"${ROOT_DIR}\" --no-same-owner; \
     fi; \
     bash \"${ROOT_DIR}/deploy/redeploy.sh\" \"${REMOTE_ARCHIVE}\""
else
  ssh "${TARGET}" \
    "if [ ! -x \"${ROOT_DIR}/deploy/redeploy.sh\" ]; then \
       mkdir -p \"${ROOT_DIR}\"; \
       tar -xzf \"${REMOTE_ARCHIVE}\" -C \"${ROOT_DIR}\" --no-same-owner; \
     fi; \
     bash \"${ROOT_DIR}/deploy/redeploy.sh\" \"${REMOTE_ARCHIVE}\""
fi
