#!/usr/bin/env bash
# Validate the configuration Compose actually mounts, without production keys.
set -euo pipefail

IMAGE="${1:-nginx-check}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$(mktemp -d)"
trap 'rm -rf "$CERT_DIR"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=mcp.scanmalware.com \
  -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem" \
  > "$CERT_DIR/openssl.log" 2>&1
chmod 600 "$CERT_DIR/privkey.pem"
docker run --rm --network none --add-host mcp:127.0.0.1 \
  -v "$SCRIPT_DIR/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" \
  -v "$CERT_DIR:/etc/letsencrypt/live/mcp.scanmalware.com:ro" \
  "$IMAGE" nginx -t
