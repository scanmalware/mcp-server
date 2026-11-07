#!/usr/bin/env bash
set -euo pipefail
umask 077

ARCHIVE_PATH="${1:-/tmp/scanmalware-mcp.tar.gz}"
ROOT_DIR="${ROOT_DIR:-/opt/scanmalware-mcp}"
PROJECT="${COMPOSE_PROJECT_NAME:-deploy}"
WAIT_TIMEOUT="${DEPLOY_WAIT_TIMEOUT_S:-120}"
if [[ "$ROOT_DIR" != /* || "$ROOT_DIR" == / || ! -f "$ARCHIVE_PATH" || ! -f "$ROOT_DIR/deploy/docker-compose.yml" ]]; then
  echo "Expected an absolute deployment directory with a Compose file and an existing release archive." >&2
  exit 1
fi
ROOT_DIR="$(cd "$ROOT_DIR" && pwd -P)"
if [[ "$ROOT_DIR" == / ]]; then exit 1; fi

# Prevent overlapping releases from replacing each other's bind mounts/images.
LOCK_DIR="${ROOT_DIR}.deploy-lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "Another deploy holds $LOCK_DIR; resolve it before retrying." >&2
  exit 1
fi
STAGE=""
BACKUP=""
STOPPED=false
OLD_MOVED=false
NEW_INSTALLED=false
ENV_ARGS=(--env-file /dev/null)

compose() {
  docker compose --project-name "$PROJECT" "${ENV_ARGS[@]}" -f "$1" "${@:2}"
}

restore_images() {
  if [[ -n "$BACKUP" && -f "$BACKUP/images" ]]; then
    while read -r saved original; do
      docker image tag "$saved" "$original" || return 1
    done < "$BACKUP/images"
  fi
}

finish() {
  local status=$? recovered=true
  trap - EXIT
  set +e
  if [[ $status -ne 0 ]]; then
    echo "Deploy failed; restoring the previous release..." >&2
    if $NEW_INSTALLED; then
      compose "$ROOT_DIR/deploy/docker-compose.yml" down
      if [[ -d "$ROOT_DIR/logs" && ! -e "$BACKUP/release/logs" ]]; then
        mv "$ROOT_DIR/logs" "$BACKUP/release/logs" || recovered=false
      fi
      mv "$ROOT_DIR" "$STAGE" || recovered=false
    fi
    if $OLD_MOVED; then
      mv "$BACKUP/release" "$ROOT_DIR" || recovered=false
    fi
    restore_images || recovered=false
    if $STOPPED && $recovered; then
      # Read the restored source/config directly, avoiding a second interpolation
      # of values (such as literal '$' characters) in a rendered Compose file.
      compose "$ROOT_DIR/deploy/docker-compose.yml" up -d --no-build --wait --wait-timeout "$WAIT_TIMEOUT" || recovered=false
    fi
    if ! $recovered; then
      echo "Automatic recovery needs attention. Preserved release/config at $BACKUP and $STAGE." >&2
    fi
  fi
  if $recovered; then
    if [[ -n "$BACKUP" && -f "$BACKUP/images" ]]; then
      while read -r saved original; do
        docker image rm "$saved" >/dev/null 2>&1
      done < "$BACKUP/images"
    fi
    [[ -z "$STAGE" ]] || rm -rf "$STAGE"
    [[ -z "$BACKUP" ]] || rm -rf "$BACKUP"
  fi
  rmdir "$LOCK_DIR"
  exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

STAGE="$(mktemp -d "${ROOT_DIR}.staging.XXXXXX")"
BACKUP="$(mktemp -d "${ROOT_DIR}.rollback.XXXXXX")"
# Preserve source readability even under the private umask used for backups.
tar -xzpf "$ARCHIVE_PATH" -C "$STAGE" --no-same-owner
find "$STAGE" -name '._*' -delete
if [[ ! -f "$STAGE/deploy/docker-compose.yml" ]]; then
  echo "Release archive has no deploy/docker-compose.yml" >&2
  exit 1
fi

# Private configuration and the inspection CA belong to the operator, not git.
# Existing values take precedence over anything accidentally shipped in an archive.
for config in .env deploy/.env; do
  if [[ -f "$ROOT_DIR/$config" ]]; then
    cp -a "$ROOT_DIR/$config" "$STAGE/$config"
  fi
done
if [[ -d "$ROOT_DIR/deploy/mitmproxy/state" ]]; then
  mkdir -p "$STAGE/deploy/mitmproxy/state"
  cp -a "$ROOT_DIR/deploy/mitmproxy/state/." "$STAGE/deploy/mitmproxy/state/"
fi
ENV_FILE="${DEPLOY_ENV_FILE:-}"
if [[ -z "$ENV_FILE" ]]; then
  for config in deploy/.env .env; do
    if [[ -f "$ROOT_DIR/$config" ]]; then ENV_FILE="$ROOT_DIR/$config"; break; fi
  done
fi
if [[ -n "$ENV_FILE" ]]; then
  if [[ ! -f "$ENV_FILE" ]]; then echo "Missing environment file: $ENV_FILE" >&2; exit 1; fi
  ENV_FILE="$(cd "$(dirname "$ENV_FILE")" && pwd -P)/$(basename "$ENV_FILE")"
  ENV_ARGS=(--env-file "$ENV_FILE")
fi

compose "$ROOT_DIR/deploy/docker-compose.yml" config --quiet
compose "$ROOT_DIR/deploy/docker-compose.yml" config --images > "$BACKUP/image-refs"
index=0
while IFS= read -r image; do
  if id="$(docker image inspect --format '{{.Id}}' "$image" 2>/dev/null)"; then
    saved="scanmalware-rollback:release-${BACKUP##*.}-$index"
    docker image tag "$id" "$saved"
    echo "$saved $image" >> "$BACKUP/images"
    index=$((index + 1))
  fi
done < "$BACKUP/image-refs"

echo "Validating and building the staged release while the current stack runs..."
compose "$STAGE/deploy/docker-compose.yml" config --quiet
compose "$STAGE/deploy/docker-compose.yml" build

echo "Switching releases..."
STOPPED=true
compose "$ROOT_DIR/deploy/docker-compose.yml" down
mv "$ROOT_DIR" "$BACKUP/release"
OLD_MOVED=true
mv "$STAGE" "$ROOT_DIR"
NEW_INSTALLED=true
if [[ -d "$BACKUP/release/logs" ]]; then
  rm -rf "$ROOT_DIR/logs"
  mv "$BACKUP/release/logs" "$ROOT_DIR/logs"
fi
compose "$ROOT_DIR/deploy/docker-compose.yml" up -d --no-build --wait --wait-timeout "$WAIT_TIMEOUT"
echo "Deploy complete; services passed Compose readiness checks."
