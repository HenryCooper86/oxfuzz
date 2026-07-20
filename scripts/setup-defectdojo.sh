#!/usr/bin/env bash
# Install and start a local DefectDojo for oxfuzz on Docker/OrbStack.
#
# oxfuzz ships no DefectDojo image or compose file: it adopts and supervises
# an upstream install (see docs/design/defectdojo-integration.md). This script
# performs that upstream install for you -- it clones DefectDojo's own
# docker-compose project, brings it up on the port the app expects, and writes
# config/defectdojo.toml so the desktop app and CLI find it. It is idempotent:
# re-running when the stack is already up is a fast no-op.
#
# Environment overrides:
#   HF_DEFECTDOJO_DIR      where the upstream compose project is cloned
#                          (default: $HOME/.oxfuzz/defectdojo)
#   HF_DEFECTDOJO_PORT     host port the app owns (default: 8080)
#   HF_DEFECTDOJO_PROJECT  docker compose project name (default: defectdojo)
#   HF_DEFECTDOJO_READY_TIMEOUT  seconds to wait for first boot (default: 300)
#
# Usage: ./scripts/setup-defectdojo.sh
set -uo pipefail

# Finder-launched callers may not inherit the OrbStack/Docker PATH.
export PATH="$HOME/.orbstack/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DD_DIR="${HF_DEFECTDOJO_DIR:-$HOME/.oxfuzz/defectdojo}"
DD_PORT="${HF_DEFECTDOJO_PORT:-8080}"
DD_PROJECT="${HF_DEFECTDOJO_PROJECT:-defectdojo}"
READY_TIMEOUT="${HF_DEFECTDOJO_READY_TIMEOUT:-300}"
DD_URL="http://localhost:${DD_PORT}"
UPSTREAM="https://github.com/DefectDojo/django-DefectDojo.git"
CONFIG_FILE="$REPO_ROOT/config/defectdojo.toml"

log() { printf '=== %s ===\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker CLI not found (install OrbStack or Docker Desktop)"
docker info >/dev/null 2>&1 || die "Docker daemon is not reachable -- start OrbStack/Docker and retry"
command -v git >/dev/null 2>&1 || die "git not found"

# --- Fast path: already fully set up --------------------------------------
project_running() {
  [ -n "$(docker ps -q --filter "label=com.docker.compose.project=${DD_PROJECT}" 2>/dev/null)" ]
}
config_has_token() { grep -q '^api_token = ' "$CONFIG_FILE" 2>/dev/null; }

if project_running && config_has_token; then
  log "DefectDojo already running (project '${DD_PROJECT}') and configured with a token"
  echo "URL: ${DD_URL}"
  exit 0
fi

# Whether the stack needs to be pulled and started. When it is already up we
# still fall through to (re)provision the token and rewrite the config, but skip
# the expensive clone/pull/up.
need_start=1
if project_running; then
  need_start=0
  log "DefectDojo is already running; ensuring config and API token"
fi

# --- Clone or update upstream compose project ------------------------------
# Always needed for the compose file and the credentials .env, even when the
# stack is already running (the checkout is where its .env lives).
if [ -d "$DD_DIR/.git" ]; then
  if [ "$need_start" = 1 ]; then
    log "Updating upstream DefectDojo in ${DD_DIR}"
    git -C "$DD_DIR" pull --ff-only --quiet || echo "warning: could not fast-forward the DefectDojo checkout; using the existing one"
  fi
else
  log "Cloning upstream DefectDojo into ${DD_DIR}"
  mkdir -p "$(dirname "$DD_DIR")"
  git clone --depth 1 "$UPSTREAM" "$DD_DIR" || die "git clone failed"
fi
[ -f "$DD_DIR/docker-compose.yml" ] || die "no docker-compose.yml in ${DD_DIR}"

# --- Deterministic admin credentials (persisted once) ----------------------
# A known admin password lets this script provision an API token without manual
# UI steps. Generate it once and keep it in the compose project's own .env
# (compose auto-loads it); an override injects it into the initializer, whose
# base compose does not declare DD_ADMIN_PASSWORD.
DD_ENV="$DD_DIR/.env"
if ! grep -q '^DD_ADMIN_PASSWORD=' "$DD_ENV" 2>/dev/null; then
  GEN_PW="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)"
  {
    echo "DD_ADMIN_USER=admin"
    echo "DD_ADMIN_PASSWORD=${GEN_PW}"
    echo "DD_PORT=${DD_PORT}"
  } >>"$DD_ENV"
fi
# shellcheck disable=SC1090
set -a; . "$DD_ENV"; set +a

if [ "$need_start" = 1 ]; then
  cat >"$DD_DIR/docker-compose.override.yml" <<'YAML'
# Written by oxfuzz scripts/setup-defectdojo.sh: inject the admin password
# into the initializer so the account is created with known credentials.
services:
  initializer:
    environment:
      DD_ADMIN_PASSWORD: "${DD_ADMIN_PASSWORD}"
YAML

  # --- Pull released images, then start (no source build) ------------------
  # Services declare both build: and image:; pulling first makes `up` use the
  # released images instead of building DefectDojo from source.
  log "Pulling DefectDojo images (this is large on first run)"
  ( cd "$DD_DIR" && COMPOSE_PROJECT_NAME="$DD_PROJECT" DD_PORT="$DD_PORT" docker compose pull ) \
    || die "docker compose pull failed"

  log "Starting DefectDojo (project '${DD_PROJECT}', port ${DD_PORT})"
  ( cd "$DD_DIR" && COMPOSE_PROJECT_NAME="$DD_PROJECT" DD_PORT="$DD_PORT" docker compose up -d ) \
    || die "docker compose up failed"
fi

# --- Wait for readiness (HTTP, not TCP: nginx answers before uwsgi is up) ---
log "Waiting for DefectDojo to become ready (up to ${READY_TIMEOUT}s on first boot)"
ready=0
waited=0
while [ "$waited" -lt "$READY_TIMEOUT" ]; do
  # DefectDojo's login is at /login (no trailing slash; /login/ returns 404).
  code="$(curl -s -o /dev/null -w '%{http_code}' "${DD_URL}/login" 2>/dev/null || echo 000)"
  if [ "$code" = "200" ]; then ready=1; break; fi
  sleep 5
  waited=$((waited + 5))
  printf '  ... still starting (%ss, last HTTP %s)\n' "$waited" "$code"
done

# --- Provision an API token (best-effort) ----------------------------------
TOKEN=""
if [ "$ready" = "1" ]; then
  TOKEN="$(curl -s -X POST "${DD_URL}/api/v2/api-token-auth/" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"${DD_ADMIN_USER:-admin}\",\"password\":\"${DD_ADMIN_PASSWORD}\"}" 2>/dev/null \
    | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
fi

# --- Write oxfuzz config (gitignored; may hold the token) --------------
mkdir -p "$REPO_ROOT/config"
{
  echo "# Written by scripts/setup-defectdojo.sh. Gitignored -- may hold a token."
  echo "url = \"${DD_URL}\""
  if [ -n "$TOKEN" ]; then
    echo "api_token = \"${TOKEN}\""
  else
    echo "# Auto-token provisioning did not complete; create an API v2 Key in the"
    echo "# DefectDojo UI (Profile -> API v2 Key) and paste it here, or export it:"
    echo "api_token_env = \"HF_DEFECTDOJO_TOKEN\""
  fi
  echo "verify_tls = false"
  echo "auto_create = true"
  echo "reimport = true"
  echo ""
  echo "[lifecycle]"
  echo "autostart = true"
  echo "compose_project = \"${DD_PROJECT}\""
} >"$CONFIG_FILE"

# --- Summary ---------------------------------------------------------------
echo ""
log "DefectDojo setup complete"
echo "  URL:        ${DD_URL}"
echo "  Admin user: ${DD_ADMIN_USER:-admin}"
echo "  Admin pass: ${DD_ADMIN_PASSWORD}   (also in ${DD_ENV})"
echo "  Compose:    project '${DD_PROJECT}' in ${DD_DIR}"
echo "  Config:     ${CONFIG_FILE}"
if [ -n "$TOKEN" ]; then
  echo "  API token:  provisioned and written to config (api_token)"
else
  echo "  API token:  NOT provisioned automatically -- see ${CONFIG_FILE}"
fi
if [ "$ready" != "1" ]; then
  echo ""
  echo "note: the server was still booting after ${READY_TIMEOUT}s. It usually finishes"
  echo "      migrations within a few minutes; check: docker compose -p ${DD_PROJECT} logs -f uwsgi"
fi
