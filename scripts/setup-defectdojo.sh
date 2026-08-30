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
#   HF_DEFECTDOJO_REF      exact reviewed upstream commit to install
#
# Usage: ./scripts/setup-defectdojo.sh
set -uo pipefail
umask 077

# Finder-launched callers may not inherit the OrbStack/Docker PATH.
export PATH="$HOME/.orbstack/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DD_DIR="${HF_DEFECTDOJO_DIR:-$HOME/.oxfuzz/defectdojo}"
DD_PORT="${HF_DEFECTDOJO_PORT:-8080}"
DD_PROJECT="${HF_DEFECTDOJO_PROJECT:-defectdojo}"
READY_TIMEOUT="${HF_DEFECTDOJO_READY_TIMEOUT:-300}"
DD_URL="http://localhost:${DD_PORT}"
UPSTREAM="https://github.com/DefectDojo/django-DefectDojo.git"
# DefectDojo 2.58.4. This is the peeled release commit, not the annotated tag.
DEFAULT_DEFECTDOJO_REF="5b1d60e8d59b3fd8df638e7dcdfa279a5cb815af"
DEFECTDOJO_REF="${HF_DEFECTDOJO_REF:-$DEFAULT_DEFECTDOJO_REF}"
DJANGO_IMAGE_VERSION="2.58.4@sha256:aa1ad27ac55660ccc8d635f5ba03b701a2882285abafd66f248424b6aff9d630"
NGINX_IMAGE_VERSION="2.58.4@sha256:7d2d0ec29051039f081072366df973fe8d5d12fde4e4a524bdd0a1a0aab1c4fe"
CONFIG_FILE="$REPO_ROOT/config/defectdojo.toml"

log() { printf '=== %s ===\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
validate_commit_ref() { [[ "$1" =~ ^[0-9a-f]{40}$ ]]; }

read_env_value() {
  local name="$1"
  local file="$2"
  local count
  count="$(grep -c "^${name}=" "$file" 2>/dev/null || true)"
  [ "$count" = 1 ] || die "${file} must contain exactly one ${name} entry"
  grep "^${name}=" "$file" | sed "s/^${name}=//"
}

validate_commit_ref "$DEFECTDOJO_REF" \
  || die "HF_DEFECTDOJO_REF must be an exact lowercase 40-character commit"
[[ "$DD_PORT" =~ ^[0-9]+$ ]] && [ "$DD_PORT" -ge 1 ] && [ "$DD_PORT" -le 65535 ] \
  || die "HF_DEFECTDOJO_PORT must be an integer between 1 and 65535"
[[ "$READY_TIMEOUT" =~ ^[0-9]+$ ]] && [ "$READY_TIMEOUT" -le 3600 ] \
  || die "HF_DEFECTDOJO_READY_TIMEOUT must be an integer no greater than 3600"
[[ "$DD_PROJECT" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]] \
  || die "HF_DEFECTDOJO_PROJECT must be a lowercase compose project name"

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

# --- Prepare the reviewed upstream compose project -------------------------
# The checkout is required even when the stack is already running because its
# compose file and generated credential data remain the lifecycle source.
if [ -d "$DD_DIR/.git" ]; then
  [ "$(git -C "$DD_DIR" remote get-url origin 2>/dev/null)" = "$UPSTREAM" ] \
    || die "existing DefectDojo checkout has an unexpected origin"
else
  if [ -d "$DD_DIR" ] && [ -n "$(find "$DD_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
    die "${DD_DIR} exists and is not an empty DefectDojo checkout"
  fi
  log "Initializing reviewed DefectDojo checkout in ${DD_DIR}"
  mkdir -p "$(dirname "$DD_DIR")"
  git init --quiet "$DD_DIR" || die "git init failed"
  git -C "$DD_DIR" remote add origin "$UPSTREAM" || die "git remote setup failed"
fi

current_ref="$(git -C "$DD_DIR" rev-parse HEAD 2>/dev/null || true)"
if [ "$current_ref" != "$DEFECTDOJO_REF" ]; then
  git -C "$DD_DIR" diff --quiet && git -C "$DD_DIR" diff --cached --quiet \
    || die "existing DefectDojo checkout has local changes; refusing to replace it"
  log "Fetching reviewed DefectDojo commit ${DEFECTDOJO_REF}"
  git -C "$DD_DIR" fetch --depth 1 origin "$DEFECTDOJO_REF" \
    || die "fetching reviewed DefectDojo commit failed"
  ( cd "$DD_DIR" && git checkout --detach "$DEFECTDOJO_REF" ) \
    || die "checking out reviewed DefectDojo commit failed"
fi
resolved_ref="$(git -C "$DD_DIR" rev-parse HEAD 2>/dev/null)" \
  || die "resolving DefectDojo checkout failed"
[ "$resolved_ref" = "$DEFECTDOJO_REF" ] \
  || die "DefectDojo checkout does not match the reviewed commit"
[ -f "$DD_DIR/docker-compose.yml" ] || die "no docker-compose.yml in ${DD_DIR}"

# --- Deterministic admin credentials (persisted once) ----------------------
# A known admin password lets this script provision an API token without manual
# UI steps. Generate it once and keep it in the compose project's own .env
# (compose auto-loads it); an override injects it into the initializer, whose
# base compose does not declare DD_ADMIN_PASSWORD.
DD_ENV="$DD_DIR/.env"
touch "$DD_ENV" || die "cannot create ${DD_ENV}"
chmod 600 "$DD_ENV" || die "cannot protect ${DD_ENV}"
if grep -Ev '^[[:space:]]*(#|$)|^(DD_ADMIN_USER|DD_ADMIN_PASSWORD|DD_PORT)=' "$DD_ENV" | grep -q .; then
  die "${DD_ENV} contains unsupported entries; expected only DD_ADMIN_USER, DD_ADMIN_PASSWORD, and DD_PORT"
fi
if ! grep -q '^DD_ADMIN_USER=' "$DD_ENV"; then
  echo "DD_ADMIN_USER=admin" >>"$DD_ENV"
fi
if ! grep -q '^DD_ADMIN_PASSWORD=' "$DD_ENV"; then
  GEN_PW="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)"
  echo "DD_ADMIN_PASSWORD=${GEN_PW}" >>"$DD_ENV"
fi
if ! grep -q '^DD_PORT=' "$DD_ENV"; then
  echo "DD_PORT=${DD_PORT}" >>"$DD_ENV"
fi
DD_ADMIN_USER="$(read_env_value DD_ADMIN_USER "$DD_ENV")"
DD_ADMIN_PASSWORD="$(read_env_value DD_ADMIN_PASSWORD "$DD_ENV")"
DD_ENV_PORT="$(read_env_value DD_PORT "$DD_ENV")"
[[ "$DD_ADMIN_USER" =~ ^[A-Za-z0-9_.@-]{1,128}$ ]] \
  || die "DD_ADMIN_USER contains unsupported characters"
[[ "$DD_ADMIN_PASSWORD" =~ ^[A-Za-z0-9]{24,128}$ ]] \
  || die "DD_ADMIN_PASSWORD must contain 24 to 128 ASCII letters or digits"
[ "$DD_ENV_PORT" = "$DD_PORT" ] \
  || die "configured DD_PORT ${DD_PORT} differs from persisted ${DD_ENV_PORT}"

if [ "$need_start" = 1 ]; then
  cat >"$DD_DIR/docker-compose.override.yml" <<'YAML'
# Written by oxfuzz scripts/setup-defectdojo.sh: inject the admin password
# into the initializer so the account is created with known credentials.
services:
  initializer:
    environment:
      DD_ADMIN_PASSWORD: "${DD_ADMIN_PASSWORD}"
YAML
  chmod 600 "$DD_DIR/docker-compose.override.yml" \
    || die "cannot protect the compose override"

  # --- Pull reviewed images, then start (no source build) ------------------
  # The application image variables include registry digests. The pinned
  # upstream compose revision already digest-pins its database and cache.
  log "Pulling DefectDojo images (this is large on first run)"
  ( cd "$DD_DIR" && \
    COMPOSE_PROJECT_NAME="$DD_PROJECT" \
    COMPOSE_FILE="$DD_DIR/docker-compose.yml:$DD_DIR/docker-compose.override.yml" \
    DJANGO_VERSION="$DJANGO_IMAGE_VERSION" \
    NGINX_VERSION="$NGINX_IMAGE_VERSION" \
    docker compose --env-file "$DD_ENV" pull ) \
    || die "docker compose pull failed"

  log "Starting DefectDojo (project '${DD_PROJECT}', port ${DD_PORT})"
  ( cd "$DD_DIR" && \
    COMPOSE_PROJECT_NAME="$DD_PROJECT" \
    COMPOSE_FILE="$DD_DIR/docker-compose.yml:$DD_DIR/docker-compose.override.yml" \
    DJANGO_VERSION="$DJANGO_IMAGE_VERSION" \
    NGINX_VERSION="$NGINX_IMAGE_VERSION" \
    docker compose --env-file "$DD_ENV" up -d --no-build ) \
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
  TOKEN="$(
    printf '{"username":"%s","password":"%s"}' "$DD_ADMIN_USER" "$DD_ADMIN_PASSWORD" \
      | curl -s -X POST "${DD_URL}/api/v2/api-token-auth/" \
        -H 'Content-Type: application/json' --data-binary @- 2>/dev/null \
      | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
  )"
fi

# --- Write oxfuzz config (gitignored; may hold the token) --------------
mkdir -p "$REPO_ROOT/config"
CONFIG_TEMP="$(mktemp "$REPO_ROOT/config/.defectdojo.toml.XXXXXX")" \
  || die "cannot create temporary DefectDojo config"
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
} >"$CONFIG_TEMP"
chmod 600 "$CONFIG_TEMP" || die "cannot protect temporary DefectDojo config"
mv "$CONFIG_TEMP" "$CONFIG_FILE" || die "cannot install DefectDojo config"
chmod 600 "$CONFIG_FILE" || die "cannot protect ${CONFIG_FILE}"

# --- Summary ---------------------------------------------------------------
echo ""
log "DefectDojo setup complete"
echo "  URL:        ${DD_URL}"
echo "  Admin user: ${DD_ADMIN_USER}"
echo "  Credentials: stored owner-only in ${DD_ENV}"
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
