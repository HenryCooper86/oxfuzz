#!/usr/bin/env bash
# Register a GitLab CI runner for this project as an OrbStack Docker container.
#
# This resolves the "no runners available" gap that caused .gitlab-ci.yml to be
# removed: the pipeline's Docker-executor jobs (rust:1.94, node:22,
# python:3.12-slim) need a registered runner to pick them up. One registered
# runner gates every push to the OrbStack GitLab origin.
#
# The runner itself is a long-lived `gitlab/gitlab-runner` container. Using the
# Docker executor, it spawns one throwaway container per CI job, so it mounts the
# host Docker socket. Its configuration lives in a named volume, so re-running
# the daemon never loses the registration.
#
# Prerequisites:
#   1. Docker (OrbStack provides it) is running.
#   2. A runner authentication token. In the project on the OrbStack GitLab:
#      Settings > CI/CD > Runners > "New project runner" -> copy the `glrt-...`
#      token. (Legacy registration tokens still work; pass --registration-token.)
#
# Usage:
#   GITLAB_RUNNER_TOKEN=glrt-xxxx scripts/ci/register-gitlab-runner.sh
#   scripts/ci/register-gitlab-runner.sh --token glrt-xxxx --url http://gitlab-ce.orb.local
#
# See docs/guides/CI.md for the full walkthrough, including OrbStack DNS notes.
set -euo pipefail

URL="${GITLAB_URL:-http://gitlab-ce.orb.local}"
TOKEN="${GITLAB_RUNNER_TOKEN:-}"
REGISTRATION_TOKEN=""
NAME="${RUNNER_NAME:-oxfuzz-gitlab-runner}"
DEFAULT_IMAGE="${RUNNER_DEFAULT_IMAGE:-rust:1.94}"
CONFIG_VOLUME="${NAME}-config"

usage() {
  sed -n '2,29p' "$0"
  exit "${1:-0}"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --token) TOKEN="$2"; shift 2 ;;
    --registration-token) REGISTRATION_TOKEN="$2"; shift 2 ;;
    --url) URL="$2"; shift 2 ;;
    --name) NAME="$2"; CONFIG_VOLUME="${NAME}-config"; shift 2 ;;
    --image) DEFAULT_IMAGE="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 2 ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found; start OrbStack (or Docker Desktop) first." >&2
  exit 1
fi

if [ -z "${TOKEN}" ] && [ -z "${REGISTRATION_TOKEN}" ]; then
  echo "no token provided. Set GITLAB_RUNNER_TOKEN (a glrt-... authentication" >&2
  echo "token) or pass --registration-token for the legacy flow. See --help." >&2
  exit 2
fi

# Idempotent: a runner already running for this project is left in place.
if docker ps --format '{{.Names}}' | grep -qx "${NAME}"; then
  echo "runner container '${NAME}' is already running. Nothing to do."
  echo "To re-register from scratch: docker rm -f '${NAME}' && docker volume rm '${CONFIG_VOLUME}'"
  exit 0
fi

# A stopped container of the same name would block `docker run --name`.
if docker ps -a --format '{{.Names}}' | grep -qx "${NAME}"; then
  echo "removing stopped container '${NAME}'."
  docker rm -f "${NAME}" >/dev/null
fi

echo "Registering runner against ${URL} ..."
# Writes /etc/gitlab-runner/config.toml into the named config volume. The modern
# `glrt-` flow uses --token; the legacy flow uses --registration-token.
if [ -n "${TOKEN}" ]; then
  docker run --rm \
    -v "${CONFIG_VOLUME}:/etc/gitlab-runner" \
    gitlab/gitlab-runner:latest register \
    --non-interactive \
    --url "${URL}" \
    --token "${TOKEN}" \
    --executor docker \
    --docker-image "${DEFAULT_IMAGE}" \
    --description "${NAME}"
else
  docker run --rm \
    -v "${CONFIG_VOLUME}:/etc/gitlab-runner" \
    gitlab/gitlab-runner:latest register \
    --non-interactive \
    --url "${URL}" \
    --registration-token "${REGISTRATION_TOKEN}" \
    --executor docker \
    --docker-image "${DEFAULT_IMAGE}" \
    --description "${NAME}" \
    --locked=false
fi

echo "Starting the runner daemon '${NAME}' ..."
docker run -d \
  --name "${NAME}" \
  --restart always \
  -v "${CONFIG_VOLUME}:/etc/gitlab-runner" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  gitlab/gitlab-runner:latest >/dev/null

echo "Done. The runner should appear online under Settings > CI/CD > Runners."
echo "Verify a pipeline picks it up by pushing a branch, or run:"
echo "  docker logs -f ${NAME}"
