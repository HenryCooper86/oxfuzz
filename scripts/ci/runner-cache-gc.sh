#!/bin/sh
# Free disk on a GitLab Docker-executor runner host by removing idle runner
# cache volumes once the root filesystem passes a usage threshold.
#
#   scripts/ci/runner-cache-gc.sh            # threshold 70%
#   RUNNER_CACHE_GC_THRESHOLD=80 scripts/ci/runner-cache-gc.sh
#
# The runner keeps each project's build directory and cache in Docker volumes
# named runner-<id>-cache-<hash>[-protected]. They are never pruned, and a
# workspace this size adds tens of gigabytes per pipeline, so the disk
# eventually fills and jobs fail with "No space left on device".
#
# Only volumes matching that exact name pattern are touched, and only when no
# container references them (Docker's dangling filter), so a running job keeps
# its volume. The next pipeline rebuilds what was removed, more slowly.
# Install on the runner host with a daily systemd timer; see docs/guides/CI.md.
set -eu

threshold="${RUNNER_CACHE_GC_THRESHOLD:-70}"
usage="$(df --output=pcent / | tail -n 1 | tr -dc '0-9')"
if [ "$usage" -lt "$threshold" ]; then
  echo "runner-cache-gc: disk at ${usage}% (threshold ${threshold}%); nothing to do"
  exit 0
fi

echo "runner-cache-gc: disk at ${usage}% (threshold ${threshold}%); removing idle runner cache volumes"
idle="$(docker volume ls -q --filter dangling=true)"
# grep exits 1 when no volume matches; that is the "nothing idle" case, not
# an error, and it is the only failure swallowed here.
volumes="$(printf '%s\n' "$idle" |
  grep -E '^runner-[0-9a-f]{32}-cache-[0-9a-f]{32}(-protected)?$' || true)"
for volume in $volumes; do
  docker volume rm "$volume"
done
echo "runner-cache-gc: disk now at $(df --output=pcent / | tail -n 1 | tr -d ' ')"
