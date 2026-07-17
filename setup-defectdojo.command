#!/usr/bin/env bash
# Install and start a local DefectDojo for hobot_fuzz on Docker/OrbStack.
# Double-click to run; watch the output for success/failure. Idempotent -- safe
# to re-run. See scripts/setup-defectdojo.sh for details and env overrides.
set -uo pipefail
cd "$(dirname "$0")"

# Finder-launched scripts may not inherit the OrbStack/Docker PATH.
export PATH="$HOME/.orbstack/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"

./scripts/setup-defectdojo.sh ; RC=$?

echo ""
if [ "$RC" -ne 0 ]; then
  echo "=== DefectDojo setup FAILED (exit ${RC}). See errors above. ==="
fi
echo "Done (exit ${RC}). You can close this window."
