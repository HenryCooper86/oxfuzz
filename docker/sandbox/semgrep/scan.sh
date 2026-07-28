#!/usr/bin/env bash
set -euo pipefail
[[ "$#" -eq 0 ]] || { echo "oxfuzz-semgrep-scan accepts no arguments" >&2; exit 64; }
unset SEMGREP_APP_TOKEN
export SEMGREP_SEND_METRICS=off
export SEMGREP_SETTINGS_FILE=/tmp/oxfuzz-semgrep-settings.yml
export SEMGREP_LOG_FILE=/tmp/oxfuzz-semgrep.log
[[ "$(semgrep --version --disable-version-check)" == "1.169.0" ]]
[[ "$(python3 /opt/oxfuzz/semgrep-tree-digest.py /opt/oxfuzz/semgrep-rules/rules/c)" == \
   "$(cat /opt/oxfuzz/semgrep-rules/RULES_SHA256)" ]]
rm -f /work/output/semgrep.json
cd /work/source
exec semgrep scan \
  --config /opt/oxfuzz/semgrep-rules/rules/c \
  --json \
  --json-output /work/output/semgrep.json \
  --metrics off \
  --disable-version-check \
  --no-rewrite-rule-ids \
  --jobs 2 \
  --max-target-bytes 2097152 \
  --timeout 30 \
  --timeout-threshold 1 \
  .
