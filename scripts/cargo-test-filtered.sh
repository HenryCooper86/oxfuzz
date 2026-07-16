#!/usr/bin/env bash
# Run cargo test with the repository's required concise error filter while
# preserving cargo's exit status even when grep has no lines to print.
set -u

set +e
cargo test "$@" 2>&1 \
  | grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' \
  | head -200
test_status=${PIPESTATUS[0]}
set -e

exit "$test_status"
