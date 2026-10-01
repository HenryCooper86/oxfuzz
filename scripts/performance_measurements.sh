#!/usr/bin/env bash
# Keep compilation separate so CI can be rechecked before either measurement.
set -euo pipefail

case "${1:-}" in
  prepare)
    cargo bench -p hf-tools --bench dispatch --no-run
    scripts/cargo-test-filtered.sh -p hf-service --release --test finding_review --no-run
    ;;
  measure)
    cargo bench -p hf-tools --bench dispatch -- --test
    scripts/cargo-test-filtered.sh -p hf-service --release --test finding_review \
      profile_retained_multi_target_finding_queue -- --ignored --exact
    ;;
  *)
    printf '%s\n' 'Choose prepare or measure.' >&2
    exit 2
    ;;
esac
