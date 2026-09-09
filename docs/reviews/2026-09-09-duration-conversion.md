# Checked campaign duration conversion

The shared CLI duration parser multiplied minute and hour inputs without checking
whether the resulting seconds fit in `u64`. The regression test reproduced an
arithmetic panic, and the actual CLI subprocess exited 101 instead of returning
an input error. Unchecked multiplication can also wrap when overflow checks are
disabled.

The parser now parses the numeric value once and uses checked multiplication.
Overflow returns `duration exceeds supported seconds range`. Bare seconds and
all existing suffixes retain their behavior; representable durations still pass
through service-owned campaign policy. No default or resource limit changed.

Parser tests cover the maximum representable value for each suffix and the next
minute/hour value. The subprocess test covers both overflowing suffixes and
requires error exit 1 with no database or workspace creation. Focused CLI tests
passed after the correction. Full workspace tests passed: 3,250 passed, zero
failed, seven ignored across 180 summaries. Formatting, fixing/strict Clippy,
compilation, documentation and all-target Clippy passed. Frontend tests passed
518 tests in 72 files, build/bundle budgets and lint; 93 script tests, translation
pairing, dependency checks and domain coverage passed (91.12% aggregate).

Local logs are `/tmp/oxfuzz-duration-*.log`. No model, generated harness, target
build or real fuzzer was executed by these checks.
